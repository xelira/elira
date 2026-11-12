use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tokio::time::timeout;

mod stream;

pub use stream::{execute_stream, BodyStream, StreamRequest, StreamResponse};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;

pub const MAX_STDERR_BYTES: usize = 8 * 1024 * 1024;

const GATEWAY_INTERFACE: &str = "CGI/1.1";

const SERVER_SOFTWARE: &str = "elira";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub script: PathBuf,

    pub params: Vec<(String, String)>,

    pub body: Vec<u8>,

    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,

    pub headers: Vec<(String, String)>,

    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("spawn {path}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("CGI script timed out")]
    Timeout,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("malformed CGI response: {0}")]
    Malformed(&'static str),

    #[error("CGI script exited with status {status:?}")]
    Exit { status: Option<i32> },
}

pub async fn execute(request: &Request) -> Result<Response, Error> {
    let mut command = command(request)?;
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        path: request.script.clone(),
        source,
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("CGI stdin was not piped"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("CGI stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("CGI stderr was not piped"))?;

    let exchange = async {
        tokio::try_join!(
            write_body(stdin, &request.body),
            read_stdout_capped(stdout, MAX_STDOUT_BYTES),
            read_stderr_capped(stderr, MAX_STDERR_BYTES),
            async { child.wait().await.map_err(Error::Io) },
        )
    };

    let exchange_result = if request.timeout.is_zero() {
        exchange.await
    } else {
        match timeout(request.timeout, exchange).await {
            Ok(result) => result,
            Err(_) => {
                kill_and_reap(&mut child).await;
                return Err(Error::Timeout);
            }
        }
    };

    let (_stdin_closed, stdout, _stderr, status) = match exchange_result {
        Ok(parts) => parts,
        Err(error) => {
            kill_and_reap(&mut child).await;
            return Err(error);
        }
    };

    parse_response(&stdout, status)
}

fn base_command(script: &Path, params: &[(String, String)]) -> Result<Command, Error> {
    validate_script(script)?;
    validate_params(params)?;

    let mut command = Command::new(script);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    for (name, value) in params {
        command.env(name, value);
    }

    command.env("GATEWAY_INTERFACE", GATEWAY_INTERFACE);
    command.env("SERVER_SOFTWARE", SERVER_SOFTWARE);

    Ok(command)
}

fn command(request: &Request) -> Result<Command, Error> {
    let mut command = base_command(&request.script, &request.params)?;

    if !request
        .params
        .iter()
        .any(|(name, _)| name == "CONTENT_LENGTH")
    {
        command.env("CONTENT_LENGTH", request.body.len().to_string());
    }

    Ok(command)
}

fn validate_script(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Malformed("script path must be absolute"));
    }

    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Malformed("script path must not contain '..'"));
    }

    if path.as_os_str().to_string_lossy().contains('\0') {
        return Err(Error::Malformed("script path contains NUL"));
    }

    Ok(())
}

fn validate_params(params: &[(String, String)]) -> Result<(), Error> {
    for (name, value) in params {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(Error::Malformed("invalid CGI environment variable name"));
        }
        if value.contains('\0') {
            return Err(Error::Malformed("invalid CGI environment variable value"));
        }
    }
    Ok(())
}

async fn write_body(mut stdin: ChildStdin, body: &[u8]) -> Result<(), Error> {
    match stdin.write_all(body).await {
        Ok(()) => {}

        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
        Err(error) => return Err(Error::Io(error)),
    }

    let _ = stdin.shutdown().await;
    Ok(())
}

async fn read_stdout_capped<R>(reader: R, limit: usize) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let mut limited = reader.take(limit.saturating_add(1) as u64);
    let mut output = Vec::new();
    limited.read_to_end(&mut output).await.map_err(Error::Io)?;

    if output.len() > limit {
        return Err(Error::Malformed("stdout exceeds the configured limit"));
    }
    Ok(output)
}

async fn read_stderr_capped(mut reader: ChildStderr, limit: usize) -> Result<Vec<u8>, Error> {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let read = reader.read(&mut chunk).await.map_err(Error::Io)?;
        if read == 0 {
            break;
        }

        let room = limit.saturating_sub(captured.len());
        if room > 0 {
            captured.extend_from_slice(&chunk[..read.min(room)]);
        }
    }

    Ok(captured)
}

async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn parse_response(stdout: &[u8], status: ExitStatus) -> Result<Response, Error> {
    if stdout.is_empty() {
        return if status.success() {
            Err(Error::Malformed("empty CGI response"))
        } else {
            Err(Error::Exit {
                status: status.code(),
            })
        };
    }

    let (header_block, body) =
        split_headers(stdout).ok_or(Error::Malformed("missing CGI header terminator"))?;
    let (status, headers) = parse_header_block(header_block)?;

    Ok(Response {
        status,
        headers,
        body: body.to_vec(),
    })
}

fn parse_header_block(header_block: &[u8]) -> Result<(u16, Vec<(String, String)>), Error> {
    let mut explicit_status = None;
    let mut headers = Vec::new();

    for line in header_block.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }

        if line[0] == b' ' || line[0] == b'\t' {
            return Err(Error::Malformed("CGI header uses obsolete line folding"));
        }

        let text = std::str::from_utf8(line)
            .map_err(|_| Error::Malformed("CGI header is not valid UTF-8"))?;
        let colon = text
            .find(':')
            .ok_or(Error::Malformed("CGI header line has no ':'"))?;
        let name = &text[..colon];

        if name.is_empty() || name.bytes().any(|byte| !is_token(byte)) {
            return Err(Error::Malformed("invalid CGI header name"));
        }

        let value =
            text[colon + 1..].trim_matches(|character| character == ' ' || character == '\t');
        if value.bytes().any(is_control) {
            return Err(Error::Malformed("control character in CGI header value"));
        }

        if name.eq_ignore_ascii_case("Status") {
            explicit_status = Some(parse_status(value)?);
        } else {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let inferred_status = if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Location"))
    {
        302
    } else {
        200
    };

    Ok((explicit_status.unwrap_or(inferred_status), headers))
}

fn split_headers(output: &[u8]) -> Option<(&[u8], &[u8])> {
    let crlf = find_subslice(output, b"\r\n\r\n").map(|index| (index, index + 4));
    let lf = find_subslice(output, b"\n\n").map(|index| (index, index + 2));

    match (crlf, lf) {
        (Some((crlf_index, crlf_end)), Some((lf_index, lf_end))) => {
            if crlf_index <= lf_index {
                Some((&output[..crlf_index], &output[crlf_end..]))
            } else {
                Some((&output[..lf_index], &output[lf_end..]))
            }
        }
        (Some((index, end)), None) | (None, Some((index, end))) => {
            Some((&output[..index], &output[end..]))
        }
        (None, None) => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_status(value: &str) -> Result<u16, Error> {
    let code = value
        .split_ascii_whitespace()
        .next()
        .ok_or(Error::Malformed("empty Status header"))?;

    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Malformed("invalid Status code"));
    }

    let code: u16 = code
        .parse()
        .map_err(|_| Error::Malformed("invalid Status code"))?;

    if !(100..=599).contains(&code) {
        return Err(Error::Malformed("Status code out of range"));
    }

    Ok(code)
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_control(byte: u8) -> bool {
    (byte < 0x20 && byte != b'\t') || byte == 0x7f
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static SPAWN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = env::temp_dir().join(format!(
                "elira-cgi-test-{}-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
                nanos
            ));
            fs::create_dir_all(&path).expect("create temporary directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn script(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("write test script");
            let mut permissions = fs::metadata(&path).expect("stat test script").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("make test script executable");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn request(script: PathBuf) -> Request {
        Request {
            script,
            params: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(5),
        }
    }

    fn header_values<'a>(response: &'a Response, wanted: &str) -> Vec<&'a str> {
        response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    #[tokio::test]
    async fn runs_script_with_stdin_and_environment() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "normal.sh",
            r#"#!/bin/sh
IFS= read -r line || true
printf 'Content-Type: text/plain\r\nX-Test: one\r\nX-Test: two\r\n\r\n'
printf 'stdin=%s gateway=%s software=%s custom=%s length=%s' \
    "$line" "$GATEWAY_INTERFACE" "$SERVER_SOFTWARE" "$ELIRA_TEST" "$CONTENT_LENGTH"
"#,
        );

        let mut request = request(script);
        request
            .params
            .push(("ELIRA_TEST".to_owned(), "yes".to_owned()));
        request.body = b"hello stdin".to_vec();

        let response = execute(&request).await.expect("script should succeed");

        assert_eq!(response.status, 200);
        assert_eq!(
            response.body,
            b"stdin=hello stdin gateway=CGI/1.1 software=elira custom=yes length=11".to_vec()
        );
        assert_eq!(header_values(&response, "Content-Type"), ["text/plain"]);
        assert_eq!(header_values(&response, "X-Test"), ["one", "two"]);
    }

    #[tokio::test]
    async fn status_header_sets_the_response_status() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "not-found.sh",
            r#"#!/bin/sh
printf 'Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nmissing'
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("script should succeed");

        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"missing".to_vec());
        assert!(header_values(&response, "Status").is_empty());
        assert_eq!(header_values(&response, "Content-Type"), ["text/plain"]);
    }

    #[tokio::test]
    async fn location_without_status_implies_a_redirect() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "redirect.sh",
            r#"#!/bin/sh
printf 'Location: /next\r\nContent-Length: 0\r\n\r\n'
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("script should succeed");

        assert_eq!(response.status, 302);
        assert_eq!(header_values(&response, "Location"), ["/next"]);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn explicit_status_wins_over_location() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "created.sh",
            r#"#!/bin/sh
printf 'Status: 201 Created\r\nLocation: /thing\r\n\r\n'
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("script should succeed");

        assert_eq!(response.status, 201);
        assert_eq!(header_values(&response, "Location"), ["/thing"]);
    }

    #[tokio::test]
    async fn malformed_header_is_rejected() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "bad-header.sh",
            r#"#!/bin/sh
printf 'this is not a header\r\n\r\n'
"#,
        );

        let error = execute(&request(script))
            .await
            .expect_err("header should be invalid");

        assert!(matches!(
            error,
            Error::Malformed("CGI header line has no ':'")
        ));
    }

    #[tokio::test]
    async fn malformed_status_is_rejected() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "bad-status.sh",
            r#"#!/bin/sh
printf 'Status: not-a-code\r\n\r\n'
"#,
        );

        let error = execute(&request(script))
            .await
            .expect_err("status should be invalid");

        assert!(matches!(error, Error::Malformed("invalid Status code")));
    }

    #[tokio::test]
    async fn nonzero_exit_still_returns_valid_output() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "partial.sh",
            r#"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\npartial'
exit 3
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("valid stdout should win over the exit code");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"partial".to_vec());
    }

    #[tokio::test]
    async fn nonzero_exit_without_output_reports_exit() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "exit-empty.sh",
            r#"#!/bin/sh
exit 7
"#,
        );

        let error = execute(&request(script))
            .await
            .expect_err("no output gives nothing to return");

        assert!(matches!(error, Error::Exit { status: Some(7) }));
    }

    #[tokio::test]
    async fn successful_exit_without_output_is_malformed() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "empty.sh",
            r#"#!/bin/sh
exit 0
"#,
        );

        let error = execute(&request(script))
            .await
            .expect_err("empty output is not a valid CGI response");

        assert!(matches!(error, Error::Malformed("empty CGI response")));
    }

    #[tokio::test]
    async fn timeout_kills_a_sleeping_script() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "slow.sh",
            r#"#!/bin/sh
/bin/sleep 5
"#,
        );

        let mut request = request(script);
        request.timeout = Duration::from_millis(100);
        let started = Instant::now();

        let error = execute(&request).await.expect_err("script should time out");

        assert!(matches!(error, Error::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout should not wait for the script to finish"
        );
    }

    #[tokio::test]
    async fn missing_script_reports_spawn_error() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let path = dir.path().join("does-not-exist.sh");

        let error = execute(&request(path.clone()))
            .await
            .expect_err("missing executable cannot start");

        match error {
            Error::Spawn { path: reported, .. } => assert_eq!(reported, path),
            other => panic!("expected Spawn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relative_path_is_rejected() {
        let _guard = SPAWN_LOCK.lock().await;
        let error = execute(&request(PathBuf::from("relative.sh")))
            .await
            .expect_err("relative script path must not run");

        assert!(matches!(
            error,
            Error::Malformed("script path must be absolute")
        ));
    }

    #[tokio::test]
    async fn parent_directory_component_is_rejected() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let path = dir.path().join("..").join("script.sh");

        let error = execute(&request(path))
            .await
            .expect_err("parent directory component must not run");

        assert!(matches!(
            error,
            Error::Malformed("script path must not contain '..'")
        ));
    }

    #[tokio::test]
    async fn stderr_does_not_leak_into_the_body() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "noisy.sh",
            r#"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\nok'
printf 'this belongs on stderr\n' >&2
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("script should succeed");

        assert_eq!(response.body, b"ok".to_vec());
        assert_eq!(header_values(&response, "Content-Type"), ["text/plain"]);
    }

    #[tokio::test]
    async fn bare_lf_header_terminator_is_accepted() {
        let _guard = SPAWN_LOCK.lock().await;
        let dir = TempDir::new();
        let script = dir.script(
            "lf.sh",
            r#"#!/bin/sh
printf 'Content-Type: text/plain\n\nbody with\n\nblank lines'
"#,
        );

        let response = execute(&request(script))
            .await
            .expect("script should succeed");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"body with\n\nblank lines".to_vec());
    }

    #[tokio::test]
    async fn stdout_limit_is_enforced() {
        let _guard = SPAWN_LOCK.lock().await;
        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            let _ = writer.write_all(b"0123456789").await;
        });

        let error = read_stdout_capped(reader, 8)
            .await
            .expect_err("output larger than the limit must be rejected");
        writer_task.await.expect("writer task");

        assert!(matches!(
            error,
            Error::Malformed("stdout exceeds the configured limit")
        ));
    }
}
