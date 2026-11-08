//! CGI/1.1 script execution for the proxy.
//!
//! The runner starts a program directly with [`tokio::process::Command`]. The
//! script path is never passed through a shell and no arguments are assembled
//! from request data, so metacharacters in a path remain ordinary characters
//! for `execve` instead of being interpreted by `/bin/sh`. That also means a
//! path containing spaces, quotes, or `$` is not a command-injection surface.
//! The path still has to be absolute and free of `..`, which keeps a
//! configuration mistake from turning into a search path or a path-traversal
//! problem when a script is selected from a request value.
//!
//! The child environment is cleared and rebuilt from the request parameters.
//! Inheriting the proxy environment would leak proxy credentials and service
//! configuration into every script, and it would make the `PATH` used for a
//! script's own child processes depend on how the proxy was started. The two
//! CGI identity variables are written last, so a caller cannot impersonate a
//! different gateway or server by passing them in `params`.
//!
//! Output is bounded before it is stored. A script that writes without end is
//! killed once stdout crosses the limit; stderr is drained but truncated at
//! its own limit because a noisy log should not turn a valid response into a
//! failure. The timeout covers the complete exchange, including reading the
//! pipes, and a timed-out child is killed and reaped so the proxy does not
//! accumulate zombies.

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

/// Boxed error type carried by streaming request and response bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Largest stdout payload accepted from a script.
///
/// CGI responses are buffered because the header block determines how the
/// rest is interpreted, so an unbounded write would be an unbounded allocation
/// in the proxy. Eight MiB is larger than a normal scripted response while
/// small enough that a runaway script cannot exhaust a worker's memory.
pub const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;

/// Largest amount of stderr kept while draining a script.
///
/// The bytes are not part of the public response, but they still have to be
/// read: leaving a full stderr pipe unread would block the script forever. The
/// limit bounds that drain without making a chatty script fail.
pub const MAX_STDERR_BYTES: usize = 8 * 1024 * 1024;

/// The interface name required by CGI/1.1.
const GATEWAY_INTERFACE: &str = "CGI/1.1";

/// The server identity exposed to scripts.
const SERVER_SOFTWARE: &str = "elira";

/// A CGI request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Absolute path to the executable script.
    pub script: PathBuf,
    /// Environment variables passed to the script, in insertion order.
    ///
    /// Later entries with the same name replace earlier ones. Names and
    /// values containing NUL, and names containing `=`, are rejected because
    /// they cannot be represented faithfully in a process environment.
    pub params: Vec<(String, String)>,
    /// Bytes written to the script's standard input.
    pub body: Vec<u8>,
    /// Overall deadline for writing, reading, and waiting.
    ///
    /// [`Duration::ZERO`] disables the deadline. Without a deadline a script
    /// that never exits keeps the request task alive indefinitely; callers
    /// should normally supply a finite value.
    pub timeout: Duration,
}

/// A parsed CGI response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code. Defaults to 200, or 302 when `Location` is present
    /// without an explicit `Status` header.
    pub status: u16,
    /// Response headers in script order. Duplicates are preserved, and the
    /// CGI-only `Status` header is consumed rather than copied here.
    pub headers: Vec<(String, String)>,
    /// Bytes after the blank line that terminates the CGI header block.
    pub body: Vec<u8>,
}

/// Failures while starting, running, or parsing a CGI script.
#[derive(Debug, Error)]
pub enum Error {
    /// The script could not be started at all. This includes a missing file,
    /// a missing executable bit, and a bad interpreter in the shebang.
    #[error("spawn {path}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The overall deadline elapsed. The child has been killed and reaped by
    /// the time this is returned.
    #[error("CGI script timed out")]
    Timeout,

    /// The pipes or the process wait failed after a successful spawn.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The script's stdout was not a valid CGI response.
    #[error("malformed CGI response: {0}")]
    Malformed(&'static str),

    /// The script failed and produced no stdout to parse. `None` means the
    /// child was terminated by a signal rather than exiting normally.
    #[error("CGI script exited with status {status:?}")]
    Exit { status: Option<i32> },
}

/// Runs one CGI script and parses its response.
///
/// A non-zero exit does not discard a valid response: some scripts report a
/// problem through `Status` and then exit non-zero. If stdout is empty on a
/// failed exit, there is nothing to return, so [`Error::Exit`] is used instead.
pub async fn execute(request: &Request) -> Result<Response, Error> {
    let mut command = command(request)?;
    let mut child = command.spawn().map_err(|source| Error::Spawn {
        path: request.script.clone(),
        source,
    })?;

    // The command was built with piped stdio, so a missing handle indicates a
    // programming error rather than a script problem. Returning an I/O error
    // is still preferable to panicking inside a proxy worker.
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

    // All four operations run together. In particular, waiting for the child
    // before draining its pipes would deadlock as soon as a script fills the
    // pipe buffer, and writing a large body before reading would do the same
    // in the other direction.
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
                // Dropping the exchange future cancels the reads but does not
                // terminate the process. Explicitly signal and reap it before
                // reporting the timeout.
                kill_and_reap(&mut child).await;
                return Err(Error::Timeout);
            }
        }
    };

    let (_stdin_closed, stdout, _stderr, status) = match exchange_result {
        Ok(parts) => parts,
        Err(error) => {
            // A read-limit error, for example, leaves the script running. It
            // has no consumer for its pipes anymore, so stop it rather than
            // leaking a process until it notices EOF on its own.
            kill_and_reap(&mut child).await;
            return Err(error);
        }
    };

    parse_response(&stdout, status)
}

/// Validates the script and parameters and builds the common command shape.
///
/// The caller adds any body-length specific environment entries because the
/// buffered path knows the length while the streaming path does not.
fn base_command(script: &Path, params: &[(String, String)]) -> Result<Command, Error> {
    validate_script(script)?;
    validate_params(params)?;

    let mut command = Command::new(script);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // If the caller's future is cancelled, dropping the child handle must
        // not leave the script running with open pipes.
        .kill_on_drop(true);

    for (name, value) in params {
        command.env(name, value);
    }

    // Written after the caller's parameters so these cannot be overridden.
    command.env("GATEWAY_INTERFACE", GATEWAY_INTERFACE);
    command.env("SERVER_SOFTWARE", SERVER_SOFTWARE);

    Ok(command)
}

/// Validates the request and builds a command without a shell.
fn command(request: &Request) -> Result<Command, Error> {
    let mut command = base_command(&request.script, &request.params)?;

    // CGI scripts commonly use CONTENT_LENGTH to decide how much stdin to
    // read. Supplying it is safe because the runner wrote exactly this body;
    // an explicit caller value wins in case a proxy needs a different
    // convention for a particular script.
    if !request
        .params
        .iter()
        .any(|(name, _)| name == "CONTENT_LENGTH")
    {
        command.env("CONTENT_LENGTH", request.body.len().to_string());
    }

    Ok(command)
}

/// Rejects paths that would make the selected executable ambiguous.
fn validate_script(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Malformed("script path must be absolute"));
    }

    // An absolute path with `..` still resolves deterministically, but it is
    // almost always a sign that a caller is trying to escape the directory
    // chosen by configuration. Refusing it keeps the boundary simple.
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

/// Rejects environment entries the operating system cannot represent.
fn validate_params(params: &[(String, String)]) -> Result<(), Error> {
    for (name, value) in params {
        // `=` separates the name from the value in the C environment, and NUL
        // terminates the string. Rejecting both avoids a command that either
        // fails in exec or silently changes meaning.
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(Error::Malformed("invalid CGI environment variable name"));
        }
        if value.contains('\0') {
            return Err(Error::Malformed("invalid CGI environment variable value"));
        }
    }
    Ok(())
}

/// Writes the body and closes stdin so the script sees EOF.
async fn write_body(mut stdin: ChildStdin, body: &[u8]) -> Result<(), Error> {
    match stdin.write_all(body).await {
        Ok(()) => {}
        // A script is allowed to stop reading early. That closes the pipe and
        // produces EPIPE here, which is not an error in the CGI exchange.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
        Err(error) => return Err(Error::Io(error)),
    }

    // Closing the write end is what lets a script using `read` or reading to
    // EOF finish. The handle would be dropped at the end of this future too,
    // but an explicit shutdown makes the ordering local and obvious.
    let _ = stdin.shutdown().await;
    Ok(())
}

/// Reads stdout up to `limit` bytes and fails if the script writes more.
async fn read_stdout_capped<R>(reader: R, limit: usize) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    // Read one byte past the limit. That distinguishes an exact-size response
    // from an over-limit one without buffering the rest of the output.
    let mut limited = reader.take(limit.saturating_add(1) as u64);
    let mut output = Vec::new();
    limited.read_to_end(&mut output).await.map_err(Error::Io)?;

    if output.len() > limit {
        return Err(Error::Malformed("stdout exceeds the configured limit"));
    }
    Ok(output)
}

/// Drains stderr while keeping at most `limit` bytes.
///
/// Continuing to read after the cap matters: if the runner stops reading, a
/// script writing debug output blocks on its stderr pipe and can never finish
/// producing a valid response.
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

/// Kills and reaps a child that is still running or was not waited for.
async fn kill_and_reap(child: &mut Child) {
    // `start_kill` sends the signal without waiting. The following `wait`
    // collects the exit status; skipping it would leave a zombie. Both errors
    // are ignored because the process may have exited between cancellation
    // and this call, and there is no useful recovery from a failed reap here.
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Converts stdout plus the child's exit status into a response.
fn parse_response(stdout: &[u8], status: ExitStatus) -> Result<Response, Error> {
    if stdout.is_empty() {
        return if status.success() {
            // A successful CGI script must emit at least the blank line that
            // ends its header block, so this is a malformed script rather
            // than a valid empty response.
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

/// Parse a CGI header block that has already been separated from its body.
///
/// Both execution paths use this so the buffered and streaming responses
/// accept and reject exactly the same headers.
fn parse_header_block(header_block: &[u8]) -> Result<(u16, Vec<(String, String)>), Error> {
    let mut explicit_status = None;
    let mut headers = Vec::new();

    for line in header_block.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // An empty line inside the block is harmless; the first blank
            // line already terminated the block, so this can only be a stray
            // extra newline.
            continue;
        }

        // A header beginning with whitespace is the obsolete folded form.
        // Rejecting it avoids silently joining two headers in a way that can
        // change their meaning.
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
            // `Status` is CGI metadata, not an HTTP header. It is consumed
            // here so the proxy does not forward it by accident.
            explicit_status = Some(parse_status(value)?);
        } else {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    // CGI defines Location without Status as a redirect. Any explicit status
    // wins, including a non-redirect status paired with Location.
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

/// Finds the blank line that separates CGI headers from the body.
///
/// Both the CRLF and bare-LF conventions are accepted because scripts are
/// often written by hand or on a system whose text mode differs. The earliest
/// terminator wins, which keeps a `\n\n` sequence inside the body from being
/// mistaken for a header terminator.
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

/// Returns the first position of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parses the value of a CGI `Status` header.
///
/// The status code is the first token and must be exactly three digits. A
/// reason phrase is optional because some scripts emit only the number.
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

    // HTTP has no meaningful statuses outside this range. Rejecting early
    // keeps an invalid script from producing a response the proxy would have
    // to reject when it builds the HTTP response anyway.
    if !(100..=599).contains(&code) {
        return Err(Error::Malformed("Status code out of range"));
    }

    Ok(code)
}

/// RFC 7230 `tchar`: the characters allowed in an HTTP header name.
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

/// Rejects C0 controls and DEL in header values, while allowing horizontal
/// tab and the ordinary visible characters.
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

    /// Serialises the create-then-execute pairs used by these tests.
    ///
    /// When one test thread forks a child, it inherits every open descriptor
    /// in the process. If another thread is between writing and executing a
    /// script at that moment, the inherited write descriptor makes `exec` fail
    /// with `ETXTBSY`. The tests themselves are not the feature under test, so
    /// they take this lock instead of tolerating a flaky failure.
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
            // Best effort: a failed cleanup must not turn a passing assertion
            // into a confusing test panic.
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
