#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use elira_cgi::{execute_stream, BodyStream, BoxError, Error, StreamRequest, StreamResponse};
use futures_util::{stream, StreamExt};

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
            "elira-cgi-stream-test-{}-{}-{}",
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

fn body_from(chunks: Vec<&'static [u8]>) -> BodyStream {
    let items: Vec<Result<Bytes, BoxError>> = chunks
        .into_iter()
        .map(|chunk| Ok(Bytes::from_static(chunk)))
        .collect();
    Box::pin(stream::iter(items))
}

fn request(script: PathBuf, body: BodyStream) -> StreamRequest {
    StreamRequest {
        script,
        params: Vec::new(),
        body,
        timeout: Duration::from_secs(5),
    }
}

async fn collect(response: StreamResponse) -> (Vec<u8>, Vec<usize>, Option<BoxError>) {
    let mut body = response.body;
    let mut bytes = Vec::new();
    let mut chunk_sizes = Vec::new();
    let mut failure = None;

    while let Some(item) = body.next().await {
        match item {
            Ok(chunk) => {
                chunk_sizes.push(chunk.len());
                bytes.extend_from_slice(&chunk);
            }
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }

    (bytes, chunk_sizes, failure)
}

#[tokio::test]
async fn streams_stdin_and_multi_chunk_stdout() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let script = dir.script(
        "stream.sh",
        r#"#!/bin/sh
body=$(cat)
printf 'Content-Type: text/plain\r\nX-Test: streamed\r\n\r\n'
printf 'first:'
/bin/sleep 0.05
printf '%s' "$body"
/bin/sleep 0.05
printf ':last'
"#,
    );

    let response = execute_stream(
        request(script, body_from(vec![b"hello ", b"streamed"])),
        64 * 1024,
    )
    .await
    .expect("script should run");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("X-Test".to_owned(), "streamed".to_owned()),
        ]
    );

    let (bytes, chunks, failure) = collect(response).await;
    assert!(failure.is_none(), "unexpected stream error: {failure:?}");
    assert_eq!(bytes, b"first:hello streamed:last");
    assert!(
        chunks.len() >= 2,
        "expected the script output in several chunks, got {chunks:?}"
    );
}

#[tokio::test]
async fn large_request_body_is_streamed_without_deadlock() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let script = dir.script(
        "count.sh",
        r#"#!/bin/sh
bytes=$(wc -c)
printf 'Content-Type: text/plain\r\n\r\n'
printf '%s' "$bytes"
"#,
    );

    let block = Bytes::from(vec![b'a'; 64 * 1024]);
    let chunks: Vec<Result<Bytes, BoxError>> = (0..4).map(|_| Ok(block.clone())).collect();
    let body: BodyStream = Box::pin(stream::iter(chunks));

    let response = execute_stream(request(script, body), 64 * 1024)
        .await
        .expect("script should run");

    let (bytes, _, failure) = collect(response).await;
    assert!(failure.is_none(), "unexpected stream error: {failure:?}");
    assert_eq!(String::from_utf8_lossy(&bytes), (4 * 64 * 1024).to_string());
}

#[tokio::test]
async fn stdout_limit_is_enforced_on_the_body_stream() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let script = dir.script(
        "flood.sh",
        r#"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
/bin/sleep 0.1
i=0
while [ "$i" -lt 200 ]; do
    printf '0123456789'
    i=$((i + 1))
done
"#,
    );

    let response = execute_stream(request(script, body_from(Vec::new())), 64)
        .await
        .expect("headers should arrive before the limit is crossed");

    let (_, _, failure) = collect(response).await;
    let failure = failure.expect("the stream must report the limit");
    let error = failure
        .downcast::<Error>()
        .expect("the error keeps its concrete type");
    assert!(
        matches!(*error, Error::Malformed(message) if message.contains("exceeds")),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn client_drop_kills_the_child() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let pid_file = dir.path().join("pid");

    let script = dir.script(
        "hang.sh",
        r#"#!/bin/sh
echo $$ > "$ELIRA_PID_FILE"
printf 'Content-Type: text/plain\r\n\r\nstart'
exec /bin/sleep 60
"#,
    );

    let mut request = request(script, body_from(Vec::new()));
    request
        .params
        .push(("ELIRA_PID_FILE".to_owned(), pid_file.display().to_string()));

    let response = execute_stream(request, 64 * 1024)
        .await
        .expect("headers should arrive");
    assert_eq!(response.status, 200);

    let pid: u32 = fs::read_to_string(&pid_file)
        .expect("script should record its pid")
        .trim()
        .parse()
        .expect("pid should be numeric");

    drop(response.body);
    wait_for_exit(pid).await;
}

#[tokio::test]
async fn timeout_kills_the_child() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let pid_file = dir.path().join("pid");

    let script = dir.script(
        "sleep.sh",
        r#"#!/bin/sh
echo $$ > "$ELIRA_PID_FILE"
/bin/sleep 60
"#,
    );

    let mut request = request(script, body_from(Vec::new()));
    request.timeout = Duration::from_millis(250);
    request
        .params
        .push(("ELIRA_PID_FILE".to_owned(), pid_file.display().to_string()));

    let started = Instant::now();
    let error = execute_stream(request, 64 * 1024)
        .await
        .expect_err("script should time out");
    assert!(matches!(error, Error::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5));

    let pid: u32 = fs::read_to_string(&pid_file)
        .expect("script should record its pid")
        .trim()
        .parse()
        .expect("pid should be numeric");
    wait_for_exit(pid).await;
}

#[tokio::test]
async fn missing_header_terminator_is_rejected() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let script = dir.script(
        "no-terminator.sh",
        r#"#!/bin/sh
printf 'Status: 200 OK\r\nContent-Type: text/plain\r\n'
"#,
    );

    let error = execute_stream(request(script, body_from(Vec::new())), 64 * 1024)
        .await
        .expect_err("a header block without a blank line must fail");
    assert!(
        matches!(error, Error::Malformed(message) if message.contains("header")),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn malformed_status_is_rejected() {
    let _guard = SPAWN_LOCK.lock().await;
    let dir = TempDir::new();
    let script = dir.script(
        "bad-status.sh",
        r#"#!/bin/sh
printf 'Status: nope\r\nContent-Type: text/plain\r\n\r\nbody'
"#,
    );

    let error = execute_stream(request(script, body_from(Vec::new())), 64 * 1024)
        .await
        .expect_err("a malformed Status header must fail");
    assert!(
        matches!(error, Error::Malformed(_)),
        "unexpected error: {error:?}"
    );
}

#[cfg(target_os = "linux")]
async fn wait_for_exit(pid: u32) {
    let path = format!("/proc/{pid}");
    for _ in 0..150 {
        if !Path::new(&path).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("child {pid} is still running");
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_exit(_pid: u32) {}
