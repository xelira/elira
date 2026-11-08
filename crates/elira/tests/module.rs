//! Loads the example dynamic module. Ignored by default because it builds a
//! separate cdylib; run with:
//!
//! cargo test -p elira --test module -- --ignored

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

#[test]
#[ignore = "builds the example cdylib"]
fn module_route_answers_from_a_shared_library() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/modules/echo");
    let status = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .status()
        .expect("build example module");
    assert!(status.success(), "example module did not build");
    let library = root.join("target/debug/libelira_module_echo.so");
    assert!(library.is_file(), "missing {}", library.display());

    let dir = std::env::temp_dir().join(format!("elira-module-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"

[[routes]]
host = "*"
module = "{}"
"#,
            library.display()
        ),
    )
    .expect("config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_elira"))
        .args(["run", "--config"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn elira");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut response = None;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(
                b"GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            );
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(read) = stream.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let text = String::from_utf8_lossy(&buffer).to_string();
            if text.contains("200 OK") {
                response = Some(text);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    let response = response.expect("module route did not answer");
    assert!(response.contains("x-module: echo"), "{response}");
    assert!(response.ends_with("GET /hello"), "{response}");
}

#[test]
#[ignore = "builds the example cdylib"]
fn sandboxed_module_uses_the_child_runner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/modules/echo");
    let status = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .status()
        .expect("build example module");
    assert!(status.success());
    let library = root.join("target/debug/libelira_module_echo.so");

    let dir = std::env::temp_dir().join(format!("elira-sandbox-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"

[[routes]]
host = "*"
module = "{}"
module_sandbox = true
"#,
            library.display()
        ),
    )
    .expect("config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_elira"))
        .args(["run", "--config"])
        .arg(&config)
        .env("ELIRA_MODULE_RUNNER", env!("CARGO_BIN_EXE_elira"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn elira");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut response = None;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(
                b"GET /sandbox HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            );
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(read) = stream.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            let text = String::from_utf8_lossy(&buffer).to_string();
            if text.contains("200 OK") {
                response = Some(text);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    let response = response.expect("sandboxed module did not answer");
    assert!(response.contains("x-module: echo"), "{response}");
    assert!(response.ends_with("GET /sandbox"), "{response}");
}
