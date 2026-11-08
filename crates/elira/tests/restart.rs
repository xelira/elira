//! SIGUSR2 must not take the service down when the replacement cannot start.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn get(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut body = [0u8; 64];
    matches!(stream.read(&mut body), Ok(read) if read > 0)
}

#[test]
fn a_broken_replacement_keeps_the_old_process_running() {
    let dir = std::env::temp_dir().join(format!("elira-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();

    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true

[[routes]]
host = "*"
root = "{root}"
"#,
            root = dir.display()
        ),
    )
    .expect("write config");
    std::fs::write(dir.join("index.html"), "ok").expect("index");

    let mut child = Command::new(env!("CARGO_BIN_EXE_elira"))
        .args(["run", "--config"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn elira");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !get(port) {
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The replacement will fail to parse this file and exit before binding.
    std::fs::write(&config, "listen = \"not an address\"\n").expect("break config");

    let status = Command::new("kill")
        .args(["-USR2", &child.id().to_string()])
        .status()
        .expect("send SIGUSR2");
    assert!(status.success(), "kill failed");

    // Give the parent enough time to notice the failed child and decide to
    // stay, then check that it still answers.
    std::thread::sleep(Duration::from_secs(2));
    assert!(get(port), "the old process must keep serving");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let stopped = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        matches!(child.try_wait(), Ok(Some(_)))
    });
    assert!(stopped, "server did not stop after SIGTERM");
    let _ = std::fs::remove_dir_all(&dir);
}
