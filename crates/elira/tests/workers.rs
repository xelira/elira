//! The supervisor starts several processes on one port and stops them cleanly.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn get(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
    }
    Some(String::from_utf8_lossy(&response).to_string())
}

#[test]
fn workers_share_a_port_and_stop_together() {
    let dir = std::env::temp_dir().join(format!("elira-workers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    std::fs::write(dir.join("index.html"), "workers").expect("index");

    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true
workers = 2

[[routes]]
host = "*"
root = "{root}"
"#,
            root = dir.display()
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
        .expect("spawn superviser");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut response = None;
    while Instant::now() < deadline {
        response = get(port).filter(|response| response.contains("200 OK"));
        if response.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let response = response.expect("workers did not serve");
    assert!(response.ends_with("workers"), "{response}");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let stopped = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        matches!(child.try_wait(), Ok(Some(_)))
    });
    assert!(stopped, "supervisor did not stop");
    assert!(get(port).is_none(), "port still accepts connections");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_killed_worker_is_restarted() {
    let dir = std::env::temp_dir().join(format!("elira-respawn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    std::fs::write(dir.join("index.html"), "respawn").expect("index");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true
workers = 2

[[routes]]
host = "*"
root = "{root}"
"#,
            root = dir.display()
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
        .expect("spawn supervisor");

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if get(port)
            .map(|response| response.contains("200 OK"))
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let children = |parent: u32| -> Vec<u32> {
        let output = Command::new("pgrep")
            .args(["-P", &parent.to_string()])
            .output()
            .expect("pgrep");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    };

    let pids = children(child.id());
    assert_eq!(pids.len(), 2, "expected two workers, got {pids:?}");
    let _ = Command::new("kill")
        .args(["-KILL", &pids[0].to_string()])
        .status();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut recovered = false;
    while Instant::now() < deadline {
        let alive: Vec<u32> = children(child.id())
            .into_iter()
            .filter(|pid| *pid != pids[0])
            .collect();
        if alive.len() == 2
            && get(port)
                .map(|response| response.contains("200 OK"))
                .unwrap_or(false)
        {
            recovered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(recovered, "supervisor did not replace the dead worker");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
