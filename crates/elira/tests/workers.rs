use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn get(port: u16) -> Option<String> {
    get_path(port, "/")
}

fn get_path(port: u16, path: &str) -> Option<String> {
    get_at(port, "localhost", path)
}

fn get_at(port: u16, host: &str, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
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

fn wait_admin(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if get_path(port, "/status").is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("admin listener did not start");
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
    let closed = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        get(port).is_none()
    });
    assert!(closed, "port still accepts connections");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_killed_worker_is_restarted() {
    let dir = std::env::temp_dir().join(format!("elira-respawn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    let metrics_port = free_port();
    std::fs::write(dir.join("index.html"), "respawn").expect("index");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true
workers = 2

[metrics]
listen = "127.0.0.1:{metrics_port}"

[[routes]]
host = "*"
root = "{root}"
"#,
            root = dir.display(),
            metrics_port = metrics_port
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

    let deadline = Instant::now() + Duration::from_secs(40);
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

    std::thread::sleep(Duration::from_millis(1500));
    let metrics = get_path(metrics_port, "/metrics").expect("aggregate metrics");
    assert!(
        metrics.contains("elira_requests_total"),
        "aggregate metrics missing counters: {metrics}"
    );
    let status = get_path(metrics_port, "/status").expect("aggregate status");
    assert!(status.contains("\"workers\":["), "{status}");
    assert!(status.contains("\"worker\":0"), "{status}");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_drain_stops_the_supervisor() {
    let dir = std::env::temp_dir().join(format!("elira-drain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    let metrics_port = free_port();
    std::fs::write(dir.join("index.html"), "drain").expect("index");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true
workers = 2

[metrics]
listen = "127.0.0.1:{metrics_port}"

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

    wait_admin(metrics_port);

    let mut stream = TcpStream::connect(("127.0.0.1", metrics_port)).expect("metrics");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(b"POST /drain HTTP/1.1\r\nHost: localhost\r\nx-elira-admin: 1\r\nConnection: close\r\n\r\n")
        .expect("post");
    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("202"), "{response}");

    let stopped = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        matches!(child.try_wait(), Ok(Some(_)))
    });
    assert!(stopped, "admin drain did not stop the supervisor");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_purge_reaches_every_worker() {
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    std::thread::spawn(move || {
        for stream in upstream.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: max-age=60\r\n\
                  Content-Length: 2\r\nConnection: close\r\n\r\nok",
            );
        }
    });

    let dir = std::env::temp_dir().join(format!("elira-purge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("elira.toml");
    let port = free_port();
    let metrics_port = free_port();
    std::fs::write(
        &config,
        format!(
            r#"
listen = "127.0.0.1:{port}"
reuse_port = true
workers = 2

[metrics]
listen = "127.0.0.1:{metrics_port}"

[cache]
enabled = true
ttl_secs = 60
max_item_bytes = 65536

[[upstreams]]
name = "app"
servers = ["{upstream_addr}"]

[[routes]]
host = "*"
upstream = "app"
"#
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
        if get_at(port, "a.example", "/one")
            .map(|response| response.contains("200 OK"))
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    for _ in 0..4 {
        let _ = get_at(port, "a.example", "/one");
    }

    wait_admin(metrics_port);

    let mut stream = TcpStream::connect(("127.0.0.1", metrics_port)).expect("metrics");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(
            b"POST /cache/purge?prefix=a.example/one HTTP/1.1\r\nHost: localhost\r\nx-elira-admin: 1\r\nConnection: close\r\n\r\n",
        )
        .expect("post");
    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&response).contains("202"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    std::thread::sleep(Duration::from_millis(400));
    let after = get_at(port, "a.example", "/one").expect("post-purge request");
    assert!(after.contains("200 OK"), "{after}");

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
