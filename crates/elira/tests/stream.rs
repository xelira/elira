//! Layer-4 stream proxy tests.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use elira::config::Config;
use elira::server::Runtime;
use elira_metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

async fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp")
        .local_addr()
        .expect("tcp addr")
        .port()
}

async fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp")
        .local_addr()
        .expect("udp addr")
        .port()
}

fn temp_root(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("elira-stream-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create root");
    path
}

async fn tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    let Ok(read) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let port = socket.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buffer = [0u8; 65_535];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let _ = socket.send_to(&buffer[..read], peer).await;
        }
    });
    port
}

#[tokio::test]
async fn tcp_stream_proxies_bytes() {
    let upstream = tcp_echo().await;
    let listen = free_tcp_port().await;
    let root = temp_root("tcp");
    let config = format!(
        r#"
listen = "127.0.0.1:{}"

[[streams]]
listen = "127.0.0.1:{listen}"
upstreams = ["127.0.0.1:{upstream}"]

[[routes]]
host = "*"
root = "{}"
"#,
        free_tcp_port().await,
        root.display()
    );
    let cfg = Config::parse(&config).expect("config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("runtime"),
    ));
    let (stop_tx, stop_rx) = watch::channel(false);
    let bound = elira::stream::bind(&cfg.streams[0])
        .await
        .expect("bind stream");
    let handle = elira::stream::spawn(bound, runtime, 16, Arc::new(Metrics::new()), stop_rx);

    let mut client = TcpStream::connect(("127.0.0.1", listen))
        .await
        .expect("connect");
    client.write_all(b"ping").await.expect("write");
    let mut buffer = [0u8; 4];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"ping");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn udp_stream_proxies_datagrams() {
    let upstream = udp_echo().await;
    let listen = free_udp_port().await;
    let root = temp_root("udp");
    let config = format!(
        r#"
listen = "127.0.0.1:{}"

[[streams]]
listen = "127.0.0.1:{listen}"
transport = "udp"
upstreams = ["127.0.0.1:{upstream}"]

[[routes]]
host = "*"
root = "{}"
"#,
        free_tcp_port().await,
        root.display()
    );
    let cfg = Config::parse(&config).expect("config");
    let runtime = Arc::new(ArcSwap::from_pointee(
        Runtime::build(&cfg).expect("runtime"),
    ));
    let (stop_tx, stop_rx) = watch::channel(false);
    let bound = elira::stream::bind(&cfg.streams[0])
        .await
        .expect("bind stream");
    let handle = elira::stream::spawn(bound, runtime, 16, Arc::new(Metrics::new()), stop_rx);

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");
    client
        .send_to(b"ping", ("127.0.0.1", listen))
        .await
        .expect("send");
    let mut buffer = [0u8; 16];
    let size = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .expect("recv timeout")
        .expect("recv");
    assert_eq!(&buffer[..size], b"ping");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
