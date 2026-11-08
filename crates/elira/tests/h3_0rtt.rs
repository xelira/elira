//! QUIC session resumption and 0-RTT acceptance.

use std::sync::Arc;

use elira::config::Config;
use elira::proxy::Proxy;
use elira_metrics::Metrics;
use tokio::sync::watch;

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    socket.local_addr().expect("addr").port()
}

#[tokio::test]
async fn quic_accepts_a_resumed_0rtt_connection() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures");
    let root = std::env::temp_dir().join(format!("elira-0rtt-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("root");
    std::fs::write(root.join("index.html"), "ok").expect("index");

    let config = Config::parse(&format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
root = "{}"
"#,
        root.display()
    ))
    .expect("config");
    let proxy = Arc::new(Proxy::new(&config).expect("proxy"));
    let loader = {
        let proxy = proxy.clone();
        Arc::new(move || (*proxy).clone())
    };

    let port = free_udp_port();
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(elira_h3::serve(
        elira_h3::Config {
            listen: format!("127.0.0.1:{port}").parse().expect("addr"),
            cert: fixtures.join("cert.pem"),
            key: fixtures.join("key.pem"),
            reuse_port: false,
            client_ca: None,
            client_auth: elira_tls::ClientAuth::Off,
            certificates: Vec::new(),
            proxy_protocol: false,
            idle_timeout_secs: 5,
            early_data: true,
        },
        loader,
        Arc::new(Metrics::new()),
        None,
        Arc::new(|_| {}),
        stop_rx,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut tls = elira_upstream::client_config(&elira_upstream::TlsOptions {
        insecure: true,
        ..Default::default()
    })
    .expect("client tls");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
    let client = quinn::ClientConfig::new(Arc::new(crypto));

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("local")).expect("client endpoint");
    endpoint.set_default_client_config(client);
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("server");

    // The first handshake receives the session ticket.
    let first = endpoint
        .connect(address, "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    first.close(0u32.into(), b"done");

    let second = endpoint.connect(address, "localhost").expect("connect");
    let (_connection, _accepted) = second
        .into_0rtt()
        .expect("a resumed session should offer 0-RTT");

    endpoint.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(&root);
}
