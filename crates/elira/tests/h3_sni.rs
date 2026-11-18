use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Buf;
use elira::config::Config;
use elira_metrics::Metrics;
use rcgen::{CertificateParams, DnType, KeyPair};
use tokio::sync::watch;

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    socket.local_addr().expect("addr").port()
}

fn make_runtime(body: &str) -> Arc<ArcSwap<elira::server::Runtime>> {
    let config = format!(
        r#"
listen = "127.0.0.1:0"

[[routes]]
host = "*"
return = {{ status = 200, body = "{body}" }}
"#
    );
    let config = Config::parse(&config).expect("config");
    Arc::new(ArcSwap::from_pointee(
        elira::server::Runtime::build(&config).expect("runtime"),
    ))
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("elira-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).expect("temp dir");
    root
}

async fn start_server(
    runtime: Arc<ArcSwap<elira::server::Runtime>>,
    named_cert: std::path::PathBuf,
    named_key: std::path::PathBuf,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures");
    let loader = {
        let runtime = runtime.clone();
        Arc::new(move || runtime.load().proxy().clone())
    };
    let port = free_udp_port();
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let _ = elira_h3::serve(
            elira_h3::Config {
                listen: format!("127.0.0.1:{port}").parse().expect("addr"),
                cert: fixtures.join("cert.pem"),
                key: fixtures.join("key.pem"),
                reuse_port: false,
                client_ca: None,
                client_crl: None,
                client_auth: elira_tls::ClientAuth::Off,
                cipher_suites: None,
                curves: None,
                ticket_key: None,
                certificates: vec![elira_tls::NamedCert {
                    names: vec!["other.local".to_owned()],
                    cert: named_cert,
                    key: named_key,
                    ocsp: None,
                }],
                proxy_protocol: false,
                proxy_protocol_trusted: Vec::new(),
                idle_timeout_secs: 10,
                early_data: false,
                max_concurrent_bidi_streams: None,
                stream_receive_window: None,
                receive_window: None,
                send_window: None,
                reject_unknown_sni: true,
                max_header_bytes: 16384,
                max_headers: 64,
                max_connections: 64,
            },
            loader,
            Arc::new(Metrics::new()),
            None,
            Arc::new(|_| {}),
            stop_rx,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (
        format!("127.0.0.1:{port}").parse().expect("server"),
        stop_tx,
        handle,
    )
}

async fn connect(
    address: std::net::SocketAddr,
    server_name: &str,
) -> Result<
    (
        quinn::Endpoint,
        quinn::Connection,
        h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    ),
    quinn::ConnectionError,
> {
    let mut tls = elira_upstream::client_config(&elira_upstream::TlsOptions {
        insecure: true,
        ..Default::default()
    })
    .expect("client tls");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
    let config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("local")).expect("client endpoint");
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(address, server_name)
        .expect("connect")
        .await?;
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|_| quinn::ConnectionError::LocallyClosed)?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    Ok((endpoint, connection, send))
}

#[tokio::test]
async fn h3_selects_named_sni_certificate() {
    let root = temp_root("h3-sni");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["other.local".to_owned()]).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, "other.local");
    let cert = params.self_signed(&key).expect("cert");
    let cert_path = root.join("other.pem");
    let key_path = root.join("other.key");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");

    let runtime = make_runtime("sni");
    let (address, stop_tx, handle) = start_server(runtime, cert_path, key_path).await;

    let (endpoint, connection, mut send) = connect(address, "other.local")
        .await
        .expect("named SNI handshake");
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://other.local/")
        .body(())
        .expect("request");
    let mut stream = send.send_request(request).await.expect("send");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await.expect("data") {
        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    assert_eq!(body, b"sni");

    connection.close(0u32.into(), b"done");
    endpoint.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;

    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn h3_rejects_unknown_sni() {
    let root = temp_root("h3-sni-reject");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["other.local".to_owned()]).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, "other.local");
    let cert = params.self_signed(&key).expect("cert");
    let cert_path = root.join("other.pem");
    let key_path = root.join("other.key");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");

    let runtime = make_runtime("sni");
    let (address, stop_tx, handle) = start_server(runtime, cert_path, key_path).await;

    assert!(
        connect(address, "missing.local").await.is_err(),
        "unknown SNI must not receive the default certificate"
    );

    let _ = stop_tx.send(true);
    let _ = handle.await;

    std::fs::remove_dir_all(&root).ok();
}
