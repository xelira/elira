use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Buf;
use elira::config::Config;
use elira_metrics::Metrics;
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

async fn start_server(
    runtime: Arc<ArcSwap<elira::server::Runtime>>,
    max_headers: usize,
    max_connections: usize,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    Arc<Metrics>,
) {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures");
    let loader = {
        let runtime = runtime.clone();
        Arc::new(move || runtime.load().proxy().clone())
    };
    let port = free_udp_port();
    let (stop_tx, stop_rx) = watch::channel(false);
    let metrics = Arc::new(Metrics::new());
    let server_metrics = metrics.clone();
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
                certificates: Vec::new(),
                proxy_protocol: false,
                proxy_protocol_trusted: Vec::new(),
                idle_timeout_secs: 10,
                early_data: false,
                max_concurrent_bidi_streams: None,
                stream_receive_window: None,
                receive_window: None,
                send_window: None,
                reject_unknown_sni: false,
                max_header_bytes: 16384,
                max_headers,
                max_connections,
            },
            loader,
            server_metrics,
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
        metrics,
    )
}

async fn client(
    address: std::net::SocketAddr,
) -> (
    quinn::Endpoint,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) {
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
        .connect(address, "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 client");
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    (endpoint, send)
}

async fn request(
    send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) -> String {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://localhost/")
        .body(())
        .expect("request");
    let mut stream = send.send_request(request).await.expect("send request");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await.expect("data") {
        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    String::from_utf8(body).expect("body")
}

#[tokio::test]
async fn quic_connection_survives_runtime_swap() {
    let runtime = make_runtime("one");
    let (address, stop_tx, handle, metrics) = start_server(runtime.clone(), 64, 64).await;
    let (endpoint, mut send) = client(address).await;

    assert_eq!(request(&mut send).await, "one");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        metrics.take_delta().connections_in_flight,
        1,
        "live QUIC connection must be counted"
    );
    runtime.store(make_runtime("two").load_full());
    assert_eq!(request(&mut send).await, "two");

    endpoint.close(0u32.into(), b"done");
    for _ in 0..40 {
        if metrics.take_delta().connections_in_flight == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        metrics.take_delta().connections_in_flight,
        0,
        "closed QUIC connection must release the gauge"
    );
    let _ = stop_tx.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn h3_rejects_too_many_headers() {
    let runtime = make_runtime("ok");
    let (address, stop_tx, handle, _metrics) = start_server(runtime, 1, 64).await;
    let (endpoint, mut send) = client(address).await;

    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://localhost/")
        .header("x-one", "1")
        .header("x-two", "2")
        .body(())
        .expect("request");
    let mut stream = send.send_request(request).await.expect("send");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(
        response.status(),
        http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );

    endpoint.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn h3_enforces_connection_limit() {
    let runtime = make_runtime("ok");
    let (address, stop_tx, handle, _metrics) = start_server(runtime, 64, 1).await;
    let (endpoint, mut send) = client(address).await;
    assert_eq!(request(&mut send).await, "ok");

    let mut tls = elira_upstream::client_config(&elira_upstream::TlsOptions {
        insecure: true,
        ..Default::default()
    })
    .expect("client tls");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
    let config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut second =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("local")).expect("client endpoint");
    second.set_default_client_config(config);
    let connecting = second.connect(address, "localhost").expect("connect");
    match tokio::time::timeout(std::time::Duration::from_secs(5), connecting).await {
        Ok(Err(_)) => {}
        Ok(Ok(connection)) => {
            connection.close(0u32.into(), b"unexpected");
            panic!("connection above max_connections must be refused");
        }
        Err(_) => panic!("connection limit did not refuse the second connection"),
    }

    endpoint.close(0u32.into(), b"done");
    second.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn quic_connection_survives_client_rebind() {
    let runtime = make_runtime("migrated");
    let (address, stop_tx, handle, _metrics) = start_server(runtime, 64, 64).await;
    let (endpoint, mut send) = client(address).await;

    assert_eq!(request(&mut send).await, "migrated");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("rebind socket");
    endpoint.rebind(socket).expect("rebind");
    assert_eq!(request(&mut send).await, "migrated");

    endpoint.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;
}

async fn lossy_proxy(
    target: std::net::SocketAddr,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("front");
    let address = front.local_addr().expect("front addr");
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("back");
    back.connect(target).await.expect("connect back");
    let handle = tokio::spawn(async move {
        let mut client = None;
        let mut packet = 0u64;
        let mut front_buffer = vec![0u8; 65536];
        let mut back_buffer = vec![0u8; 65536];
        loop {
            tokio::select! {
                result = front.recv_from(&mut front_buffer) => {
                    let Ok((read, peer)) = result else { break };
                    client = Some(peer);
                    packet += 1;
                    if !packet.is_multiple_of(5) {
                        let _ = back.send(&front_buffer[..read]).await;
                    }
                }
                result = back.recv(&mut back_buffer) => {
                    let Ok(read) = result else { break };
                    let Some(peer) = client else { continue };
                    packet += 1;
                    if !packet.is_multiple_of(5) {
                        let _ = front.send_to(&back_buffer[..read], peer).await;
                    }
                }
            }
        }
    });
    (address, handle)
}

#[tokio::test]
async fn quic_survives_packet_loss() {
    let runtime = make_runtime("lossy");
    let (server, stop_tx, handle, _metrics) = start_server(runtime, 64, 64).await;
    let (address, relay) = lossy_proxy(server).await;
    let (endpoint, mut send) = client(address).await;

    assert_eq!(request(&mut send).await, "lossy");

    endpoint.close(0u32.into(), b"done");
    relay.abort();
    let _ = stop_tx.send(true);
    let _ = handle.await;
}
