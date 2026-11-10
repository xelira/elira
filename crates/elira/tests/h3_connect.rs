//! HTTP/3 CONNECT tunnelling.

use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use elira::config::Config;
use elira::proxy::Proxy;
use elira_metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    socket.local_addr().expect("addr").port()
}

async fn tcp_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn connect_tunnels_over_http3() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../elira-tls/tests/fixtures");
    let echo = tcp_echo().await;

    let config = Config::parse(&format!(
        r#"
listen = "127.0.0.1:0"

[connect]
enabled = true
allow = ["{echo}"]

[[routes]]
host = "*"
return = {{ status = 404, body = "no route" }}
"#
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
            client_crl: None,
            client_auth: elira_tls::ClientAuth::Off,
            cipher_suites: None,
            curves: None,
            ticket_key: None,
            certificates: Vec::new(),
            proxy_protocol: false,
            idle_timeout_secs: 5,
            early_data: false,
            max_concurrent_bidi_streams: None,
            stream_receive_window: None,
            receive_window: None,
            send_window: None,
        },
        loader,
        Arc::new(Metrics::new()),
        None,
        Arc::new(|_| {}),
        stop_rx,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut tls = elira_upstream::client_config(&elira_upstream::TlsOptions {
        insecure: true,
        ..Default::default()
    })
    .expect("client tls");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
    let client = quinn::ClientConfig::new(Arc::new(crypto));

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("local")).expect("client endpoint");
    endpoint.set_default_client_config(client);
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("server");
    let connection = endpoint
        .connect(address, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let (h3, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 client");

    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("{echo}"))
        .body(())
        .expect("CONNECT request");
    let mut stream = send_request.send_request(request).await.expect("send");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);

    stream
        .send_data(bytes::Bytes::from_static(b"ping"))
        .await
        .expect("send data");
    let mut echoed = stream.recv_data().await.expect("recv").expect("data");
    assert_eq!(&echoed.copy_to_bytes(echoed.remaining())[..], b"ping");

    stream.finish().await.expect("finish");

    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://example.com/wt")
        .body(())
        .expect("WebTransport request");
    request.extensions_mut().insert(
        "webtransport"
            .parse::<h3::ext::Protocol>()
            .ok()
            .expect("protocol"),
    );
    let mut stream = send_request
        .send_request(request)
        .await
        .expect("send WebTransport");
    let response = stream.recv_response().await.expect("response");
    assert_eq!(response.status(), http::StatusCode::NOT_IMPLEMENTED);
    stream.finish().await.expect("finish");

    drop(h3);

    endpoint.close(0u32.into(), b"done");
    let _ = stop_tx.send(true);
    let _ = handle.await;

    let _ = TcpStream::connect(echo).await;
}
