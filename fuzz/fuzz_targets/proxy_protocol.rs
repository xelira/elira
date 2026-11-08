#![no_main]

use std::io::Write;
use std::net::TcpListener;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio runtime")
    })
}

// The pure v1/v2 parsers are private. `read_peer` is the public entry point,
// so drive it through a loopback TcpStream with the fuzz input as the bytes
// the peer would send.
fuzz_target!(|data: &[u8]| {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => listener,
        Err(_) => return,
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let payload = data.to_vec();
    let writer = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(&payload);
        }
    });

    runtime().block_on(async {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            let _ = elira::proxy_protocol::read_peer(&mut stream).await;
        }
    });

    let _ = writer.join();
});
