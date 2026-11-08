#![no_main]

use http::header::ACCEPT_ENCODING;
use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;

// `preferred_encoding` and `compressible` are the public header helpers in
// elira-proxy. Feed arbitrary Accept-Encoding values to the quality parser and
// arbitrary content types to the compressibility check.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(text) {
        headers.insert(ACCEPT_ENCODING, value);
    }

    let _ = elira_proxy::preferred_encoding(&headers);
    let _ = elira_proxy::compressible(text);
});
