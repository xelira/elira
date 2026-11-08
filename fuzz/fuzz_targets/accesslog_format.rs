#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use elira_accesslog::{Entry, Format};
use http::{Method, StatusCode, Version};
use libfuzzer_sys::fuzz_target;

fn entry() -> Entry {
    Entry {
        peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        method: Method::GET,
        version: Version::HTTP_11,
        host: "example.com".to_owned(),
        path: "/path".to_owned(),
        status: StatusCode::OK,
        bytes: 1234,
        duration: Duration::from_millis(12),
        user_agent: Some("curl/8.0".to_owned()),
        request_id: "a1b2c3d4e5f60718".to_owned(),
    }
}

// Parse an arbitrary nginx-like `$variable` template and render a fixed entry.
// The template is the untrusted part; rendering must never panic or let a
// control character through unescaped.
fuzz_target!(|data: &[u8]| {
    let Ok(template) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(format) = Format::parse(template) {
        let _ = format.render(&entry());
    }
});
