#![no_main]

use libfuzzer_sys::fuzz_target;

// `Target::parse` is the public entry point for `fastcgi_pass` values, so give
// it arbitrary UTF-8 rather than only well-formed `host:port` and `unix:`
// strings.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let _ = elira_fastcgi::Target::parse(text);
});
