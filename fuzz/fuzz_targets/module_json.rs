#![no_main]

use elira_module::{Request, Response};
use libfuzzer_sys::fuzz_target;

// Both envelope types cross the native module ABI as JSON. Deserialization is
// the host's first parse of untrusted module output, so fuzz it directly with
// arbitrary bytes (including invalid UTF-8 and bad base64 bodies).
fuzz_target!(|data: &[u8]| {
    let _: Result<Request, _> = serde_json::from_slice(data);
    let _: Result<Response, _> = serde_json::from_slice(data);
});
