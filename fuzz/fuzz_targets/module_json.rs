#![no_main]

use elira_module::{Request, Response};
use libfuzzer_sys::fuzz_target;




fuzz_target!(|data: &[u8]| {
    let _: Result<Request, _> = serde_json::from_slice(data);
    let _: Result<Response, _> = serde_json::from_slice(data);
});
