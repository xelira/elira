use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use serde::{Deserialize, Serialize};

const VERSION: &str = concat!("echo ", env!("CARGO_PKG_VERSION"), "\0");

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    #[serde(with = "base64_bytes")]
    body: Vec<u8>,
}

#[derive(Serialize)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    #[serde(with = "base64_bytes")]
    body: Vec<u8>,
}

fn handle(request: &[u8]) -> Result<Vec<u8>, ()> {
    let request: Request = serde_json::from_slice(request).map_err(|_| ())?;

    let body = format!("{} {}", request.method, request.path).into_bytes();
    let response = Response {
        status: 200,
        headers: vec![
            ("x-module".to_string(), "echo".to_string()),
            (
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                "x-echo-body-len".to_string(),
                request.body.len().to_string(),
            ),
        ],
        body,
    };

    serde_json::to_vec(&response).map_err(|_| ())
}

#[no_mangle]
pub unsafe extern "C" fn elira_handle(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut *mut u8,
    response_len: *mut usize,
) -> c_int {
    if request_ptr.is_null() || response_ptr.is_null() || response_len.is_null() {
        return 1;
    }

    unsafe {
        *response_ptr = std::ptr::null_mut();
        *response_len = 0;
    }

    let request = unsafe { slice::from_raw_parts(request_ptr, request_len) };

    let bytes = match catch_unwind(AssertUnwindSafe(|| handle(request))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(())) => return 1,
        Err(_) => return 2,
    };

    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;

    unsafe {
        *response_ptr = ptr;
        *response_len = len;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn elira_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }

    let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(unsafe { Box::from_raw(slice) });
}

#[no_mangle]
pub extern "C" fn elira_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

mod base64_bytes {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
