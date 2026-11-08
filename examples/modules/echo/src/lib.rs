//! Example Elira native module.
//!
//! It implements the ABI documented in `elira-module`: accept a JSON request,
//! return a JSON response, and expose the optional `elira_free` and
//! `elira_version` symbols. The response body is `"<method> <path>"` and the
//! headers mark the answer with `x-module: echo`.
//!
//! Build it with `cargo build --manifest-path examples/modules/echo/Cargo.toml`
//! and load `target/debug/libelira_module_echo.so` from the host.

use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use serde::{Deserialize, Serialize};

/// Includes the terminator because `elira_version` returns a C string.
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

/// The actual module logic. Everything fallible is converted to `()`, and the
/// FFI wrapper turns that into a non-zero status without letting a panic cross
/// the C boundary.
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

/// Entry point required by the ABI.
///
/// # Safety
///
/// The host must pass a readable request buffer, two valid out-pointers, and
/// later release the returned buffer with [`elira_free`] using the same length.
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

    // Leave the out-parameters in a defined state even when the request is
    // rejected. The host checks the pointer before looking at the length.
    // SAFETY: both pointers were checked for null and the host guarantees they
    // point to writable storage.
    unsafe {
        *response_ptr = std::ptr::null_mut();
        *response_len = 0;
    }

    // SAFETY: the ABI requires `request_len` readable bytes behind
    // `request_ptr`; the null check above covers the empty case.
    let request = unsafe { slice::from_raw_parts(request_ptr, request_len) };

    // A Rust panic must not unwind into the host. Catching here also keeps the
    // example honest for the `elira-module` documentation.
    let bytes = match catch_unwind(AssertUnwindSafe(|| handle(request))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(())) => return 1,
        Err(_) => return 2,
    };

    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;

    // SAFETY: the host passed valid out-pointers, checked above.
    unsafe {
        *response_ptr = ptr;
        *response_len = len;
    }
    0
}

/// Frees a buffer produced by [`elira_handle`].
///
/// # Safety
///
/// `ptr` and `len` must be exactly the values returned by [`elira_handle`],
/// and the buffer must not have been freed already.
#[no_mangle]
pub unsafe extern "C" fn elira_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the host contract says this pointer and length came from
    // `Box::into_raw` in `elira_handle` and have not been freed yet.
    let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(unsafe { Box::from_raw(slice) });
}

/// Optional version string. The host copies it before the library is closed.
#[no_mangle]
pub extern "C" fn elira_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Serde adapter for the base64 body field. The host uses the same standard
/// alphabet, so both sides agree without a second representation.
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
