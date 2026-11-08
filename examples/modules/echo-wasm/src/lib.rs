//! Example sandboxed WebAssembly module for Elira.
//!
//! The module implements the ABI documented in `elira-wasm`:
//!
//! ```text
//! memory
//! elira_alloc(len: i32) -> i32
//! elira_handle(req_ptr: i32, req_len: i32) -> i64
//! elira_free(ptr: i32, len: i32)
//! ```
//!
//! The response body is the request body passed through unchanged. Bodies are
//! base64 strings in the shared JSON envelope, so copying the encoded string
//! is the same as echoing the decoded bytes. The response also sets
//! `x-module: echo-wasm`.
//!
//! Build for Wasm with:
//!
//! ```sh
//! rustup target add wasm32-unknown-unknown
//! cargo build --manifest-path examples/modules/echo-wasm/Cargo.toml \
//!     --target wasm32-unknown-unknown --release
//! ```
//!
//! The resulting file is `target/wasm32-unknown-unknown/release/elira_echo_wasm.wasm`.

use serde::{Deserialize, Serialize};

/// The subset of the request envelope this example uses. Unknown fields are
/// ignored by serde, and `body` stays base64-encoded. Passing it straight back
/// in the response is a byte-for-byte echo of the request body.
#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    body: String,
}

/// The response envelope. `body` is still the base64 string from the request.
#[derive(Serialize)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// Converts a byte vector into the packed `(ptr << 32) | len` value.
///
/// The allocation is intentionally leaked here. The host copies the response
/// and then calls [`elira_free`] with the same pointer and length, which
/// reconstructs the boxed slice.
fn leak_response(bytes: Vec<u8>) -> i64 {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    (i64::from(ptr as u32) << 32) | i64::from(len as u32)
}

/// Returns a zero response, which the host reports as a malformed response.
fn failure() -> i64 {
    0
}

fn handle(request: &[u8]) -> Option<Vec<u8>> {
    let request: Request = serde_json::from_slice(request).ok()?;
    let response = Response {
        status: 200,
        headers: vec![
            ("x-module".to_string(), "echo-wasm".to_string()),
            (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
            ("x-echo-method".to_string(), request.method.clone()),
            ("x-echo-path".to_string(), request.path.clone()),
        ],
        body: request.body,
    };
    serde_json::to_vec(&response).ok()
}

/// Allocates `len` bytes of linear memory for the host's request.
///
/// The host writes the JSON request at the returned offset. A non-positive
/// length is not expected, but returning 0 is a defined failure value.
#[no_mangle]
pub extern "C" fn elira_alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    let boxed: Box<[u8]> = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(boxed) as *mut u8 as i32
}

/// Handles one request and returns the packed response pointer and length.
///
/// # Safety
///
/// The host must pass a readable range `[req_ptr, req_ptr + req_len)` inside
/// the exported linear memory. It must not use the returned buffer after
/// calling [`elira_free`] on it.
#[no_mangle]
pub unsafe extern "C" fn elira_handle(req_ptr: i32, req_len: i32) -> i64 {
    if req_len <= 0 {
        return failure();
    }
    // SAFETY: the ABI requires `req_len` readable bytes at `req_ptr`. The host
    // allocates that range with `elira_alloc` and writes the request there.
    // The offset is reinterpreted as unsigned, because a wasm32 address may
    // have its high bit set even though the Rust parameter is an `i32`.
    let request = unsafe {
        std::slice::from_raw_parts(req_ptr as u32 as usize as *const u8, req_len as usize)
    };
    match handle(request) {
        Some(bytes) => leak_response(bytes),
        None => failure(),
    }
}

/// Releases a request or response buffer allocated by [`elira_alloc`] or
/// [`leak_response`].
///
/// # Safety
///
/// `ptr` and `len` must be exactly the values produced by this module for an
/// allocation that has not already been freed. A zero length is a no-op.
#[no_mangle]
pub unsafe extern "C" fn elira_free(ptr: i32, len: i32) {
    if len <= 0 {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(ptr as u32 as usize as *mut u8, len as usize);
    // SAFETY: the pointer came from `Box::into_raw` with exactly this length
    // and the host calls this function once per allocation.
    drop(unsafe { Box::from_raw(slice) });
}
