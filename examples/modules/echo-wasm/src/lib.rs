use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    method: String,
    path: String,
    body: String,
}

#[derive(Serialize)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn leak_response(bytes: Vec<u8>) -> i64 {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    (i64::from(ptr as u32) << 32) | i64::from(len as u32)
}

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

#[no_mangle]
pub extern "C" fn elira_alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    let boxed: Box<[u8]> = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(boxed) as *mut u8 as i32
}

#[no_mangle]
pub unsafe extern "C" fn elira_handle(req_ptr: i32, req_len: i32) -> i64 {
    if req_len <= 0 {
        return failure();
    }

    let request = unsafe {
        std::slice::from_raw_parts(req_ptr as u32 as usize as *const u8, req_len as usize)
    };
    match handle(request) {
        Some(bytes) => leak_response(bytes),
        None => failure(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn elira_free(ptr: i32, len: i32) {
    if len <= 0 {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(ptr as u32 as usize as *mut u8, len as usize);

    drop(unsafe { Box::from_raw(slice) });
}
