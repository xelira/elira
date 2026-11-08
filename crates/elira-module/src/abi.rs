//! Wire types and function signatures shared with a native module.
//!
//! The JSON object is the ABI. Field names, nesting and the base64 encoding of
//! `body` are stable; changing them breaks every already-compiled module.
//!
//! ```json
//! {
//!   "method": "POST",
//!   "path": "/hello",
//!   "query": "a=1",
//!   "host": "example.com",
//!   "headers": [["content-type", "text/plain"]],
//!   "body": "aGVsbG8=",
//!   "remote_addr": "192.0.2.1:443"
//! }
//! ```
//!
//! `body` is standard base64 with padding, not a JSON array of numbers. A
//! 1 MiB body would become roughly 4 MiB of decimal digits as an array; the
//! encoded string costs about 1.4 MiB and parses faster. Both sides must use
//! the same alphabet and padding, so no URL-safe variant and no missing `=`.

use std::ffi::{c_char, c_int};

use serde::{Deserialize, Serialize};

/// Signature of `elira_handle`.
///
/// The host owns the request buffer for the duration of the call. On success
/// the module stores a heap buffer in `response_ptr`/`response_len` and
/// returns `0`; on failure it returns a non-zero code. The response buffer is
/// released with [`FreeFn`] when the module exports one.
pub type HandleFn = unsafe extern "C" fn(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut *mut u8,
    response_len: *mut usize,
) -> c_int;

/// Signature of the optional `elira_free`.
///
/// The arguments are exactly the pointer and length the module returned from
/// `elira_handle`. The host calls it after copying the response, so the module
/// must not expect the buffer to stay in use.
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize);

/// Signature of the optional `elira_version`.
///
/// The returned pointer must stay valid for the lifetime of the library and
/// point at a NUL-terminated string.
pub type VersionFn = unsafe extern "C" fn() -> *const c_char;

/// A request handed to a module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// HTTP method as received, for example `GET`.
    pub method: String,
    /// Request path without the query string.
    pub path: String,
    /// Raw query string without the leading `?`. Empty when absent.
    pub query: String,
    /// Host header, including a non-default port when the client sent one.
    pub host: String,
    /// Request headers in wire order. Values are not trimmed or folded.
    pub headers: Vec<(String, String)>,
    /// Raw request body. Serialized as a base64 string, see the module docs.
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    /// Peer address in `IP:port` form.
    pub remote_addr: String,
}

/// A response produced by a module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// HTTP status code. [`crate::Module::call`] rejects values outside
    /// `100..=599`.
    pub status: u16,
    /// Response headers. Duplicates are allowed; order is preserved.
    pub headers: Vec<(String, String)>,
    /// Raw response body, serialized as base64 in the JSON envelope.
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
}

impl Response {
    /// Creates an empty response with the given status.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// Serde adapter for the base64 body field. Kept private so the wire format
/// only has one implementation.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: Vec<u8>) -> Request {
        Request {
            method: "POST".to_string(),
            path: "/hello".to_string(),
            query: "a=1&b=2".to_string(),
            host: "example.com:8443".to_string(),
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-test".to_string(), "one".to_string()),
            ],
            body,
            remote_addr: "192.0.2.1:51000".to_string(),
        }
    }

    #[test]
    fn request_round_trip_preserves_non_utf8_body() {
        let original = request(vec![0x00, 0xff, b'h', b'i', 0x80]);
        let json = serde_json::to_vec(&original).expect("request serializes");
        let decoded: Request = serde_json::from_slice(&json).expect("request parses");
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_body_is_a_base64_string() {
        let value = serde_json::to_value(request(b"hello".to_vec())).expect("request serializes");
        assert_eq!(value["body"], "aGVsbG8=");
        assert!(value["body"].is_string());
    }

    #[test]
    fn empty_body_is_an_empty_string() {
        let value = serde_json::to_value(request(Vec::new())).expect("request serializes");
        assert_eq!(value["body"], "");
    }

    #[test]
    fn headers_serialize_as_pairs_in_order() {
        let value = serde_json::to_value(request(Vec::new())).expect("request serializes");
        assert_eq!(value["headers"][0][0], "content-type");
        assert_eq!(value["headers"][0][1], "text/plain");
        assert_eq!(value["headers"][1][0], "x-test");
    }

    #[test]
    fn request_has_exactly_the_documented_fields() {
        let value = serde_json::to_value(request(Vec::new())).expect("request serializes");
        let object = value.as_object().expect("request is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "body",
                "headers",
                "host",
                "method",
                "path",
                "query",
                "remote_addr"
            ]
        );
    }

    #[test]
    fn response_round_trip_preserves_body() {
        let original = Response {
            status: 201,
            headers: vec![("x-module".to_string(), "echo".to_string())],
            body: vec![0x00, 0xfe, b'o', b'k'],
        };
        let json = serde_json::to_vec(&original).expect("response serializes");
        let decoded: Response = serde_json::from_slice(&json).expect("response parses");
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_body_is_a_base64_string() {
        let response = Response {
            status: 200,
            headers: Vec::new(),
            body: b"hello".to_vec(),
        };
        let value = serde_json::to_value(response).expect("response serializes");
        assert_eq!(value["body"], "aGVsbG8=");
    }

    #[test]
    fn response_new_starts_empty() {
        let response = Response::new(204);
        assert_eq!(response.status, 204);
        assert!(response.headers.is_empty());
        assert!(response.body.is_empty());
    }

    #[test]
    fn malformed_base64_is_rejected() {
        let json = r#"{
            "method":"GET",
            "path":"/",
            "query":"",
            "host":"example.com",
            "headers":[],
            "body":"not base64!",
            "remote_addr":"192.0.2.1:1"
        }"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    #[test]
    fn url_safe_base64_is_not_accepted() {
        // The ABI says standard alphabet with padding; accepting both would
        // make the encoding ambiguous for a module that re-serializes it.
        let json = r#"{
            "method":"GET",
            "path":"/",
            "query":"",
            "host":"example.com",
            "headers":[],
            "body":"_-8=",
            "remote_addr":"192.0.2.1:1"
        }"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }
}
