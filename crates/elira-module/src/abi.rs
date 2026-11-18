use std::ffi::{c_char, c_int};

use serde::{Deserialize, Serialize};

pub type HandleFn = unsafe extern "C" fn(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut *mut u8,
    response_len: *mut usize,
) -> c_int;

pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize);

pub type VersionFn = unsafe extern "C" fn() -> *const c_char;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub method: String,

    pub path: String,

    pub query: String,

    pub host: String,

    pub headers: Vec<(String, String)>,

    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,

    pub remote_addr: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,

    pub headers: Vec<(String, String)>,

    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
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
