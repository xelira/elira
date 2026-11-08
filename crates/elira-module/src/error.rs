//! Errors returned while loading and calling a native module.

use thiserror::Error;

/// Everything that can go wrong between opening a `.so` and using its
/// response.
///
/// The variants keep the module's own failure code instead of flattening it
/// into a string: an operator debugging a broken plugin needs to know whether
/// the module rejected the request or the host could not parse the answer.
#[derive(Debug, Error)]
pub enum Error {
    /// The shared library could not be opened. This also covers a path that
    /// exists but is not a loadable object for this platform.
    #[error("open module {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: libloading::Error,
    },

    /// A required symbol is missing, or the loader refused to resolve it.
    #[error("resolve {symbol}: {source}")]
    Symbol {
        symbol: &'static str,
        #[source]
        source: libloading::Error,
    },

    /// The module accepted the request but returned a non-zero status.
    #[error("module returned error code {code}")]
    Call { code: i32 },

    /// The module reported success while leaving the response pointer null.
    #[error("module returned a null response pointer for {len} bytes")]
    NullResponse { len: usize },

    /// The serialized request is larger than [`crate::MAX_REQUEST_BYTES`].
    #[error("request JSON is {len} bytes, limit is {limit}")]
    RequestTooLarge { len: usize, limit: usize },

    /// The response is larger than [`crate::MAX_RESPONSE_BYTES`].
    #[error("response is {len} bytes, limit is {limit}")]
    ResponseTooLarge { len: usize, limit: usize },

    /// The response bytes are not valid UTF-8 and therefore cannot be JSON.
    #[error("{context} is not UTF-8: {source}")]
    Utf8 {
        context: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },

    /// Request serialization or response parsing failed.
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    /// The module returned a buffer but does not export `elira_free`, so the
    /// host has no safe way to release it.
    #[error("module returned {len} bytes but does not export elira_free; the buffer is leaked")]
    NoFree { len: usize },

    /// The module returned a status outside the HTTP range. Passing it on
    /// would turn a module bug into a malformed response on the wire.
    #[error("module returned status {status}, expected 100..=599")]
    InvalidStatus { status: u16 },
}
