use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("open module {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: libloading::Error,
    },

    #[error("resolve {symbol}: {source}")]
    Symbol {
        symbol: &'static str,
        #[source]
        source: libloading::Error,
    },

    #[error("module returned error code {code}")]
    Call { code: i32 },

    #[error("module returned a null response pointer for {len} bytes")]
    NullResponse { len: usize },

    #[error("request JSON is {len} bytes, limit is {limit}")]
    RequestTooLarge { len: usize, limit: usize },

    #[error("response is {len} bytes, limit is {limit}")]
    ResponseTooLarge { len: usize, limit: usize },

    #[error("{context} is not UTF-8: {source}")]
    Utf8 {
        context: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("module returned {len} bytes but does not export elira_free; the buffer is leaked")]
    NoFree { len: usize },

    #[error("module returned status {status}, expected 100..=599")]
    InvalidStatus { status: u16 },

    #[error("module process: {reason}")]
    Process { reason: String },
}
