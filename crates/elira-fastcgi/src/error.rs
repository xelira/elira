use std::io;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid FastCGI target {value:?}: {reason}")]
    InvalidTarget { value: String, reason: String },

    #[error("cannot connect to FastCGI server {target}: {source}")]
    Connect {
        target: String,

        #[source]
        source: io::Error,
    },

    #[error("{context}: {source}")]
    Io {
        context: &'static str,

        #[source]
        source: io::Error,
    },

    #[error("FastCGI protocol error: {0}")]
    Protocol(String),

    #[error("FastCGI response is invalid: {0}")]
    Response(String),

    #[error("FastCGI request is invalid: {0}")]
    Request(String),

    #[error("reading the request body: {0}")]
    RequestBody(#[source] crate::BoxError),

    #[error("FastCGI server {target} did not answer within {duration:?}")]
    Timeout { target: String, duration: Duration },
}
