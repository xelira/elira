//! Errors returned by the FastCGI client.

use std::io;
use std::time::Duration;

use thiserror::Error;

/// Something went wrong before, during, or after a FastCGI exchange.
///
/// The variants are deliberately coarse: a proxy usually turns any failure
/// into a 502 and logs the text. The important distinction is between a
/// problem reaching the server (`Connect`, `Io`, `Timeout`) and a server that
/// answered with something that is not a usable response (`Protocol`,
/// `Response`).
#[derive(Debug, Error)]
pub enum Error {
    /// The configured target could not be turned into a socket address.
    #[error("invalid FastCGI target {value:?}: {reason}")]
    InvalidTarget {
        /// The value exactly as it was passed to [`Target::parse`](crate::Target::parse).
        value: String,
        /// What is wrong with it.
        reason: String,
    },

    /// The socket could not be opened.
    #[error("cannot connect to FastCGI server {target}: {source}")]
    Connect {
        /// Human-readable target, for example `tcp://127.0.0.1:9000`.
        target: String,
        /// The underlying socket error.
        #[source]
        source: io::Error,
    },

    /// A write or read failed after the connection was established.
    #[error("{context}: {source}")]
    Io {
        /// The operation that failed.
        context: &'static str,
        /// The underlying socket error.
        #[source]
        source: io::Error,
    },

    /// The peer did not follow the FastCGI record protocol.
    #[error("FastCGI protocol error: {0}")]
    Protocol(String),

    /// The FastCGI stream ended without a usable CGI response.
    #[error("FastCGI response is invalid: {0}")]
    Response(String),

    /// The request cannot be represented in the FastCGI wire format.
    #[error("FastCGI request is invalid: {0}")]
    Request(String),

    /// Reading from the caller's streaming request body failed.
    #[error("reading the request body: {0}")]
    RequestBody(#[source] crate::BoxError),

    /// The exchange did not finish before the deadline.
    #[error("FastCGI server {target} did not answer within {duration:?}")]
    Timeout {
        /// Human-readable target, for example `unix:/run/php.sock`.
        target: String,
        /// The timeout that was configured.
        duration: Duration,
    },
}
