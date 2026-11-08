//! Elira — HTTP server and reverse proxy.
//!
//! The binary lives in `main.rs`. This library is the same server with a
//! different entry point: it exists so tests can drive it without spawning a
//! process, and so the proxy can be embedded.

mod access_log;
pub mod proxy_protocol;
mod sendfile;
pub mod server;

pub use elira_config as config;
pub use elira_proxy as proxy;
