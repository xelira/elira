//! Elira — HTTP server and reverse proxy.
//!
//! The binary lives in `main.rs`. This library exists so the proxy can be
//! embedded in tests and other tools without spawning a process.

pub use elira_config as config;
pub use elira_proxy as proxy;
