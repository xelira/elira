use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("wasm module is empty")]
    EmptyModule,

    #[error("wasm module is {len} bytes, limit is {limit}")]
    ModuleTooLarge { len: usize, limit: usize },

    #[error("read wasm module {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("compile wasm module: {source}")]
    Compile {
        #[source]
        source: wasmi::Error,
    },

    #[error("wasm module imports {module}::{name}; imports are not allowed")]
    UnsupportedImport { module: String, name: String },

    #[error("wasm module does not export {name}")]
    MissingExport { name: &'static str },

    #[error("wasm export {name} must be {expected}")]
    InvalidExport {
        name: &'static str,
        expected: &'static str,
    },

    #[error("instantiate wasm module: {source}")]
    Instantiate {
        #[source]
        source: wasmi::Error,
    },

    #[error("resolve wasm export {name}: {source}")]
    Resolve {
        name: &'static str,
        #[source]
        source: wasmi::Error,
    },

    #[error("wasm instance lock is poisoned")]
    Poisoned,

    #[error("request JSON is {len} bytes, limit is {limit}")]
    RequestTooLarge { len: usize, limit: usize },

    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("elira_alloc returned an invalid pointer {code}")]
    Allocation { code: i32 },

    #[error("{operation}: {source}")]
    Memory {
        operation: &'static str,
        #[source]
        source: wasmi::errors::MemoryError,
    },

    #[error("{operation} trapped: {source}")]
    Trap {
        operation: &'static str,
        #[source]
        source: wasmi::Error,
    },

    #[error(
        "elira_handle returned pointer {ptr:#010x} with {len} bytes outside linear memory: {source}"
    )]
    BadResponsePointer {
        ptr: u32,
        len: u32,
        #[source]
        source: wasmi::errors::MemoryError,
    },

    #[error("response is {len} bytes, limit is {limit}")]
    ResponseTooLarge { len: usize, limit: usize },

    #[error("{context} is not UTF-8: {source}")]
    Utf8 {
        context: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error("module returned status {status}, expected 100..=599")]
    InvalidStatus { status: u16 },

    #[error("elira_free trapped: {source}")]
    Free {
        #[source]
        source: wasmi::Error,
    },
}
