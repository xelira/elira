//! Errors returned while loading and calling a WebAssembly module.
//!
//! The variants keep the failing operation visible. A module that traps is not
//! the same failure as a host that could not parse the response, and a module
//! that returns an out-of-bounds pointer is not the same failure as one that
//! returns a valid buffer with invalid JSON. Operators debugging a module need
//! that distinction, and tests can match on it without inspecting strings.

use thiserror::Error;

/// Everything that can go wrong between reading a `.wasm` file and using the
/// response of a call.
#[derive(Debug, Error)]
pub enum Error {
    /// The input contained no bytes at all. An empty file cannot be a Wasm
    /// module, and reporting it separately from a parse failure gives the
    /// operator a useful hint.
    #[error("wasm module is empty")]
    EmptyModule,

    /// The module bytes exceed [`crate::MAX_MODULE_BYTES`].
    #[error("wasm module is {len} bytes, limit is {limit}")]
    ModuleTooLarge { len: usize, limit: usize },

    /// Reading the module file failed.
    #[error("read wasm module {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Wasmi rejected the bytes as an invalid or unsupported Wasm module.
    #[error("compile wasm module: {source}")]
    Compile {
        #[source]
        source: wasmi::Error,
    },

    /// The module imports a host item. Elira provides no imports, so a module
    /// that needs WASI, filesystem access or a network socket is rejected
    /// before instantiation. The import is named in the error.
    #[error("wasm module imports {module}::{name}; imports are not allowed")]
    UnsupportedImport { module: String, name: String },

    /// A required export is absent.
    #[error("wasm module does not export {name}")]
    MissingExport { name: &'static str },

    /// An export exists but has the wrong kind or function signature.
    #[error("wasm export {name} must be {expected}")]
    InvalidExport {
        name: &'static str,
        expected: &'static str,
    },

    /// Instantiation failed, for example because the declared memory minimum
    /// exceeds [`crate::MAX_MEMORY_BYTES`] or a start function trapped.
    #[error("instantiate wasm module: {source}")]
    Instantiate {
        #[source]
        source: wasmi::Error,
    },

    /// Looking up a validated export on the instantiated module failed. This
    /// should not happen after the export checks, but keeping it as an error
    /// avoids an `expect` on a value produced by a foreign module.
    #[error("resolve wasm export {name}: {source}")]
    Resolve {
        name: &'static str,
        #[source]
        source: wasmi::Error,
    },

    /// A previous call panicked while holding the instance lock. Continuing
    /// would use a store of unknown consistency, so the module is failed
    /// closed instead of unwrapping the mutex.
    #[error("wasm instance lock is poisoned")]
    Poisoned,

    /// Serializing the request produced more than [`crate::MAX_REQUEST_BYTES`].
    #[error("request JSON is {len} bytes, limit is {limit}")]
    RequestTooLarge { len: usize, limit: usize },

    /// Request serialization or response parsing failed.
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    /// `elira_alloc` returned a negative value. The ABI treats the result as a
    /// 32-bit linear-memory offset, so a negative `i32` cannot be an address.
    #[error("elira_alloc returned an invalid pointer {code}")]
    Allocation { code: i32 },

    /// A host read or write of the module's linear memory was out of bounds.
    /// Wasmi checks the range against the current memory size, so this is a
    /// controlled error rather than a host process fault.
    #[error("{operation}: {source}")]
    Memory {
        operation: &'static str,
        #[source]
        source: wasmi::errors::MemoryError,
    },

    /// An exported function trapped or ran out of resources. Wasmi catches the
    /// trap and returns it as an error; it does not unwind across the host.
    #[error("{operation} trapped: {source}")]
    Trap {
        operation: &'static str,
        #[source]
        source: wasmi::Error,
    },

    /// `elira_handle` reported a response range outside linear memory. The
    /// packed pointer and length are reported so a module author can see what
    /// was actually returned.
    #[error(
        "elira_handle returned pointer {ptr:#010x} with {len} bytes outside linear memory: {source}"
    )]
    BadResponsePointer {
        ptr: u32,
        len: u32,
        #[source]
        source: wasmi::errors::MemoryError,
    },

    /// The module announced a response larger than
    /// [`crate::MAX_RESPONSE_BYTES`]. The length is checked before a host
    /// buffer is allocated, so a bogus length cannot exhaust memory.
    #[error("response is {len} bytes, limit is {limit}")]
    ResponseTooLarge { len: usize, limit: usize },

    /// The response bytes are not valid UTF-8 and therefore cannot be JSON.
    #[error("{context} is not UTF-8: {source}")]
    Utf8 {
        context: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },

    /// The parsed status is outside `100..=599`. Passing it through would turn
    /// a module bug into a malformed HTTP response.
    #[error("module returned status {status}, expected 100..=599")]
    InvalidStatus { status: u16 },

    /// The optional `elira_free` export trapped while releasing a buffer.
    #[error("elira_free trapped: {source}")]
    Free {
        #[source]
        source: wasmi::Error,
    },
}
