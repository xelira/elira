//! Sandboxed WebAssembly modules for Elira.
//!
//! A Wasm module is an alternative to the native shared libraries handled by
//! [`elira_module`]. The host serializes an [`elira_module::Request`] to JSON,
//! passes it through a tiny linear-memory ABI, and parses the JSON
//! [`elira_module::Response`] that comes back. The module runs inside the
//! `wasmi` interpreter: it has no filesystem, network, clock or environment
//! imports, and the host checks every pointer against the module's linear
//! memory. This is a capability sandbox, not a process boundary, so a module
//! still shares the host's address space and thread.
//!
//! # ABI
//!
//! A module must export:
//!
//! ```text
//! memory
//! elira_alloc(len: i32) -> i32
//! elira_handle(req_ptr: i32, req_len: i32) -> i64
//! ```
//!
//! `elira_alloc` returns an offset into `memory` at which the host writes
//! `req_len` bytes of UTF-8 JSON. `elira_handle` returns a packed response:
//!
//! ```text
//! (ptr << 32) | len
//! ```
//!
//! Both halves are 32-bit unsigned values. `ptr` is an offset into `memory`
//! and `len` is the byte length of a UTF-8 JSON response. The host copies the
//! bytes out immediately; it never holds a pointer past the call.
//!
//! A module may also export:
//!
//! ```text
//! elira_free(ptr: i32, len: i32)
//! ```
//!
//! When `elira_free` is present the host releases the request buffer and a
//! distinct response buffer after copying the response. When it is absent the
//! host never frees anything: the module owns all of its linear-memory buffers
//! and may reuse them across calls. That is why a module without `elira_free`
//! may return the same response buffer on every call, as long as it rewrites
//! the bytes before returning. The host never calls a null or absent free
//! function.
//!
//! If the response pointer equals the request pointer, the host treats it as
//! one allocation and releases it once with the original request length. A
//! response buffer must not overlap the request buffer at a different base
//! address; such a module would be freed twice.
//!
//! When a response is rejected because its pointer is outside linear memory or
//! its length exceeds [`MAX_RESPONSE_BYTES`], the host releases the request but
//! deliberately does not call `elira_free` on the untrusted response range.
//! The allocation remains part of the instance's linear memory and is
//! reclaimed when the module is dropped. Calling a module's free function with
//! a bogus length would give hostile code another chance to run unbounded
//! cleanup work, so the host fails closed instead.
//!
//! On failure a module should return a zero value (`ptr == 0`, `len == 0`).
//! The host then sees an empty response and reports a JSON parse error; it
//! does not treat zero as a valid allocation. Wasm traps are caught by wasmi
//! and returned as [`Error::Trap`].
//!
//! # Limits
//!
//! - Module files are limited to [`MAX_MODULE_BYTES`] (16 MiB).
//! - Serialized requests and accepted responses are limited to 16 MiB.
//! - Each linear memory may grow to [`MAX_MEMORY_BYTES`] (256 MiB).
//! - One instance and one memory are allowed per module.
//! - At most 64 tables and one million table elements are allowed.
//! - Arbitrary imports are rejected before instantiation.
//!
//! The size checks happen before allocating a host buffer. A response length
//! larger than [`MAX_RESPONSE_BYTES`] is rejected without reading memory, so a
//! module cannot make the host allocate an attacker-chosen amount.
//!
//! # Trust and safety
//!
//! Wasmi is a pure-Rust interpreter with checked memory accesses. A module
//! cannot read host memory through a bad pointer, call a host function (there
//! are no imports), open a socket or read a file. The host does not expose a
//! pointer to its own heap; the only shared region is the module's own linear
//! memory.
//!
//! A module is still untrusted code: it can consume CPU indefinitely if it
//! loops inside `elira_handle`, and it can use up to its memory limit. There is
//! each call has a fixed fuel budget ([`MAX_FUEL`]), so an infinite loop traps;
//! a wall-clock timeout is still the caller's responsibility for long but
//! finite modules. A trap, a bad pointer, a malformed response or an
//! oversized response becomes an [`Error`]; none of them unwind into the host.
//!
//! [`WasmModule`] is `Send + Sync`. One loaded instance is serialized behind a
//! [`std::sync::Mutex`], so concurrent calls do not run the same module twice
//! at the same time. Load several modules (or several instances) for parallel
//! execution.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! use elira_module::Request;
//! use elira_wasm::WasmModule;
//!
//! let module = WasmModule::load(Path::new(
//!     "examples/modules/echo-wasm/target/wasm32-unknown-unknown/release/elira_echo_wasm.wasm",
//! ))?;
//!
//! let response = module.call(&Request {
//!     method: "POST".to_string(),
//!     path: "/echo".to_string(),
//!     query: String::new(),
//!     host: "example.com".to_string(),
//!     headers: Vec::new(),
//!     body: b"hello".to_vec(),
//!     remote_addr: "192.0.2.1:50000".to_string(),
//! })?;
//!
//! assert_eq!(response.status, 200);
//! assert_eq!(response.body, b"hello");
//! # Ok::<(), elira_wasm::Error>(())
//! ```

mod error;

pub use error::Error;

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use elira_module::{Request, Response};
use wasmi::{
    Config, Engine, ExternType, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
    TypedFunc, ValType,
};

/// Largest Wasm module accepted from disk or memory. A compiled module carries
/// code and data sections; 16 MiB is far above a normal module and small
/// enough that loading one cannot be used to exhaust the host.
pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

/// Largest serialized request handed to a module.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Largest response the host will accept. The check runs before the host
/// allocates a copy, so a module reporting a huge length cannot force a huge
/// allocation.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum amount of linear memory a single module may use, including growth.
/// The response limit is much smaller; this leaves room for a module's own
/// working set without allowing a 4 GiB allocation.
pub const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

/// Maximum number of table elements in the module's tables. Tables are not
/// used by the ABI, but a module can declare one; bounding it keeps a hostile
/// table declaration from reserving a large array.
pub const MAX_TABLE_ELEMENTS: usize = 1_000_000;

/// Fuel budget for one `elira_handle` call. Enough for normal modules, low
/// enough that an infinite loop traps instead of pinning a worker thread.
pub const MAX_FUEL: u64 = 5_000_000;

const MEMORY_EXPORT: &str = "memory";
const ALLOC_EXPORT: &str = "elira_alloc";
const HANDLE_EXPORT: &str = "elira_handle";
const FREE_EXPORT: &str = "elira_free";

/// A compiled Wasm module and its single instance.
///
/// Loading validates the module byte size, compiles it with wasmi, rejects all
/// imports, checks the export signatures and instantiates it. The instance's
/// store is protected by a mutex because wasmi calls need `&mut Store`; the
/// wrapper itself is therefore usable from several threads.
pub struct WasmModule {
    path: Option<PathBuf>,
    bytes: usize,
    state: Mutex<InstanceState>,
}

struct InstanceState {
    store: Store<StoreLimits>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    handle: TypedFunc<(i32, i32), i64>,
    free: Option<TypedFunc<(i32, i32), ()>>,
}

impl WasmModule {
    /// Compiles and instantiates a module from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyModule`] for an empty slice, [`Error::ModuleTooLarge`]
    /// when the input exceeds [`MAX_MODULE_BYTES`], and [`Error::Compile`] when
    /// wasmi rejects the bytes. A module with any import is rejected with
    /// [`Error::UnsupportedImport`] before it can run. Missing or mistyped
    /// exports are reported as [`Error::MissingExport`] or
    /// [`Error::InvalidExport`].
    pub fn load_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyModule);
        }
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(Error::ModuleTooLarge {
                len: bytes.len(),
                limit: MAX_MODULE_BYTES,
            });
        }

        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).map_err(|source| Error::Compile { source })?;

        // No imports means no filesystem, network, WASI, clock or host-function
        // capability. Rejecting here is clearer than letting the linker report
        // an unknown import, and it also rejects a module that merely declares
        // an unused import.
        if let Some(import) = module.imports().next() {
            return Err(Error::UnsupportedImport {
                module: import.module().to_string(),
                name: import.name().to_string(),
            });
        }

        validate_exports(&module)?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_BYTES)
            .memories(1)
            .tables(64)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(1)
            .build();
        let mut store = Store::new(&engine, limits);
        store.limiter(|limits: &mut StoreLimits| limits);

        let linker = Linker::<StoreLimits>::new(&engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|source| Error::Instantiate { source })?;

        let memory = instance
            .get_memory(&store, MEMORY_EXPORT)
            .ok_or(Error::MissingExport {
                name: MEMORY_EXPORT,
            })?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, ALLOC_EXPORT)
            .map_err(|source| Error::Resolve {
                name: ALLOC_EXPORT,
                source,
            })?;
        let handle = instance
            .get_typed_func::<(i32, i32), i64>(&store, HANDLE_EXPORT)
            .map_err(|source| Error::Resolve {
                name: HANDLE_EXPORT,
                source,
            })?;
        let free = if module.get_export(FREE_EXPORT).is_some() {
            Some(
                instance
                    .get_typed_func::<(i32, i32), ()>(&store, FREE_EXPORT)
                    .map_err(|source| Error::Resolve {
                        name: FREE_EXPORT,
                        source,
                    })?,
            )
        } else {
            None
        };

        Ok(Self {
            path: None,
            bytes: bytes.len(),
            state: Mutex::new(InstanceState {
                store,
                memory,
                alloc,
                handle,
                free,
            }),
        })
    }

    /// Reads, compiles and instantiates a module from a `.wasm` file.
    ///
    /// The file size is checked from metadata before reading, so an oversized
    /// file is rejected without loading its contents into memory. An empty
    /// file is rejected as [`Error::EmptyModule`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] when the file cannot be read and otherwise the
    /// same errors as [`load_bytes`](Self::load_bytes).
    pub fn load(path: &Path) -> Result<Self, Error> {
        let metadata = fs::metadata(path).map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;
        let len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if len == 0 {
            return Err(Error::EmptyModule);
        }
        if len > MAX_MODULE_BYTES {
            return Err(Error::ModuleTooLarge {
                len,
                limit: MAX_MODULE_BYTES,
            });
        }

        let bytes = {
            // Read at most one byte past the limit. A file that grows after
            // the metadata check can then be rejected without loading an
            // unbounded amount of data into the host.
            let file = fs::File::open(path).map_err(|source| Error::Read {
                path: path.display().to_string(),
                source,
            })?;
            let mut bytes = Vec::new();
            file.take(MAX_MODULE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|source| Error::Read {
                    path: path.display().to_string(),
                    source,
                })?;
            bytes
        };

        // Recheck the bytes we actually read. A file can grow between the
        // metadata call and the read, and the loaded slice is what matters.
        if bytes.is_empty() {
            return Err(Error::EmptyModule);
        }
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(Error::ModuleTooLarge {
                len: bytes.len(),
                limit: MAX_MODULE_BYTES,
            });
        }

        let mut module = Self::load_bytes(&bytes)?;
        module.path = Some(path.to_path_buf());
        Ok(module)
    }

    /// Returns the path the module was loaded from, if it came from a file.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the size of the compiled input in bytes, for diagnostics.
    pub fn wasm_len(&self) -> usize {
        self.bytes
    }

    /// Returns whether the module exports `elira_free`.
    ///
    /// A module without it owns its buffers. The host only reads the response
    /// range and never releases it.
    pub fn has_free(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.free.is_some())
            .unwrap_or(false)
    }

    /// Serializes `request`, invokes the module and parses its response.
    ///
    /// The request is encoded and size-checked before the instance lock is
    /// taken. A zero-length module response is parsed as JSON and therefore
    /// fails, which is the intended behaviour for a module that reports an
    /// error by returning `0`.
    ///
    /// # Errors
    ///
    /// Returns a size error when the request or response is too large, a
    /// [`Error::Trap`] when an exported function traps, a
    /// [`Error::BadResponsePointer`] when the packed response range is outside
    /// linear memory, and [`Error::InvalidStatus`] when the JSON status is not
    /// in `100..=599`.
    ///
    /// # Thread safety
    ///
    /// Calls are serialized through a mutex. A panic while the lock is held
    /// poisons it, and later calls return [`Error::Poisoned`] rather than
    /// touching a store of unknown state.
    pub fn call(&self, request: &Request) -> Result<Response, Error> {
        let request = encode_request(request)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        state
            .store
            .set_fuel(MAX_FUEL)
            .map_err(|source| Error::Trap {
                operation: "set fuel",
                source,
            })?;

        let req_len = i32::try_from(request.len()).map_err(|_| Error::RequestTooLarge {
            len: request.len(),
            limit: i32::MAX as usize,
        })?;

        // The module's allocator gives us a writable range in its own memory.
        // A negative result cannot be a valid 32-bit offset and is rejected
        // before it reaches a memory operation.
        let alloc = state.alloc;
        let req_ptr = alloc
            .call(&mut state.store, req_len)
            .map_err(|source| Error::Trap {
                operation: ALLOC_EXPORT,
                source,
            })?;
        if req_ptr < 0 {
            return Err(Error::Allocation { code: req_ptr });
        }
        let req_ptr = req_ptr as u32;

        let memory = state.memory;
        if let Err(source) = memory.write(&mut state.store, req_ptr as usize, &request) {
            // The allocation still belongs to the module. Try to release it,
            // but keep the write failure as the reported cause.
            state.release(req_ptr, req_len as u32).ok();
            return Err(Error::Memory {
                operation: "write request into wasm memory",
                source,
            });
        }

        let handle = state.handle;
        let packed = match handle.call(&mut state.store, (req_ptr as i32, req_len)) {
            Ok(packed) => packed,
            Err(source) => {
                state.release(req_ptr, req_len as u32).ok();
                return Err(Error::Trap {
                    operation: HANDLE_EXPORT,
                    source,
                });
            }
        };

        // The ABI packs an unsigned pointer and length into one i64. Casting
        // through u64 avoids sign-extension surprises when a module uses the
        // top bit of either half.
        let raw = packed as u64;
        let resp_ptr = (raw >> 32) as u32;
        let resp_len = (raw & u64::from(u32::MAX)) as u32;
        let resp_len_usize = resp_len as usize;

        // Check the announced length before allocating the host-side copy.
        // The request buffer is still released when possible; the response
        // buffer is not, because its length is not trustworthy.
        if resp_len_usize > MAX_RESPONSE_BYTES {
            state.release(req_ptr, req_len as u32).ok();
            return Err(Error::ResponseTooLarge {
                len: resp_len_usize,
                limit: MAX_RESPONSE_BYTES,
            });
        }

        let mut response_bytes = vec![0u8; resp_len_usize];
        if let Err(source) = memory.read(&state.store, resp_ptr as usize, &mut response_bytes) {
            state.release(req_ptr, req_len as u32).ok();
            return Err(Error::BadResponsePointer {
                ptr: resp_ptr,
                len: resp_len,
                source,
            });
        }

        // Free the response before the request. If the module reused the
        // request buffer as its response, there is only one allocation and it
        // is released once using the original request length.
        if resp_ptr == req_ptr {
            state.release(req_ptr, req_len as u32)?;
        } else {
            state.release(resp_ptr, resp_len)?;
            state.release(req_ptr, req_len as u32)?;
        }

        let text = std::str::from_utf8(&response_bytes).map_err(|source| Error::Utf8 {
            context: "module response",
            source,
        })?;
        let response: Response = serde_json::from_str(text).map_err(|source| Error::Json {
            context: "parse module response",
            source,
        })?;
        validate_status(response.status)?;
        Ok(response)
    }
}

impl fmt::Debug for WasmModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmModule")
            .field("path", &self.path)
            .field("bytes", &self.bytes)
            .field("has_free", &self.has_free())
            .finish()
    }
}

impl InstanceState {
    /// Calls the optional free function for a buffer.
    ///
    /// Without `elira_free` the module owns its allocations, so this is a
    /// no-op and the host does not invent a deallocator. A zero-length range
    /// is also a no-op: it cannot be a real allocation and calling a module's
    /// free function with `(0, 0)` risks turning a clean failure report into a
    /// cleanup trap.
    fn release(&mut self, ptr: u32, len: u32) -> Result<(), Error> {
        let Some(free) = self.free else {
            return Ok(());
        };
        if len == 0 {
            return Ok(());
        }
        free.call(&mut self.store, (ptr as i32, len as i32))
            .map_err(|source| Error::Free { source })
    }
}

fn encode_request(request: &Request) -> Result<Vec<u8>, Error> {
    let encoded = serde_json::to_vec(request).map_err(|source| Error::Json {
        context: "serialize request",
        source,
    })?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(Error::RequestTooLarge {
            len: encoded.len(),
            limit: MAX_REQUEST_BYTES,
        });
    }
    Ok(encoded)
}

fn validate_status(status: u16) -> Result<(), Error> {
    if (100..=599).contains(&status) {
        Ok(())
    } else {
        Err(Error::InvalidStatus { status })
    }
}

fn validate_exports(module: &Module) -> Result<(), Error> {
    match module.get_export(MEMORY_EXPORT) {
        Some(ExternType::Memory(_)) => {}
        Some(_) => {
            return Err(Error::InvalidExport {
                name: MEMORY_EXPORT,
                expected: "a linear memory",
            })
        }
        None => {
            return Err(Error::MissingExport {
                name: MEMORY_EXPORT,
            })
        }
    }

    expect_func(
        module,
        ALLOC_EXPORT,
        &[ValType::I32],
        &[ValType::I32],
        "a function (i32) -> i32",
    )?;
    expect_func(
        module,
        HANDLE_EXPORT,
        &[ValType::I32, ValType::I32],
        &[ValType::I64],
        "a function (i32, i32) -> i64",
    )?;

    // elira_free is optional, but if it is exported its signature is not
    // optional: a wrong signature would be a trap waiting to happen during
    // cleanup, after the response has already been accepted.
    match module.get_export(FREE_EXPORT) {
        None => {}
        Some(ExternType::Func(ty))
            if ty.params() == [ValType::I32, ValType::I32] && ty.results().is_empty() => {}
        Some(_) => {
            return Err(Error::InvalidExport {
                name: FREE_EXPORT,
                expected: "a function (i32, i32) -> ()",
            })
        }
    }

    Ok(())
}

fn expect_func(
    module: &Module,
    name: &'static str,
    params: &[ValType],
    results: &[ValType],
    expected: &'static str,
) -> Result<(), Error> {
    match module.get_export(name) {
        Some(ExternType::Func(ty)) if ty.params() == params && ty.results() == results => Ok(()),
        Some(_) => Err(Error::InvalidExport { name, expected }),
        None => Err(Error::MissingExport { name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WasmModule>();
    }

    #[test]
    fn status_range_is_checked() {
        assert!(validate_status(100).is_ok());
        assert!(validate_status(200).is_ok());
        assert!(validate_status(599).is_ok());
        assert!(matches!(
            validate_status(99),
            Err(Error::InvalidStatus { status: 99 })
        ));
        assert!(matches!(
            validate_status(600),
            Err(Error::InvalidStatus { status: 600 })
        ));
    }

    #[test]
    fn request_serialization_uses_the_shared_envelope() {
        let request = Request {
            method: "POST".to_string(),
            path: "/hello".to_string(),
            query: String::new(),
            host: "example.com".to_string(),
            headers: Vec::new(),
            body: b"hi".to_vec(),
            remote_addr: "192.0.2.1:1".to_string(),
        };
        let encoded = encode_request(&request).expect("request encodes");
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["body"], "aGk=");
    }

    #[test]
    fn oversized_request_is_rejected_before_the_call() {
        // The base64 envelope is larger than the raw body, so a body at the
        // raw limit already trips the encoded-size check.
        let request = Request {
            method: "POST".to_string(),
            path: "/hello".to_string(),
            query: String::new(),
            host: "example.com".to_string(),
            headers: Vec::new(),
            body: vec![0u8; MAX_REQUEST_BYTES],
            remote_addr: "192.0.2.1:1".to_string(),
        };
        match encode_request(&request).unwrap_err() {
            Error::RequestTooLarge { len, limit } => {
                assert!(len > MAX_REQUEST_BYTES);
                assert_eq!(limit, MAX_REQUEST_BYTES);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(matches!(
            WasmModule::load_bytes(&[]),
            Err(Error::EmptyModule)
        ));
    }

    #[test]
    fn oversized_bytes_are_rejected_before_compilation() {
        let bytes = vec![0u8; MAX_MODULE_BYTES + 1];
        assert!(matches!(
            WasmModule::load_bytes(&bytes),
            Err(Error::ModuleTooLarge { .. })
        ));
    }
}
