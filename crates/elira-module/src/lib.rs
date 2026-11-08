//! Native dynamic modules for Elira.
//!
//! A module is a shared library that implements a small C ABI and answers one
//! HTTP-shaped request at a time. The host serializes a [`Request`] to JSON,
//! asks the module for a JSON [`Response`], and turns that into whatever the
//! caller needs. The module never sees Elira's internal types, so it does not
//! have to be rebuilt when the proxy changes.
//!
//! # ABI
//!
//! ```c
//! // Host -> module: UTF-8 JSON request, module -> host: UTF-8 JSON response.
//! // Return 0 on success, non-zero on failure.
//! int elira_handle(const uint8_t *request_ptr, size_t request_len,
//!                  uint8_t **response_ptr, size_t *response_len);
//!
//! // Optional. Called to free a buffer returned by elira_handle.
//! void elira_free(uint8_t *ptr, size_t len);
//!
//! // Optional. Returns a pointer to a NUL-terminated version string.
//! const char *elira_version(void);
//! ```
//!
//! `elira_handle` is the only required symbol. If a module returns a non-null
//! response pointer it must also export `elira_free`; without it the host can
//! copy the bytes but has no safe way to release the allocation, so
//! [`Module::call`] returns [`Error::NoFree`] and the buffer stays leaked. A
//! module that never returns a buffer can omit `elira_free`.
//!
//! The JSON envelope is documented in [`Request`] and [`Response`]. Request
//! and response bodies use standard base64 with padding; the limit applies to
//! the encoded JSON, not the decoded body.
//!
//! # Trust and safety
//!
//! Loading is an operator decision. A module runs in this process with the
//! server's full privileges: it can read files, open sockets, inspect the
//! environment and abort the process. There is no sandbox. Load only libraries
//! you control or trust.
//!
//! The host validates that the required symbol resolved, bounds the request
//! and response sizes, rejects a null response pointer and copies the response
//! before calling `elira_free`. It cannot validate that a foreign function has
//! the declared signature or that it returns a valid allocation. A module that
//! unwinds across the C ABI, writes through a bad pointer or reports a bogus
//! length is undefined behaviour; the host does not wrap the call in
//! `catch_unwind` because a foreign panic cannot be caught safely. Rust modules
//! must catch their own panics inside `elira_handle`.
//!
//! [`Module`] is `Send + Sync`, so one loaded library may be shared between
//! threads. Calls enter the module concurrently; a module with mutable state
//! has to synchronize it itself.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! use elira_module::{Module, Request};
//!
//! let module = Module::load(Path::new(
//!     "examples/modules/echo/target/debug/libelira_module_echo.so",
//! ))?;
//! let response = module.call(&Request {
//!     method: "GET".to_string(),
//!     path: "/hello".to_string(),
//!     query: String::new(),
//!     host: "example.com".to_string(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//!     remote_addr: "192.0.2.1:50000".to_string(),
//! })?;
//! assert_eq!(response.status, 200);
//! # Ok::<(), elira_module::Error>(())
//! ```

mod abi;
mod error;

pub use abi::{FreeFn, HandleFn, Request, Response, VersionFn};
pub use error::Error;

use std::ffi::c_char;
use std::fmt;
use std::path::{Path, PathBuf};
use std::slice;
use std::str;

use libloading::Library;

/// Largest JSON request the host will hand to a module. The check runs after
/// base64 encoding, so a binary body is larger than this in memory before the
/// limit is reached.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Largest response the host will accept. A larger answer is freed when
/// possible and rejected before parsing, which keeps a broken module from
/// exhausting the server's memory.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Longest version string accepted from `elira_version`, including space for
/// the terminator. The host scans for the NUL byte itself instead of trusting
/// `CStr::from_ptr`, which would read without a bound.
pub const MAX_VERSION_BYTES: usize = 256;

const HANDLE_SYMBOL: &str = "elira_handle";
const HANDLE_SYMBOL_BYTES: &[u8] = b"elira_handle\0";
const FREE_SYMBOL_BYTES: &[u8] = b"elira_free\0";
const VERSION_SYMBOL_BYTES: &[u8] = b"elira_version\0";

/// A loaded shared library with its ABI entry points.
///
/// The library stays open for the lifetime of this value: dropping `Module`
/// closes it, so no symbol pointer may be used afterwards. The callable
/// pointers are copied out during loading and only used while `Module` is
/// alive.
pub struct Module {
    /// Kept only to keep the object mapped. Dropping this field would leave
    /// `handle`, `free` and `version` dangling.
    _library: Library,
    path: PathBuf,
    handle: HandleFn,
    free: Option<FreeFn>,
    version: Option<VersionFn>,
}

impl Module {
    /// Opens a shared library and resolves its entry points.
    ///
    /// Only `elira_handle` is required. Missing `elira_free` and
    /// `elira_version` are not load errors: the first is checked when a
    /// response buffer is actually returned, and the second makes
    /// [`version`](Self::version) return `None`.
    ///
    /// # Safety
    ///
    /// This is a safe function because the path comes from operator
    /// configuration, but opening a library runs its platform initializers in
    /// this process. Treat the path with the same care as the server binary.
    /// The symbol types cannot be checked; a module must implement the ABI
    /// exactly or the first call may be undefined behaviour.
    pub fn load(path: &Path) -> Result<Self, Error> {
        // SAFETY: loading a library is inherently unsafe because it runs
        // arbitrary initializers; the caller is the operator who chose this
        // path and the docs above spell out the trust boundary.
        let library = unsafe { Library::new(path) }.map_err(|source| Error::Open {
            path: path.display().to_string(),
            source,
        })?;

        // SAFETY: the symbol type is the ABI declared in this crate. A module
        // that exports a different function under this name is a contract
        // violation the host cannot detect.
        let handle =
            unsafe { required_symbol::<HandleFn>(&library, HANDLE_SYMBOL, HANDLE_SYMBOL_BYTES) }?;
        // SAFETY: same contract as above; both are optional and only called
        // when present.
        let free = unsafe { optional_symbol::<FreeFn>(&library, FREE_SYMBOL_BYTES) }?;
        let version = unsafe { optional_symbol::<VersionFn>(&library, VERSION_SYMBOL_BYTES) }?;

        Ok(Self {
            _library: library,
            path: path.to_path_buf(),
            handle,
            free,
            version,
        })
    }

    /// Returns the path this module was loaded from, for diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the optional `elira_version` string.
    ///
    /// Returns `None` when the module does not export the function, returns a
    /// null pointer, omits the NUL terminator within
    /// [`MAX_VERSION_BYTES`], or returns invalid UTF-8. A broken version string
    /// must not make the module unusable.
    pub fn version(&self) -> Option<String> {
        let version = self.version?;
        // SAFETY: the optional-symbol contract says this is a function with
        // the `VersionFn` signature. It may still return a bad pointer, which
        // is why the result is checked and the scan is bounded.
        let ptr = unsafe { version() };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: the ABI requires a NUL-terminated string. `bounded_cstr`
        // stops at `MAX_VERSION_BYTES` so a missing terminator cannot turn
        // into an unbounded read.
        let bytes = unsafe { bounded_cstr(ptr, MAX_VERSION_BYTES) }?;
        str::from_utf8(bytes).ok().map(str::to_owned)
    }

    /// Serializes `request`, calls the module and parses its response.
    ///
    /// The request is rejected before the call if its JSON exceeds
    /// [`MAX_REQUEST_BYTES`]. The response is copied and released before the
    /// JSON is parsed, so the module may reuse or unmap its buffer as soon as
    /// `elira_handle` returns.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Call`] when the module returns a non-zero code,
    /// [`Error::NoFree`] when it returns a buffer without exporting
    /// `elira_free`, and [`Error::InvalidStatus`] when the parsed status is
    /// outside `100..=599`.
    ///
    /// # Thread safety
    ///
    /// This method takes `&self` and may run on several threads at once. The
    /// module must protect its own mutable state; the host adds no lock.
    pub fn call(&self, request: &Request) -> Result<Response, Error> {
        let request = encode_request(request)?;

        let mut response_ptr: *mut u8 = std::ptr::null_mut();
        let mut response_len: usize = 0;

        // SAFETY: `self.handle` was resolved from a live library and is a
        // non-null function pointer with the declared signature. The request
        // slice stays alive for the whole call, and both out-pointers are
        // valid and exclusively borrowed for its duration. The module is
        // trusted to follow the ABI; the host checks everything it can after
        // the call.
        let code = unsafe {
            (self.handle)(
                request.as_ptr(),
                request.len(),
                &mut response_ptr,
                &mut response_len,
            )
        };

        if code != 0 {
            // The response is undefined after a failure, but a module that
            // allocated one should still not leak it. Release whatever pointer
            // it left behind when the module provides a free function.
            self.release(response_ptr, response_len);
            return Err(Error::Call { code });
        }

        if response_ptr.is_null() {
            return Err(Error::NullResponse { len: response_len });
        }

        if response_len > MAX_RESPONSE_BYTES {
            self.release(response_ptr, response_len);
            return Err(Error::ResponseTooLarge {
                len: response_len,
                limit: MAX_RESPONSE_BYTES,
            });
        }

        if self.free.is_none() {
            // Copying here would not help: without `elira_free` the module's
            // allocation can never be released. Fail loudly and document the
            // leak instead of pretending the call succeeded.
            return Err(Error::NoFree { len: response_len });
        }

        // SAFETY: the module contract says a non-null pointer with a successful
        // return points to `response_len` readable bytes. The slice is copied
        // immediately; it is not held past the free call below.
        let bytes = unsafe { slice::from_raw_parts(response_ptr, response_len) }.to_vec();
        self.release(response_ptr, response_len);

        let text = str::from_utf8(&bytes).map_err(|source| Error::Utf8 {
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

    /// Frees a module-owned buffer when the module exports `elira_free`.
    ///
    /// A missing free function leaves the buffer allocated; callers that get
    /// here either return [`Error::NoFree`] or have already decided to drop a
    /// failed or oversized response. The leak is the module's contract
    /// violation, but it must not turn into a use-after-free in the host.
    fn release(&self, ptr: *mut u8, len: usize) {
        if ptr.is_null() {
            return;
        }
        if let Some(free) = self.free {
            // SAFETY: the pointer and length came from this module's
            // `elira_handle`; `elira_free` is the module's own deallocator and
            // the ABI requires it to accept exactly these arguments.
            unsafe { free(ptr, len) };
        }
    }
}

impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("path", &self.path)
            .field("free", &self.free.is_some())
            .field("version", &self.version.is_some())
            .finish()
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

/// Copies a function pointer out of a loaded symbol.
///
/// `Symbol` borrows the library; the pointer itself is valid for as long as
/// the library remains mapped, which `Module` guarantees. The generic bound is
/// `Copy` because the pointer is moved out of the symbol value.
///
/// `libloading` reports a null `dlsym` result as an error, so a successful
/// lookup never yields a callable null pointer. That is why the call sites do
/// not add a second check (the compiler treats a function pointer as
/// non-nullable).
///
/// # Safety
///
/// The caller must guarantee that the symbol exists and that its real type
/// matches `T`. The loader cannot check either property.
unsafe fn required_symbol<T: Copy>(
    library: &Library,
    name: &'static str,
    encoded: &'static [u8],
) -> Result<T, Error> {
    // SAFETY: forwarded from the caller.
    let symbol = unsafe { library.get::<T>(encoded) }.map_err(|source| Error::Symbol {
        symbol: name,
        source,
    })?;
    Ok(*symbol)
}

/// Resolves an optional symbol. A missing symbol is not an error because the
/// functions are optional in the ABI.
///
/// # Safety
///
/// Same type contract as [`required_symbol`]. Other loader failures are also
/// reported as absence: only `elira_handle` is essential, and treating an
/// optional symbol as missing keeps a module with a damaged optional entry
/// point usable.
unsafe fn optional_symbol<T: Copy>(
    library: &Library,
    encoded: &'static [u8],
) -> Result<Option<T>, Error> {
    // SAFETY: forwarded from the caller.
    match unsafe { library.get::<T>(encoded) } {
        Ok(symbol) => Ok(Some(*symbol)),
        Err(_) => Ok(None),
    }
}

/// Reads a NUL-terminated byte string without scanning past `limit`.
///
/// # Safety
///
/// `ptr` must point to at least `limit` readable bytes, or to a NUL byte
/// before that point. The returned slice borrows memory owned by the module;
/// the caller must not use it after the library is unloaded.
unsafe fn bounded_cstr<'a>(ptr: *const c_char, limit: usize) -> Option<&'a [u8]> {
    let start = ptr.cast::<u8>();
    for len in 0..limit {
        // SAFETY: the caller guarantees `limit` readable bytes or an earlier
        // terminator, and `len` stays below `limit`.
        if unsafe { *start.add(len) } == 0 {
            // SAFETY: the preceding loop established that `len` bytes are
            // readable and `len` fits in the slice length.
            return Some(unsafe { slice::from_raw_parts(start, len) });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;

    use super::*;

    fn request(body: Vec<u8>) -> Request {
        Request {
            method: "POST".to_string(),
            path: "/hello".to_string(),
            query: String::new(),
            host: "example.com".to_string(),
            headers: Vec::new(),
            body,
            remote_addr: "192.0.2.1:50000".to_string(),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("elira-module-{}-{name}", std::process::id()))
    }

    #[test]
    fn module_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Module>();
    }

    #[test]
    fn missing_file_reports_the_path() {
        let path = temp_path("does-not-exist.so");
        let err = Module::load(&path).unwrap_err();
        match err {
            Error::Open { path: reported, .. } => {
                assert_eq!(reported, path.display().to_string());
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_text_file_is_not_a_library() {
        let path = temp_path("not-a-library.so");
        fs::write(&path, b"this is not an object file").unwrap();
        let err = Module::load(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(matches!(err, Error::Open { .. }), "error was {err}");
    }

    #[test]
    fn empty_request_encodes_as_json() {
        let encoded = encode_request(&request(Vec::new())).expect("request encodes");
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["body"], "");
    }

    #[test]
    fn oversized_request_is_rejected_before_the_call() {
        // The base64 envelope is larger than the raw body, so a body at the
        // raw limit is already enough to trip the encoded-size check.
        let request = request(vec![0u8; MAX_REQUEST_BYTES]);
        let err = encode_request(&request).unwrap_err();
        match err {
            Error::RequestTooLarge { len, limit } => {
                assert!(len > MAX_REQUEST_BYTES);
                assert_eq!(limit, MAX_REQUEST_BYTES);
            }
            other => panic!("unexpected error: {other}"),
        }
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
    fn version_scan_reads_a_terminated_string() {
        let text = CString::new("echo 0.1.0").unwrap();
        // SAFETY: `text` owns a NUL-terminated buffer that outlives the slice.
        let bytes = unsafe { bounded_cstr(text.as_ptr(), MAX_VERSION_BYTES) }.unwrap();
        assert_eq!(str::from_utf8(bytes), Ok("echo 0.1.0"));
    }

    #[test]
    fn version_scan_rejects_a_missing_terminator() {
        let bytes = [b'a'; 8];
        // SAFETY: the array is readable for its full length.
        assert!(unsafe { bounded_cstr(bytes.as_ptr().cast(), bytes.len()) }.is_none());
    }

    #[test]
    fn version_scan_accepts_a_terminator_at_the_limit() {
        let mut bytes = vec![b'a'; MAX_VERSION_BYTES];
        bytes[MAX_VERSION_BYTES - 1] = 0;
        // SAFETY: the vector is readable for its full length.
        let value = unsafe { bounded_cstr(bytes.as_ptr().cast(), MAX_VERSION_BYTES) }.unwrap();
        assert_eq!(value.len(), MAX_VERSION_BYTES - 1);
    }

    #[test]
    fn version_scan_rejects_a_terminator_past_the_limit() {
        let mut bytes = vec![b'a'; MAX_VERSION_BYTES + 1];
        bytes[MAX_VERSION_BYTES] = 0;
        // SAFETY: the vector is readable for its full length.
        assert!(unsafe { bounded_cstr(bytes.as_ptr().cast(), MAX_VERSION_BYTES) }.is_none());
    }

    #[test]
    fn version_scan_handles_invalid_utf8_without_panicking() {
        let text = [0xff_u8, 0];
        // SAFETY: the array is readable and contains a terminator.
        let bytes = unsafe { bounded_cstr(text.as_ptr().cast(), text.len()) }.unwrap();
        assert!(str::from_utf8(bytes).is_err());
    }
}
