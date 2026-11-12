mod abi;
mod error;
mod process;

pub use abi::{FreeFn, HandleFn, Request, Response, VersionFn};
pub use error::Error;
pub use process::ProcessModule;

use std::ffi::c_char;
use std::fmt;
use std::path::{Path, PathBuf};
use std::slice;
use std::str;

use libloading::Library;

pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_VERSION_BYTES: usize = 256;

const HANDLE_SYMBOL: &str = "elira_handle";
const HANDLE_SYMBOL_BYTES: &[u8] = b"elira_handle\0";
const FREE_SYMBOL_BYTES: &[u8] = b"elira_free\0";
const VERSION_SYMBOL_BYTES: &[u8] = b"elira_version\0";

pub struct Module {
    _library: Library,
    path: PathBuf,
    handle: HandleFn,
    free: Option<FreeFn>,
    version: Option<VersionFn>,
}

impl Module {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let library = unsafe { Library::new(path) }.map_err(|source| Error::Open {
            path: path.display().to_string(),
            source,
        })?;

        let handle =
            unsafe { required_symbol::<HandleFn>(&library, HANDLE_SYMBOL, HANDLE_SYMBOL_BYTES) }?;

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

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn version(&self) -> Option<String> {
        let version = self.version?;

        let ptr = unsafe { version() };
        if ptr.is_null() {
            return None;
        }

        let bytes = unsafe { bounded_cstr(ptr, MAX_VERSION_BYTES) }?;
        str::from_utf8(bytes).ok().map(str::to_owned)
    }

    pub fn call(&self, request: &Request) -> Result<Response, Error> {
        let request = encode_request(request)?;

        let mut response_ptr: *mut u8 = std::ptr::null_mut();
        let mut response_len: usize = 0;

        let code = unsafe {
            (self.handle)(
                request.as_ptr(),
                request.len(),
                &mut response_ptr,
                &mut response_len,
            )
        };

        if code != 0 {
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
            return Err(Error::NoFree { len: response_len });
        }

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

    fn release(&self, ptr: *mut u8, len: usize) {
        if ptr.is_null() {
            return;
        }
        if let Some(free) = self.free {
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

unsafe fn required_symbol<T: Copy>(
    library: &Library,
    name: &'static str,
    encoded: &'static [u8],
) -> Result<T, Error> {
    let symbol = unsafe { library.get::<T>(encoded) }.map_err(|source| Error::Symbol {
        symbol: name,
        source,
    })?;
    Ok(*symbol)
}

unsafe fn optional_symbol<T: Copy>(
    library: &Library,
    encoded: &'static [u8],
) -> Result<Option<T>, Error> {
    match unsafe { library.get::<T>(encoded) } {
        Ok(symbol) => Ok(Some(*symbol)),
        Err(_) => Ok(None),
    }
}

unsafe fn bounded_cstr<'a>(ptr: *const c_char, limit: usize) -> Option<&'a [u8]> {
    let start = ptr.cast::<u8>();
    for len in 0..limit {
        if unsafe { *start.add(len) } == 0 {
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

        let bytes = unsafe { bounded_cstr(text.as_ptr(), MAX_VERSION_BYTES) }.unwrap();
        assert_eq!(str::from_utf8(bytes), Ok("echo 0.1.0"));
    }

    #[test]
    fn version_scan_rejects_a_missing_terminator() {
        let bytes = [b'a'; 8];

        assert!(unsafe { bounded_cstr(bytes.as_ptr().cast(), bytes.len()) }.is_none());
    }

    #[test]
    fn version_scan_accepts_a_terminator_at_the_limit() {
        let mut bytes = vec![b'a'; MAX_VERSION_BYTES];
        bytes[MAX_VERSION_BYTES - 1] = 0;

        let value = unsafe { bounded_cstr(bytes.as_ptr().cast(), MAX_VERSION_BYTES) }.unwrap();
        assert_eq!(value.len(), MAX_VERSION_BYTES - 1);
    }

    #[test]
    fn version_scan_rejects_a_terminator_past_the_limit() {
        let mut bytes = vec![b'a'; MAX_VERSION_BYTES + 1];
        bytes[MAX_VERSION_BYTES] = 0;

        assert!(unsafe { bounded_cstr(bytes.as_ptr().cast(), MAX_VERSION_BYTES) }.is_none());
    }

    #[test]
    fn version_scan_handles_invalid_utf8_without_panicking() {
        let text = [0xff_u8, 0];

        let bytes = unsafe { bounded_cstr(text.as_ptr().cast(), text.len()) }.unwrap();
        assert!(str::from_utf8(bytes).is_err());
    }
}
