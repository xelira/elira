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

pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;

pub const MAX_TABLE_ELEMENTS: usize = 1_000_000;

pub const MAX_FUEL: u64 = 5_000_000;

const MEMORY_EXPORT: &str = "memory";
const ALLOC_EXPORT: &str = "elira_alloc";
const HANDLE_EXPORT: &str = "elira_handle";
const FREE_EXPORT: &str = "elira_free";

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

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn wasm_len(&self) -> usize {
        self.bytes
    }

    pub fn has_free(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.free.is_some())
            .unwrap_or(false)
    }

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

        let raw = packed as u64;
        let resp_ptr = (raw >> 32) as u32;
        let resp_len = (raw & u64::from(u32::MAX)) as u32;
        let resp_len_usize = resp_len as usize;

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
