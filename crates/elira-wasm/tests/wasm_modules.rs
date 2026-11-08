//! End-to-end tests with small WAT modules.
//!
//! Every module is compiled from text by the `wat` dev-dependency, so the
//! tests do not need a wasm32 toolchain or a prebuilt `.wasm` file. One test
//! writes a compiled module to a temporary `.wasm` path to cover the file
//! loader.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use elira_module::Request;
use elira_wasm::{Error, WasmModule, MAX_MODULE_BYTES, MAX_RESPONSE_BYTES};

/// Returns a fixed valid response. `elira_alloc` hands back a writable area so
/// the host can write the request even though this module ignores it.
const FIXED_RESPONSE: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"status\":200,\"headers\":[],\"body\":\"\"}")
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 2048))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0x40000000025))
)
"#;

/// Echoes the request's base64-encoded `body` field. The response body is the
/// same base64 text, so the decoded response body equals the decoded request
/// body. The module copies the bytes through linear memory, which also proves
/// the host wrote the request where `elira_alloc` asked it to.
const ECHO_BODY: &str = r#"
(module
  (memory (export "memory") 8)
  (global $heap (mut i32) (i32.const 131072))
  (data (i32.const 8192) "{\"status\":200,\"headers\":[],\"body\":\"")
  (func (export "elira_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap
      (i32.and
        (i32.add (i32.add (global.get $heap) (local.get $len)) (i32.const 7))
        (i32.const -8)))
    (local.get $ptr))
  (func (export "elira_handle") (param $req i32) (param $len i32) (result i64)
    (local $i i32)
    (local $j i32)
    (local $start i32)
    (local $out i32)
    (local.set $i (i32.const 0))
    (local.set $start (i32.const -1))
    (block $scan_done
      (loop $scan
        (br_if $scan_done
          (i32.gt_u (i32.add (local.get $i) (i32.const 8)) (local.get $len)))
        (if (i64.eq
              (i64.load (i32.add (local.get $req) (local.get $i)))
              (i64.const 0x223a2279646f6222))
          (then
            (local.set $start (i32.add (local.get $i) (i32.const 8)))
            (br $scan_done)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (if (i32.eq (local.get $start) (i32.const -1))
      (then (return (i64.const 0))))
    (local.set $j (local.get $start))
    (block $end_done
      (loop $find_end
        (br_if $end_done (i32.ge_u (local.get $j) (local.get $len)))
        (if (i32.eq
              (i32.load8_u (i32.add (local.get $req) (local.get $j)))
              (i32.const 34))
          (then (br $end_done)))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $find_end)))
    (memory.copy
      (i32.add (i32.const 8192) (i32.const 35))
      (i32.add (local.get $req) (local.get $start))
      (i32.sub (local.get $j) (local.get $start)))
    (local.set $out
      (i32.add
        (i32.add (i32.const 8192) (i32.const 35))
        (i32.sub (local.get $j) (local.get $start))))
    (i32.store8 (local.get $out) (i32.const 34))
    (i32.store8 (i32.add (local.get $out) (i32.const 1)) (i32.const 125))
    (i64.or
      (i64.shl (i64.const 8192) (i64.const 32))
      (i64.extend_i32_u
        (i32.add (i32.sub (local.get $out) (i32.const 8192)) (i32.const 2)))))
)
"#;

const TRAP: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 1024))
  (func (export "elira_handle") (param i32 i32) (result i64)
    unreachable)
)
"#;

const BAD_POINTER: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 1024))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0xffff00000000000a))
)
"#;

const OVERSIZED_RESPONSE: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 1024))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0x40001000001))
)
"#;

const MISSING_ALLOC: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0))
)
"#;

const MISSING_MEMORY: &str = r#"
(module
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 1024))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0))
)
"#;

const UNSUPPORTED_IMPORT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 1024))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0))
)
"#;

const INVALID_STATUS: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"status\":600,\"headers\":[],\"body\":\"\"}")
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 2048))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0x40000000025))
)
"#;

const BAD_JSON: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"status\":200")
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 2048))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0x4000000000c))
)
"#;

const ALLOC_FAILS: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const -1))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0))
)
"#;

/// Exports `elira_free`; the first call returns 200, later calls 201. The
/// switch proves the host actually called the free function between calls.
const FREE_IS_CALLED: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"status\":200,\"headers\":[],\"body\":\"\"}")
  (data (i32.const 2048) "{\"status\":201,\"headers\":[],\"body\":\"\"}")
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 4096))
  (func (export "elira_free") (param i32 i32)
    (i32.store8 (i32.const 3000) (i32.const 1)))
  (func (export "elira_handle") (param i32 i32) (result i64)
    (if (result i64)
      (i32.eq (i32.load8_u (i32.const 3000)) (i32.const 1))
      (then (i64.const 0x80000000025))
      (else (i64.const 0x40000000025))))
)
"#;

const FREE_TRAPS: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"status\":200,\"headers\":[],\"body\":\"\"}")
  (func (export "elira_alloc") (param i32) (result i32)
    (i32.const 2048))
  (func (export "elira_free") (param i32 i32)
    unreachable)
  (func (export "elira_handle") (param i32 i32) (result i64)
    (i64.const 0x40000000025))
)
"#;

fn module(source: &str) -> WasmModule {
    let bytes = wat::parse_str(source).expect("WAT parses");
    WasmModule::load_bytes(&bytes).expect("module loads")
}

fn request(body: Vec<u8>) -> Request {
    Request {
        method: "POST".to_string(),
        path: "/hello".to_string(),
        query: "a=1".to_string(),
        host: "example.com".to_string(),
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body,
        remote_addr: "192.0.2.1:50000".to_string(),
    }
}

fn temp_path(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "elira-wasm-{}-{serial}-{name}.wasm",
        std::process::id()
    ))
}

#[test]
fn fixed_response_is_parsed() {
    let module = module(FIXED_RESPONSE);
    let response = module.call(&request(Vec::new())).expect("call succeeds");
    assert_eq!(response.status, 200);
    assert!(response.headers.is_empty());
    assert!(response.body.is_empty());
    assert!(!module.has_free());
    assert!(module.path().is_none());
}

#[test]
fn request_body_is_echoed_through_linear_memory() {
    let module = module(ECHO_BODY);

    let first = module
        .call(&request(b"hello".to_vec()))
        .expect("first echo succeeds");
    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"hello");

    let second = module
        .call(&request(vec![0x00, 0xff, b'o', b'k']))
        .expect("second echo succeeds");
    assert_eq!(second.status, 200);
    assert_eq!(second.body, [0x00, 0xff, b'o', b'k']);
}

#[test]
fn module_is_usable_from_several_threads() {
    let module = Arc::new(module(FIXED_RESPONSE));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let module = Arc::clone(&module);
        handles.push(std::thread::spawn(move || {
            for _ in 0..10 {
                let response = module.call(&request(Vec::new())).expect("call succeeds");
                assert_eq!(response.status, 200);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker does not panic");
    }
}

#[test]
fn trap_becomes_an_error() {
    let module = module(TRAP);
    let err = module.call(&request(Vec::new())).unwrap_err();
    match err {
        Error::Trap { operation, .. } => assert_eq!(operation, "elira_handle"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn out_of_bounds_response_pointer_is_rejected() {
    let module = module(BAD_POINTER);
    let err = module.call(&request(Vec::new())).unwrap_err();
    match err {
        Error::BadResponsePointer { ptr, len, .. } => {
            assert_eq!(ptr, 0xffff_0000);
            assert_eq!(len, 10);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn oversized_response_is_rejected_before_reading_it() {
    let module = module(OVERSIZED_RESPONSE);
    let err = module.call(&request(Vec::new())).unwrap_err();
    match err {
        Error::ResponseTooLarge { len, limit } => {
            assert_eq!(len, MAX_RESPONSE_BYTES + 1);
            assert_eq!(limit, MAX_RESPONSE_BYTES);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn missing_alloc_is_a_load_error() {
    let bytes = wat::parse_str(MISSING_ALLOC).unwrap();
    let err = WasmModule::load_bytes(&bytes).unwrap_err();
    assert!(matches!(
        err,
        Error::MissingExport {
            name: "elira_alloc"
        }
    ));
}

#[test]
fn missing_memory_is_a_load_error() {
    let bytes = wat::parse_str(MISSING_MEMORY).unwrap();
    let err = WasmModule::load_bytes(&bytes).unwrap_err();
    assert!(matches!(err, Error::MissingExport { name: "memory" }));
}

#[test]
fn imports_are_rejected() {
    let bytes = wat::parse_str(UNSUPPORTED_IMPORT).unwrap();
    let err = WasmModule::load_bytes(&bytes).unwrap_err();
    match err {
        Error::UnsupportedImport { module, name } => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn invalid_status_is_rejected() {
    let module = module(INVALID_STATUS);
    assert!(matches!(
        module.call(&request(Vec::new())),
        Err(Error::InvalidStatus { status: 600 })
    ));
}

#[test]
fn invalid_json_is_rejected() {
    let module = module(BAD_JSON);
    assert!(matches!(
        module.call(&request(Vec::new())),
        Err(Error::Json { .. })
    ));
}

#[test]
fn failed_allocation_is_an_error() {
    let module = module(ALLOC_FAILS);
    assert!(matches!(
        module.call(&request(Vec::new())),
        Err(Error::Allocation { code: -1 })
    ));
}

#[test]
fn free_is_called_between_calls() {
    let module = module(FREE_IS_CALLED);
    assert!(module.has_free());

    let first = module.call(&request(Vec::new())).expect("first call");
    assert_eq!(first.status, 200);

    let second = module.call(&request(Vec::new())).expect("second call");
    assert_eq!(second.status, 201);
}

#[test]
fn a_trapping_free_is_an_error_not_a_panic() {
    let module = module(FREE_TRAPS);
    assert!(matches!(
        module.call(&request(Vec::new())),
        Err(Error::Free { .. })
    ));
}

#[test]
fn load_reads_a_real_wasm_file() {
    let bytes = wat::parse_str(FIXED_RESPONSE).unwrap();
    let path = temp_path("fixed");
    std::fs::write(&path, &bytes).unwrap();

    let module = WasmModule::load(&path).expect("file module loads");
    assert_eq!(module.path(), Some(path.as_path()));
    assert_eq!(module.wasm_len(), bytes.len());

    let response = module.call(&request(Vec::new())).expect("call succeeds");
    assert_eq!(response.status, 200);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_rejects_an_empty_file() {
    let path = temp_path("empty");
    std::fs::write(&path, []).unwrap();

    let err = WasmModule::load(&path).unwrap_err();
    let _ = std::fs::remove_file(&path);
    assert!(matches!(err, Error::EmptyModule), "error was {err}");
}

#[test]
fn load_rejects_an_oversized_file() {
    let path = temp_path("oversized");
    std::fs::write(&path, vec![0u8; MAX_MODULE_BYTES + 1]).unwrap();

    let err = WasmModule::load(&path).unwrap_err();
    let _ = std::fs::remove_file(&path);
    match err {
        Error::ModuleTooLarge { len, limit } => {
            assert_eq!(len, MAX_MODULE_BYTES + 1);
            assert_eq!(limit, MAX_MODULE_BYTES);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn load_reports_a_missing_file() {
    let path = temp_path("missing");
    let err = WasmModule::load(&path).unwrap_err();
    assert!(matches!(err, Error::Read { .. }), "error was {err}");
}

#[test]
fn malformed_wasm_is_a_compile_error() {
    let err = WasmModule::load_bytes(b"not a wasm module").unwrap_err();
    assert!(matches!(err, Error::Compile { .. }), "error was {err}");
}

#[test]
fn an_infinite_loop_runs_out_of_fuel() {
    let wasm = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "elira_alloc") (param i32) (result i32) i32.const 0)
          (func (export "elira_handle") (param i32 i32) (result i64)
            (loop $forever br $forever)
            i64.const 0))
        "#,
    )
    .expect("wat");
    let module = elira_wasm::WasmModule::load_bytes(&wasm).expect("load");
    let error = module
        .call(&elira_module::Request::default())
        .expect_err("infinite loop must trap");
    let text = format!("{error}");
    assert!(text.contains("fuel") || text.contains("trap"), "{text}");
}
