# elira-wasm

Sandboxed WebAssembly modules for Elira. This crate is the Wasm counterpart of
`elira-module`: both consume an `elira_module::Request` and produce an
`elira_module::Response`, but a Wasm module runs inside the `wasmi` interpreter
with no host imports instead of being loaded as a native `.so`.

```rust
use elira_module::Request;
use elira_wasm::WasmModule;

let module = WasmModule::load(std::path::Path::new("echo.wasm"))?;
let response = module.call(&Request {
    method: "POST".to_string(),
    path: "/hello".to_string(),
    query: String::new(),
    host: "example.com".to_string(),
    headers: Vec::new(),
    body: b"hello".to_vec(),
    remote_addr: "192.0.2.1:50000".to_string(),
})?;
assert_eq!(response.status, 200);
assert_eq!(response.body, b"hello");
# Ok::<(), elira_wasm::Error>(())
```

## API

- `WasmModule::load_bytes(&[u8])` compiles and instantiates module bytes.
- `WasmModule::load(&Path)` reads a `.wasm` file, rejecting empty files and
  files larger than 16 MiB before loading them.
- `WasmModule::call(&Request)` serializes the shared JSON envelope, invokes
  `elira_handle`, validates the response and returns an `elira_module::Response`.
- `WasmModule::path()`, `wasm_len()` and `has_free()` are diagnostics.
- `WasmModule` is `Send + Sync`; calls are serialized through a mutex.

## ABI

A module must export:

```text
memory
elira_alloc(len: i32) -> i32
elira_handle(req_ptr: i32, req_len: i32) -> i64
```

`elira_handle` returns `(ptr << 32) | len` for a UTF-8 JSON response. Both
halves are 32-bit unsigned values. On failure a module should return `0`; the
host then reports an invalid or empty JSON response.

The optional `elira_free(ptr: i32, len: i32)` releases the request and response
buffers when present. Without it the host never frees module memory: the module
owns its buffers and may reuse them across calls. The host does not call a null
or absent free function.

If the response pointer equals the request pointer, the host frees the single
allocation once using the request length. A response may not overlap the
request at a different base address.

## Security notes

- All imports are rejected. There is no WASI, filesystem, network, clock or
  host-function capability.
- Module files, requests, responses and linear memory are bounded at 16 MiB,
  16 MiB, 16 MiB and 256 MiB respectively.
- Response lengths are checked before the host allocates a copy.
- Memory reads and writes go through wasmi's checked memory API, so an
  out-of-bounds pointer becomes an error instead of a host fault.
- Traps, out-of-bounds pointers, malformed JSON, invalid status codes and
  oversized responses are errors; none of them panic the host.
- A module can still consume CPU until it returns. There is no wall-clock
  timeout or fuel budget here, so run untrusted modules with an outer request
  timeout or stronger isolation when CPU exhaustion matters.
- One instance is protected by a mutex; use multiple instances for parallel
  execution.

## Tests

From the Elira workspace:

```sh
cargo test -p elira-wasm
cargo clippy -p elira-wasm --all-targets -- -D warnings
cargo build -p elira-wasm
```

The tests use the `wat` dev-dependency to compile small modules from text, so
they do not require a wasm32 toolchain. They cover a fixed response, a body
echo through linear memory, traps, bad pointers, oversized responses, missing
exports, rejected imports, `elira_free`, the file loader and concurrent calls.

The example module in `examples/modules/echo-wasm` is built for
`wasm32-unknown-unknown` and is exercised by an ignored integration test:

```sh
cargo test -p elira-wasm --test example_module -- --ignored
```
