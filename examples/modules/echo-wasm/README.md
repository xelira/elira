# Echo Wasm module

Minimal sandboxed WebAssembly module for Elira. It parses the shared request
envelope, returns status 200, adds `x-module: echo-wasm`, and echoes the
request body. Bodies are base64 strings in the JSON envelope, so passing the
encoded body through unchanged decodes to the original request body.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/modules/echo-wasm/Cargo.toml \
    --target wasm32-unknown-unknown --release
```

The module lands at:

```text
examples/modules/echo-wasm/target/wasm32-unknown-unknown/release/elira_echo_wasm.wasm
```

The `[workspace]` table in `Cargo.toml` keeps this crate independent from the
Elira workspace; it is not a member.

## Load

```rust
use std::path::Path;

use elira_module::Request;
use elira_wasm::WasmModule;

let module = WasmModule::load(Path::new(
    "examples/modules/echo-wasm/target/wasm32-unknown-unknown/release/elira_echo_wasm.wasm",
))?;

let response = module.call(&Request {
    method: "POST".to_string(),
    path: "/echo".to_string(),
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

Run the ignored integration test that builds this module and calls it:

```sh
cargo test -p elira-wasm --test example_module -- --ignored
```

The test needs the `wasm32-unknown-unknown` target installed.

## ABI

```text
memory
elira_alloc(len: i32) -> i32
elira_handle(req_ptr: i32, req_len: i32) -> i64
elira_free(ptr: i32, len: i32)
```

`elira_alloc` returns an offset in linear memory at which the host writes the
JSON request. `elira_handle` returns `(ptr << 32) | len` for the JSON response.
This example allocates the response with a boxed slice and leaks it; the host
copies the bytes and calls `elira_free` with exactly the same pointer and
length. A zero return value means failure.

The request and response use the JSON envelope from `elira-module`. Bodies are
standard base64 with padding:

```json
{
  "method": "POST",
  "path": "/echo",
  "query": "",
  "host": "example.com",
  "headers": [],
  "body": "aGVsbG8=",
  "remote_addr": "192.0.2.1:50000"
}
```

The response has the same `headers` and `body` shape plus `status`.

## Safety

The host rejects every import, so this module cannot read files, open sockets,
inspect the environment or call host functions. It has only its own linear
memory. Memory accesses from the host are bounds-checked by wasmi, and module
traps become host errors.

The module still owns up to its memory limit and may consume CPU until
`elira_handle` returns. Do not run untrusted modules without an outer timeout or
stronger isolation when CPU exhaustion matters.

`elira_handle` copies the request body string into a newly allocated response.
It does not retain a pointer after returning. `elira_free` reconstructs the
boxed slice with the exact length supplied by the host.
