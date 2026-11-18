# Echo module

Minimal native module for Elira. It parses the request JSON, returns status
200, adds `x-module: echo`, and sets the response body to `"<method> <path>"`.

## Build

```sh
cargo build --manifest-path examples/modules/echo/Cargo.toml
```

The shared library lands at:

```
examples/modules/echo/target/debug/libelira_module_echo.so
```

Use `--release` for a release build. The `[workspace]` table in `Cargo.toml`
keeps this crate independent from the Elira workspace; it is not a member.

## Load

From Rust:

```rust
use std::path::Path;

use elira_module::{Module, Request};

let module = Module::load(Path::new(
    "examples/modules/echo/target/debug/libelira_module_echo.so",
))?;

let response = module.call(&Request {
    method: "GET".to_string(),
    path: "/hello".to_string(),
    query: "name=world".to_string(),
    host: "example.com".to_string(),
    headers: vec![("accept".to_string(), "text/plain".to_string())],
    body: Vec::new(),
    remote_addr: "192.0.2.1:50000".to_string(),
})?;

assert_eq!(response.status, 200);
assert_eq!(response.body, b"GET /hello");
# Ok::<(), elira_module::Error>(())
```

Run the ignored integration test that builds this module and calls it:

```sh
cargo test -p elira-module --test example_module -- --ignored
```

## ABI

```c
int elira_handle(const uint8_t *request_ptr, size_t request_len,
                 uint8_t **response_ptr, size_t *response_len);
void elira_free(uint8_t *ptr, size_t len);
const char *elira_version(void);
```

`elira_handle` is required. It returns `0` on success and writes a heap buffer
to `response_ptr`/`response_len`. The host copies the bytes and then calls
`elira_free` with exactly those values. A module that returns a non-null
pointer without exporting `elira_free` is rejected by the host after the
allocation, so always export both together.

`elira_version` is optional and returns a NUL-terminated string that stays
valid while the library is loaded.

The request and response are UTF-8 JSON. Bodies are standard base64 with
padding, not byte arrays:

```json
{
  "method": "POST",
  "path": "/hello",
  "query": "a=1",
  "host": "example.com",
  "headers": [["content-type", "text/plain"]],
  "body": "AA==",
  "remote_addr": "192.0.2.1:50000"
}
```

The response has the same `headers` and `body` shape plus `status`:

```json
{
  "status": 200,
  "headers": [["x-module", "echo"]],
  "body": "UE9TVCAvaGVsbG8="
}
```

## Safety

A module is loaded into the Elira process and runs with the server's full
privileges. It can read files, open sockets, inspect the environment and abort
the process. There is no sandbox and no isolation between modules. Load only
code you trust.

The host checks that `elira_handle` exists, rejects null response pointers,
caps request and response JSON at 16 MiB, copies the response before freeing
it, and parses the JSON before returning it. It cannot check the real signature
of a foreign function or the validity of a pointer. A module that unwinds
across the C boundary or returns a bad allocation is undefined behaviour. This
example catches Rust panics inside `elira_handle`; keep that guard in your own
module.

`Module` is `Send + Sync`. If the route layer calls it from several threads,
protect mutable module state with a mutex or atomics.
