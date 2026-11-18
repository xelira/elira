# Native module examples

Each directory is an independent Rust `cdylib` that implements the ABI from
`elira-module`. They are loaded by path at runtime and deliberately are not
members of the Elira workspace.

| Module | Purpose |
| --- | --- |
| [`echo`](echo/README.md) | Parses the request and returns `"<method> <path>"`. |

Build one example:

```sh
cargo build --manifest-path examples/modules/echo/Cargo.toml
```

The host loads the resulting `libelira_module_echo.so` with
`elira_module::Module::load`. Read the module README for the JSON shape, the
optional symbols and the security boundary: a module runs in-process with the
server's full privileges.
