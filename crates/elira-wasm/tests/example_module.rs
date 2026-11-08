//! Builds the example Wasm module and calls it through the real ABI.
//!
//! The test is ignored because it runs cargo for a second workspace and needs
//! the `wasm32-unknown-unknown` target installed. The WAT tests in
//! `wasm_modules.rs` cover the runtime without a cross toolchain.

use std::path::{Path, PathBuf};
use std::process::Command;

use elira_module::Request;
use elira_wasm::WasmModule;

fn example_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/modules/echo-wasm")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

#[test]
#[ignore = "builds examples/modules/echo-wasm and needs wasm32-unknown-unknown"]
fn example_wasm_module_compiles_and_runs() {
    let dir = example_dir();
    let manifest = dir.join("Cargo.toml");
    let status = Command::new(cargo())
        .args([
            "build",
            "--manifest-path",
            manifest.to_str().expect("utf-8 manifest path"),
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .status()
        .expect("start cargo");
    assert!(
        status.success(),
        "cargo build failed for {}",
        manifest.display()
    );

    let wasm = dir.join("target/wasm32-unknown-unknown/release/elira_echo_wasm.wasm");
    let module = WasmModule::load(&wasm).expect("example wasm module loads");

    let response = module
        .call(&Request {
            method: "POST".to_string(),
            path: "/echo".to_string(),
            query: String::new(),
            host: "example.com".to_string(),
            headers: Vec::new(),
            body: b"hello".to_vec(),
            remote_addr: "192.0.2.1:50000".to_string(),
        })
        .expect("example wasm module answers");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert!(response
        .headers
        .iter()
        .any(|(name, value)| name == "x-module" && value == "echo-wasm"));
}
