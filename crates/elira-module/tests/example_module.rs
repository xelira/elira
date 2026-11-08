//! Builds the example module and calls it through the real ABI.
//!
//! These tests run cargo for a second workspace, so they are ignored in the
//! normal test run. The unit tests in the crate cover the host side without
//! compiling anything.

use std::path::{Path, PathBuf};
use std::process::Command;

use elira_module::{Module, Request};

fn example_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/modules/echo")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn cargo_run(args: &[&str]) -> bool {
    let status = Command::new(cargo())
        .args(args)
        .status()
        .expect("start cargo");
    status.success()
}

fn library_path() -> PathBuf {
    let name = format!(
        "{}elira_module_echo{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    example_dir().join("target").join("debug").join(name)
}

#[test]
#[ignore = "runs cargo check for examples/modules/echo"]
fn example_module_compiles() {
    let manifest = example_dir().join("Cargo.toml");
    assert!(
        cargo_run(&[
            "check",
            "--manifest-path",
            manifest.to_str().expect("utf-8 manifest path"),
        ]),
        "cargo check failed for {}",
        manifest.display()
    );
}

#[test]
#[ignore = "builds examples/modules/echo and loads the resulting .so"]
fn loads_and_calls_the_example_module() {
    let manifest = example_dir().join("Cargo.toml");
    assert!(
        cargo_run(&[
            "build",
            "--manifest-path",
            manifest.to_str().expect("utf-8 manifest path"),
        ]),
        "cargo build failed for {}",
        manifest.display()
    );

    let path = library_path();
    let module = Module::load(&path).expect("example module loads");
    assert_eq!(module.version().as_deref(), Some("echo 0.1.0"));

    let response = module
        .call(&Request {
            method: "POST".to_string(),
            path: "/hello".to_string(),
            query: "a=1".to_string(),
            host: "example.com".to_string(),
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: vec![0x00, 0xff, b'h', b'i'],
            remote_addr: "192.0.2.1:50000".to_string(),
        })
        .expect("example module answers");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"POST /hello");
    assert!(response
        .headers
        .iter()
        .any(|(name, value)| name == "x-module" && value == "echo"));
    assert!(response
        .headers
        .iter()
        .any(|(name, value)| name == "x-echo-body-len" && value == "4"));
}
