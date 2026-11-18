use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use crate::{Error, Request, Response, MAX_RESPONSE_BYTES};

const MAX_FRAME: usize = 16 * 1024 * 1024;

pub struct ProcessModule {
    runner: PathBuf,
    module: PathBuf,
    child: Mutex<Option<Child>>,
    input: Mutex<Option<BufWriter<ChildStdin>>>,
    output: Mutex<Option<BufReader<ChildStdout>>>,
    pid: AtomicI32,
}

impl std::fmt::Debug for ProcessModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessModule")
            .field("runner", &self.runner)
            .field("module", &self.module)
            .finish_non_exhaustive()
    }
}

impl ProcessModule {
    pub fn new(runner: PathBuf, module: PathBuf) -> Self {
        Self {
            runner,
            module,
            child: Mutex::new(None),
            input: Mutex::new(None),
            output: Mutex::new(None),
            pid: AtomicI32::new(0),
        }
    }

    pub fn cancel(&self) {
        #[cfg(unix)]
        {
            let pid = self.pid.load(Ordering::Relaxed);
            if pid > 0 {
                // SAFETY: `pid` is the child we spawned and stored after a successful
                // spawn. A signal to an already reaped PID is harmless: the kernel returns
                // ESRCH and the result is ignored here.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    pub fn call(&self, request: &Request) -> Result<Response, Error> {
        let mut child = self.child.lock().unwrap_or_else(|e| e.into_inner());
        let mut input = self.input.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = self.output.lock().unwrap_or_else(|e| e.into_inner());

        if child.is_none() {
            let mut process = Command::new(&self.runner)
                .arg("module-worker")
                .arg(&self.module)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|source| Error::Process {
                    reason: format!("spawn {}: {source}", self.runner.display()),
                })?;
            *input = process.stdin.take().map(BufWriter::new);
            *output = process.stdout.take().map(BufReader::new);
            self.pid.store(process.id() as i32, Ordering::Relaxed);
            *child = Some(process);
        }

        let Some(writer) = input.as_mut() else {
            return Err(Error::Process {
                reason: "module worker has no stdin".to_owned(),
            });
        };
        let Some(reader) = output.as_mut() else {
            return Err(Error::Process {
                reason: "module worker has no stdout".to_owned(),
            });
        };

        let result = (|| -> Result<Response, Error> {
            let payload = serde_json::to_vec(request).map_err(|source| Error::Process {
                reason: format!("serialize request: {source}"),
            })?;
            if payload.len() > MAX_FRAME {
                return Err(Error::RequestTooLarge {
                    len: payload.len(),
                    limit: MAX_FRAME,
                });
            }
            writer
                .write_all(&(payload.len() as u32).to_be_bytes())
                .and_then(|_| writer.write_all(&payload))
                .and_then(|_| writer.flush())
                .map_err(|source| Error::Process {
                    reason: source.to_string(),
                })?;

            let mut length = [0u8; 4];
            reader
                .read_exact(&mut length)
                .map_err(|source| Error::Process {
                    reason: source.to_string(),
                })?;
            let length = u32::from_be_bytes(length) as usize;
            if length > MAX_FRAME || length > MAX_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge {
                    len: length,
                    limit: MAX_RESPONSE_BYTES,
                });
            }
            let mut body = vec![0u8; length];
            reader
                .read_exact(&mut body)
                .map_err(|source| Error::Process {
                    reason: source.to_string(),
                })?;
            serde_json::from_slice::<Response>(&body).map_err(|source| Error::Process {
                reason: format!("parse response: {source}"),
            })
        })();

        if result.is_err() {
            if let Some(mut process) = child.take() {
                let _ = process.kill();
                let _ = process.wait();
            }
            self.pid.store(0, Ordering::Relaxed);
            *input = None;
            *output = None;
        }
        result
    }
}

impl Drop for ProcessModule {
    fn drop(&mut self) {
        if let Some(mut process) = self.child.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::Request;

    fn request() -> Request {
        Request {
            method: "GET".to_string(),
            path: "/".to_string(),
            query: String::new(),
            host: "example.com".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            remote_addr: "192.0.2.1:1".to_string(),
        }
    }

    fn call_after_restart(module: &ProcessModule) -> Response {
        for attempt in 0..3 {
            match module.call(&request()) {
                Ok(response) => return response,
                Err(err)
                    if attempt < 2 && err.to_string().contains("failed to fill whole buffer") =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(err) => panic!("restarted response: {err:?}"),
            }
        }
        unreachable!()
    }

    #[test]
    fn sandbox_process_is_restarted_after_a_crash() {
        let Ok(version) = std::process::Command::new("python3")
            .arg("--version")
            .output()
        else {
            return;
        };
        if !version.status.success() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("elira-module-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let marker = dir.join("started");
        let runner = dir.join("runner.py");
        std::fs::write(
            &runner,
            format!(
                r#"#!/usr/bin/env python3
import json, os, struct, sys
length = sys.stdin.buffer.read(4)
if len(length) != 4:
    sys.exit(2)
size = struct.unpack(">I", length)[0]
sys.stdin.buffer.read(size)
if not os.path.exists({marker:?}):
    open({marker:?}, "w").close()
    sys.exit(1)
body = json.dumps({{"status": 200, "headers": [], "body": "b2s="}}).encode()
sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
sys.stdout.buffer.flush()
"#,
                marker = marker.display().to_string()
            ),
        )
        .expect("runner");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let module = ProcessModule::new(runner, dir.join("module.so"));
        assert!(module.call(&request()).is_err());
        let response = call_after_restart(&module);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");

        module.cancel();
        assert!(module.call(&request()).is_err());
        let response = module.call(&request()).expect("response after cancel");
        assert_eq!(response.body, b"ok");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_frame_is_an_error() {
        let Ok(version) = std::process::Command::new("python3")
            .arg("--version")
            .output()
        else {
            return;
        };
        if !version.status.success() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("elira-module-part-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let runner = dir.join("runner.py");
        std::fs::write(
            &runner,
            r#"#!/usr/bin/env python3
import struct, sys
length = sys.stdin.buffer.read(4)
if len(length) != 4:
    sys.exit(2)
size = struct.unpack(">I", length)[0]
sys.stdin.buffer.read(size)
sys.stdout.buffer.write(struct.pack(">I", 16) + b"short")
sys.stdout.buffer.flush()
"#,
        )
        .expect("runner");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let module = ProcessModule::new(runner, dir.join("module.so"));
        assert!(matches!(
            module.call(&request()),
            Err(Error::Process { .. })
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_frame_is_rejected_and_runner_restarts() {
        let Ok(version) = std::process::Command::new("python3")
            .arg("--version")
            .output()
        else {
            return;
        };
        if !version.status.success() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("elira-module-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let flag = dir.join("oversized");
        let runner = dir.join("runner.py");
        std::fs::write(
            &runner,
            format!(
                r#"#!/usr/bin/env python3
import json, os, struct, sys
length = sys.stdin.buffer.read(4)
if len(length) != 4:
    sys.exit(2)
size = struct.unpack(">I", length)[0]
sys.stdin.buffer.read(size)
if os.path.exists({flag:?}):
    sys.stdout.buffer.write(struct.pack(">I", 0xFFFFFFFF))
    sys.stdout.buffer.flush()
    sys.exit(0)
body = json.dumps({{"status": 200, "headers": [], "body": "b2s="}}).encode()
sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
sys.stdout.buffer.flush()
"#,
                flag = flag.display().to_string()
            ),
        )
        .expect("runner");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        std::fs::write(&flag, b"1").expect("flag");
        let module = ProcessModule::new(runner, dir.join("module.so"));
        assert!(matches!(
            module.call(&request()),
            Err(Error::ResponseTooLarge { .. })
        ));
        std::fs::remove_file(&flag).expect("remove flag");
        let response = call_after_restart(&module);
        assert_eq!(response.body, b"ok");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
