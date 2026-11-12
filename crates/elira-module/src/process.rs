use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use crate::{Error, Request, Response, MAX_RESPONSE_BYTES};

const MAX_FRAME: usize = 16 * 1024 * 1024;

pub struct ProcessModule {
    runner: PathBuf,
    module: PathBuf,
    child: Mutex<Option<Child>>,
    input: Mutex<Option<BufWriter<ChildStdin>>>,
    output: Mutex<Option<BufReader<ChildStdout>>>,
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
