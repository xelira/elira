//! Access log file with size-based rotation.
//!
//! The process holds one append-only descriptor. Rotation renames the current
//! file and reopens, so an external logrotate can also rename it and send
//! SIGHUP: a reload builds a new runtime and therefore a new descriptor.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct AccessLog {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    state: Mutex<State>,
}

struct State {
    file: File,
    written: u64,
}

impl AccessLog {
    pub fn open(path: PathBuf, max_bytes: usize, keep: usize) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            path,
            max_bytes: max_bytes as u64,
            keep: keep.max(1),
            state: Mutex::new(State { file, written }),
        })
    }

    pub fn write(&self, line: &str) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            // A panic elsewhere must not stop the log.
            Err(poisoned) => poisoned.into_inner(),
        };

        if writeln!(state.file, "{line}").is_err() {
            return;
        }
        state.written += line.len() as u64 + 1;

        if state.written > self.max_bytes {
            self.rotate(&mut state);
        }
    }

    fn rotate(&self, state: &mut State) {
        for index in (1..self.keep).rev() {
            let from = numbered(&self.path, index);
            let to = numbered(&self.path, index + 1);
            let _ = std::fs::rename(from, to);
        }

        let _ = std::fs::rename(&self.path, numbered(&self.path, 1));

        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            state.file = file;
            state.written = 0;
        }
    }
}

fn numbered(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{index}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        std::env::temp_dir().join(format!(
            "elira-log-{}-{label}-{}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn writes_and_rotates() {
        let path = temp_path("rotate");
        let log = AccessLog::open(path.clone(), 32, 2).expect("open");

        // The second write crosses the limit, so rotation moves both lines
        // into `.1` and the new current file starts empty.
        log.write("first line that is long enough");
        log.write("second line that is long enough");
        log.write("third line that is long enough");

        let current = std::fs::read_to_string(&path).expect("current");
        assert!(current.contains("third"), "{current}");

        let rotated = std::fs::read_to_string(numbered(&path, 1)).expect("rotated");
        assert!(rotated.contains("first"), "{rotated}");
        assert!(rotated.contains("second"), "{rotated}");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(numbered(&path, 1));
    }
}
