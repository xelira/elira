use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
        let file = open_log(&path)?;
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            path,
            max_bytes: max_bytes as u64,
            keep: keep.max(1),
            state: Mutex::new(State { file, written }),
        })
    }

    pub fn reopen(&self) {
        if let Ok(file) = open_log(&self.path) {
            let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.file = file;
            state.written = written;
        }
    }

    pub fn write(&self, line: &str) {
        let mut state = match self.state.lock() {
            Ok(state) => state,

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

        if let Ok(file) = open_log(&self.path) {
            state.file = file;
            state.written = 0;
        }
    }
}

fn open_log(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o640));
    Ok(file)
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
