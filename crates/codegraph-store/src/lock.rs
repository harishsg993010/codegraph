//! One writer at a time.
//!
//! Every command that can bring a store forward — a query that syncs
//! first, `watch`, the MCP server, `index` — takes the store's write lock
//! before it does, so two processes cannot write the same store at once.
//! Readers take nothing: a manifest commit is atomic and segments are
//! written once, so a reader always sees a whole generation.
//!
//! The lock is the OS's advisory lock on `<store>/LOCK`, released when the
//! holder exits — cleanly or not — so a crashed writer leaves nothing to
//! clean up.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

pub const LOCK_FILE: &str = "LOCK";

/// Held for the length of a write; dropped, it is released.
#[derive(Debug)]
pub struct WriteLock {
    _file: File,
}

fn lock_file(dir: &Path) -> std::io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join(LOCK_FILE))
}

impl WriteLock {
    /// The lock now, or `None` when another process holds it.
    pub fn try_acquire(dir: &Path) -> std::io::Result<Option<Self>> {
        let file = lock_file(dir)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(WriteLock { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// The lock, waiting up to `timeout` for whoever holds it.
    pub fn acquire(dir: &Path, timeout: Duration) -> std::io::Result<Option<Self>> {
        let start = Instant::now();
        loop {
            if let Some(l) = Self::try_acquire(dir)? {
                return Ok(Some(l));
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        let d = tempfile::tempdir().unwrap();
        let first = WriteLock::try_acquire(d.path()).unwrap().expect("free");
        // A second handle in the same process still contends: the lock is
        // on the file, not on the handle.
        assert!(WriteLock::try_acquire(d.path()).unwrap().is_none());
        assert!(WriteLock::acquire(d.path(), Duration::from_millis(120)).unwrap().is_none());
        drop(first);
        assert!(WriteLock::try_acquire(d.path()).unwrap().is_some());
    }
}
