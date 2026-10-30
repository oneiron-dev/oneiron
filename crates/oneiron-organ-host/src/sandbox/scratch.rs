//! A third-party organ's scratch dir (FIX 7885): a fresh dir of its own
//! under the system's temp dir, mode 0700, made before the start. It is the
//! one dir the organ's fence lets it write, and its `TMPDIR`, in place of
//! the shared `/tmp`. It goes, with all the organ left in it, when the host
//! reaps the organ (`Lifeline::end`), or when a start that made it fails.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// One organ process's scratch dir, removed on drop.
#[derive(Debug)]
pub(crate) struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// Makes a new scratch dir under the system's temp dir, as its links
    /// resolve, so the path is the one the fence matches (on macOS `/var`
    /// is `/private/var`).
    ///
    /// # Errors
    /// The temp dir does not resolve, or the dir could not be made; the
    /// error names the temp dir.
    pub(super) fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temp = std::env::temp_dir();
        let root = std::fs::canonicalize(&temp).map_err(|err| not_made(&temp, &err))?;
        let pid = std::process::id();
        // A name another dir holds is a collision, never a size: the next
        // name is tried, as many times as it takes (Rule 5). Only a dir this
        // call made is used, so one made by anyone else is never written.
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = root.join(format!("oneiron-organ-scratch-{pid}-{n}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Self { dir }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(not_made(&root, &err)),
            }
        }
    }

    /// Where the dir is.
    pub(super) fn path(&self) -> &Path {
        &self.dir
    }
}

/// `err`, saying the scratch dir under `temp` was not made.
fn not_made(temp: &Path, err: &io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!(
            "the organ's scratch dir under {} was not made: {err}",
            temp.display()
        ),
    )
}

impl Drop for Scratch {
    /// Removes the dir and all in it. A link the organ left is removed,
    /// never followed.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
