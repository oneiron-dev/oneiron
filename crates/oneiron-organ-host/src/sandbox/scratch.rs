//! A third-party organ's scratch dir (FIX 7885): a fresh dir of its own
//! under the system's temp dir, mode 0700, made before the start. It is the
//! one dir the organ's fence lets it write, and its `TMPDIR`, in place of
//! the shared `/tmp`. It goes, with all the organ left in it, when the host
//! reaps the organ (`Lifeline::end`), or when a start that made it fails.

use std::hash::{BuildHasher, Hasher};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many fresh scratch names one make tries before it says the temp dir
/// would not take one (blind-review P1): each name is unpredictable, so a
/// run of collisions is squatting or a wedged temp dir, and the start fails
/// closed instead of retrying forever.
const SCRATCH_NAME_ATTEMPTS: u32 = 10;

/// Fresh unpredictable bits for one scratch name: std's randomly keyed
/// hasher over the attempt counter. Uniqueness never rests on the hash:
/// the counter and the create that fails when taken hold that.
fn fresh_bits(counter: u64) -> u64 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(counter);
    hasher.finish()
}

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
        // Each name is fresh and unpredictable, and only a dir this call
        // made is used, so one made by anyone else is never written; a name
        // another dir holds is retried a bounded few times, then the start
        // fails closed (blind-review P1).
        for _ in 0..SCRATCH_NAME_ATTEMPTS {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let bits = fresh_bits(n);
            let dir = root.join(format!("oneiron-organ-scratch-{pid}-{n}-{bits:016x}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Self { dir }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(not_made(&root, &err)),
            }
        }
        Err(not_made(
            &root,
            &io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{SCRATCH_NAME_ATTEMPTS} fresh names collided in a row"),
            ),
        ))
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
