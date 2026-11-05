//! FIX 3678 (rule 5): the scratch environment a whole-vault import keeps its
//! row index in. It is an LMDB environment of its own, made in the vault's
//! `lfs-staging/` directory through the root the store holds, and its one file
//! is unlinked as soon as the environment is open: it holds the locators and
//! join keys of the archive being read, never a row, nothing outlives the
//! environment, and a crash leaves no file behind. Its map is the vault's own
//! (CALLS "OF-222 import scratch index"): an index too large for it belongs to
//! an archive too large for this vault.

use heed::{Env, EnvFlags, EnvOpenOptions};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The scratch map is rounded up to this, a multiple of every page size.
pub const SCRATCH_MAP_ROUNDING: usize = 1 << 16;

/// An anonymous scratch LMDB environment, closed when dropped.
pub struct ScratchEnv {
    pub env: Option<Env>,
    #[cfg(not(unix))]
    pub _dir: tempfile::TempDir,
}

impl ScratchEnv {
    /// The environment, open for as long as this is.
    pub fn env(&self) -> Result<&Env> {
        self.env
            .as_ref()
            .ok_or(Error::InvariantViolation("archive scratch index closed"))
    }
}

impl Drop for ScratchEnv {
    fn drop(&mut self) {
        if let Some(env) = self.env.take() {
            env.prepare_for_closing().wait();
        }
    }
}

