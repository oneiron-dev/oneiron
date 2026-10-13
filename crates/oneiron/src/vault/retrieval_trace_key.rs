//! The per-vault key over every stored retrieval-trace fork hash.
//!
//! A fork hash digests the query bytes with the run's settings and candidate
//! set, and a telemetry reader holds all of those but the query. Unkeyed, it
//! lets that reader test guesses at a short query offline. The stored hash is
//! therefore BLAKE3 keyed with a random key the store minted at its first open.
//! The key has its own `vault_meta` row outside the telemetry families, so it
//! never reaches telemetry, an export, a checkpoint image or sync.

use rand_core::{OsRng, RngCore};

use super::Vault;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

const RETRIEVAL_TRACE_KEY: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::RETRIEVAL_TRACE_KEY_LOCAL);

#[cfg(test)]
thread_local! {
    /// Leaves fork hashes unkeyed on this thread, so a check can compute the
    /// digest a telemetry reader could compute from a guessed query.
    static UNKEYED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The key a handle seals its retrieval-trace fork hashes with.
pub(crate) struct RetrievalTraceKey([u8; 32]);

impl RetrievalTraceKey {
    /// Reads the key `store` persisted at its first open, minting it on that
    /// first open.
    pub(super) fn resolve_at_open(store: &Store) -> Result<Self> {
        let mut wtxn = store.env.write_txn()?;
        if let Some(key) = RETRIEVAL_TRACE_KEY.get(store, &wtxn, &())? {
            return Ok(Self(key));
        }
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        RETRIEVAL_TRACE_KEY.put(store, &mut wtxn, &(), &key)?;
        wtxn.commit()?;
        Ok(Self(key))
    }

    /// `digest` keyed, as the stored trace and its fork index carry it.
    pub(crate) fn seal(&self, digest: [u8; 32]) -> [u8; 32] {
        #[cfg(test)]
        if UNKEYED.with(std::cell::Cell::get) {
            return digest;
        }
        *blake3::keyed_hash(&self.0, &digest).as_bytes()
    }
}

/// Runs `work` with this thread's fork hashes left unkeyed.
#[cfg(test)]
pub(crate) fn unkeyed_for_test<T>(work: impl FnOnce() -> T) -> T {
    UNKEYED.with(|unkeyed| unkeyed.set(true));
    let out = work();
    UNKEYED.with(|unkeyed| unkeyed.set(false));
    out
}

impl Vault {
    /// The key this handle resolved at open.
    pub(crate) fn retrieval_trace_key(&self) -> &RetrievalTraceKey {
        &self.retrieval_trace_key
    }
}
