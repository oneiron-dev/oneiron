//! Core half of `origin::secret_projection::selector_release::cache`: its store-layer items live in `oneiron_store::origin::secret_projection::selector_release::cache` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::secret_projection::selector_release::cache::*;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use crate::Vault;
use crate::secret_custody::KeyPlaces;

/// The copies one pass may take again, and the ones it used.
pub(super) struct PassCopies {
    vault: PathBuf,
    kept: BTreeMap<[u8; 32], Arc<KeptCopy>>,
    used: BTreeMap<[u8; 32], Arc<KeptCopy>>,
}

impl PassCopies {
    /// The copies kept for `vault`.
    pub(super) fn open(vault: &Vault) -> Self {
        let path = vault.store.env.path().to_path_buf();
        let kept = KEPT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&path)
            .cloned()
            .unwrap_or_default();
        Self {
            vault: path,
            kept,
            used: BTreeMap::new(),
        }
    }

    /// The copy of blob `hash` kept under the same key, now used.
    pub(super) fn take(
        &mut self,
        hash: &[u8; 32],
        present: bool,
        placed: Option<&KeyPlaces>,
    ) -> Option<Arc<KeptCopy>> {
        let kept = self
            .kept
            .get(hash)
            .filter(|kept| kept.present == present && kept.placed.as_ref() == placed)?;
        self.used.insert(*hash, Arc::clone(kept));
        Some(Arc::clone(kept))
    }

    /// Keeps the copy of blob `hash` this pass made under `present` and
    /// `placed`.
    pub(super) fn keep(
        &mut self,
        hash: [u8; 32],
        present: bool,
        placed: Option<KeyPlaces>,
        copy: Vec<u8>,
        places: Option<KeyPlaces>,
        stamp: [u8; 32],
    ) -> Arc<KeptCopy> {
        let kept = Arc::new(KeptCopy {
            present,
            placed,
            copy_hash: *blake3::hash(&copy).as_bytes(),
            copy: copy.into(),
            places: places.map(Arc::new),
            stamp,
        });
        self.used.insert(hash, Arc::clone(&kept));
        kept
    }

    /// Ends a whole pass: the vault keeps exactly the copies it used. A pass
    /// that fails before it ends leaves the kept copies as they were.
    pub(super) fn close(self) {
        KEPT.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(self.vault, self.used);
    }
}
