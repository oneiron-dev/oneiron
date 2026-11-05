//! The masked copies one pass made, kept for the next (FIX 10599; owner
//! order 30 Oct: speed is in scope): a pass-local memo in this process's
//! memory, never written to the store. The mark walk stays the one
//! authority of every pass (CALL 8033 option d); the memo only spares a pass
//! masking a blob again.
//!
//! Every window release and admission reads the marks once and makes each
//! marked blob's copy. A copy is a pure function of three things: the blob's
//! stored bytes (named by their whole BLAKE3), whether this vault holds them,
//! and the spans its marks and its mask row place in them (`None` for a
//! blob marked whole). The same three make the same bytes, so a pass keeps
//! each copy it made under exactly those, and a later pass takes it again
//! only when all three read the same in its own transaction. Any change to
//! them (a new mark, a re-mask, a value custody came to know later, an
//! erase of the stored bytes) is another key, and the copy is made again.
//!
//! Only what a peer gets is kept: the copy, its spans and its stamp, never
//! the stored bytes, which every pass reads again. Each pass keeps exactly
//! the copies it used, so a blob no longer marked, or no longer held, leaves
//! at the next pass. A kept stamp names the marks the copy was first made
//! under: marks that change without changing the spans make the same bytes,
//! so a peer holding them holds the current copy.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use crate::Vault;
use crate::secret_custody::KeyPlaces;

/// Each vault's kept copies, by its store's path, then by blob.
static KEPT: LazyLock<Mutex<HashMap<PathBuf, BTreeMap<[u8; 32], Arc<KeptCopy>>>>> =
    LazyLock::new(Mutex::default);

/// One kept copy and the key it was made under.
pub(super) struct KeptCopy {
    /// Whether the stored bytes were held.
    present: bool,
    /// The spans the blob's marks and mask row placed when it was made.
    placed: Option<KeyPlaces>,
    /// Exactly the bytes a peer gets.
    pub(super) copy: Arc<[u8]>,
    /// The BLAKE3 of `copy`.
    pub(super) copy_hash: [u8; 32],
    /// The spans `copy` overwrites; `None` for the sealed-file placeholder.
    pub(super) places: Option<Arc<KeyPlaces>>,
    /// The stamp fingerprint it was made under.
    pub(super) stamp: [u8; 32],
}

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
