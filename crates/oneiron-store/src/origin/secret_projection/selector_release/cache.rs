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

use crate::file_secret_marks::KeyPlaces;

/// Each vault's kept copies, by its store's path, then by blob.
pub static KEPT: LazyLock<Mutex<HashMap<PathBuf, BTreeMap<[u8; 32], Arc<KeptCopy>>>>> =
    LazyLock::new(Mutex::default);

/// One kept copy and the key it was made under.
pub struct KeptCopy {
    /// Whether the stored bytes were held.
    pub present: bool,
    /// The spans the blob's marks and mask row placed when it was made.
    pub placed: Option<KeyPlaces>,
    /// Exactly the bytes a peer gets.
    pub copy: Arc<[u8]>,
    /// The BLAKE3 of `copy`.
    pub copy_hash: [u8; 32],
    /// The spans `copy` overwrites; `None` for the sealed-file placeholder.
    pub places: Option<Arc<KeyPlaces>>,
    /// The stamp fingerprint it was made under.
    pub stamp: [u8; 32],
}

