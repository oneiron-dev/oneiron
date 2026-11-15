//! What a federation peer's chunk exchange releases of a published object
//! that no read authority admits (EXPORTDOORS Q3 = A; ARCH-0027 :382).
//! Publishing an object is not a disclosure: the peer gets it only whole and
//! as stored, when the Nulled rule, reading it as one file, leaves every
//! byte of it unchanged ([`crate::batch::export::export_file_body_admitted`]).
//! Otherwise its manifest and every chunk are refused alike. A chunk is a
//! slice of the object, which the receiver checks against the manifest and
//! the object's SHA-256, so a credential may cross chunks: no chunk is
//! judged or rewritten alone.
//!
//! The verdict reads the object's bytes alone, so it is kept in memory by
//! the object's OID and its manifest's BLAKE3: judged at an exchange's first
//! manifest or WANT request, and read at every later one. Who asks is never
//! kept: each request is authorized again before the verdict is read. The
//! scanner is compiled in, so a kept verdict never outlives the rules that
//! made it. No object size skips the judgment.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::Vault;
use crate::error::Result;
use crate::origin::lfs::LfsOid;

/// The most verdicts one vault keeps. Past it, one is dropped, and judged
/// again when next asked.
const KEPT_RELEASE_VERDICTS: usize = 4096;

/// An object's OID and its manifest's BLAKE3.
type ReleaseKey = (LfsOid, [u8; 32]);

/// Each judged object's release verdict, by its OID and its manifest's
/// BLAKE3 (EXPORTDOORS Q3 c). In memory only.
#[derive(Debug, Default)]
pub(crate) struct LfsReleaseVerdicts {
    kept: Mutex<HashMap<ReleaseKey, bool>>,
}

impl LfsReleaseVerdicts {
    fn kept(&self, key: &ReleaseKey) -> Option<bool> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .copied()
    }

    fn keep(&self, key: ReleaseKey, released: bool) {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.len() >= KEPT_RELEASE_VERDICTS
            && !kept.contains_key(&key)
            && let Some(dropped) = kept.keys().next().copied()
        {
            kept.remove(&dropped);
        }
        kept.insert(key, released);
    }
}

impl Vault {
    /// Whether the published object `oid`, whose stored manifest's BLAKE3
    /// is `manifest`, goes whole to a peer that no read authority admits:
    /// the Nulled rule, read over all of its verified bytes, changes none of
    /// them.
    ///
    /// # Errors
    /// The object's read (a deleted or corrupt object), or the raw release
    /// check's.
    pub(super) fn lfs_object_released(&self, oid: LfsOid, manifest: [u8; 32]) -> Result<bool> {
        let key = (oid, manifest);
        if let Some(released) = self.lfs_release_verdicts.kept(&key) {
            return Ok(released);
        }
        let bytes = self.get_lfs_object(oid)?.ok_or_else(super::invalid)?;
        let released = crate::batch::export::export_file_body_admitted(&bytes)?;
        self.lfs_release_verdicts.keep(key, released);
        Ok(released)
    }
}
