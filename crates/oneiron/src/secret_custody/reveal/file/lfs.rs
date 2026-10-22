//! An agent's sight of a lift-marked LFS object (FIX 2897; ARCH-0069:
//! "granted agent: real bytes with a reason log").
//!
//! The lift sweep marks an object whole: a key split over two chunks only
//! its mark covers, and no chunk's mark speaks for the rest. So an agent's
//! read of a marked object asks for it whole, as a sealed file's read does:
//! one group of [`SEALED_FILE_CLASS`] with no custody record behind it,
//! judged by the one reveal check (CALLS `lfs-chunks whole-object group`).
//! Its fingerprint binds the object's oid and the exact manifest it reads,
//! never a chunk's hash. No lease is stamped.
//!
//! One transfer is one read. Its first request runs the check and writes the
//! receipt; each later page, WANT and release stands on that read
//! ([`Vault::lfs_object_read_stands`]) while a standing grant still covers
//! it, or once the owner's approval once was delivered to it: nothing is
//! spent or asked again.

use super::{
    FILE_REASK_DOMAIN, KeyRead, REVEALS, ReadGroup, RevealAsker, SEALED_FILE_CLASS,
    SecretRevealState, checked_text, covering_grant, file_ask_id, load_active_standing_grants,
    reveal_bound,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::lfs::LfsOid;
use crate::secret_custody::SecretSight;
use crate::vault::Vault;

/// Domain of a lift-marked LFS object read's fingerprint: never a hash of
/// stored bytes.
const LFS_OBJECT_READ_DOMAIN: &[u8] = b"oneiron.secret_reveal.lfs_object_read.v1";

/// The handle a lift-marked LFS object's read names in place of its keys'.
const LFS_OBJECT_HANDLE: &str = "lfs object";

impl Vault {
    /// How `asker` reads the lift-marked LFS object `oid` when it says `why`
    /// (FIX 2897): the read's reference once a standing grant covers it, or
    /// the owner approved its ask once, and its receipt is written; `None`
    /// while it is withheld, its ask filed, as a masked read is no error.
    ///
    /// # Errors
    /// As [`Self::file_sight`].
    pub(crate) fn lfs_object_sight(
        &self,
        asker: &RevealAsker,
        oid: LfsOid,
        why: &str,
    ) -> Result<Option<EntityId>> {
        let why = checked_text(
            why,
            "a read of a marked lfs object says why it needs its bytes",
            "an lfs object read's why is one line of at most 512 bytes",
        )?;
        let Some((artifact, hash)) = lfs_read_fingerprint(self, oid)? else {
            return Ok(None);
        };
        let sight = self.with_write_txn_grouped(|txn| {
            let read = KeyRead {
                asker,
                artifact: &artifact,
                why: &why,
                hash,
                groups: vec![ReadGroup {
                    class: SEALED_FILE_CLASS,
                    first: artifact,
                    keys: Vec::new(),
                    handle: LFS_OBJECT_HANDLE.to_owned(),
                }],
                per_class: false,
                repo: None,
            };
            self.read_sight_in_txn(txn, &read)
        })?;
        (sight == SecretSight::Granted)
            .then(|| file_ask_id(asker, &hash, None))
            .transpose()
    }

    /// Whether the read `held`, which [`Self::lfs_object_sight`] gave
    /// `asker`, still stands for `oid` now (FIX 2897): it is this agent's
    /// read of this object's exact manifest, in this project and run, and a
    /// standing grant covers it now, or the owner's approval once of it was
    /// delivered (CALLS `lfs-chunks transfer lifetime`). Nothing is spent,
    /// asked or written.
    ///
    /// # Errors
    /// A read of the object or of the reveal rows that fails.
    pub(crate) fn lfs_object_read_stands(
        &self,
        asker: &RevealAsker,
        oid: LfsOid,
        held: &EntityId,
    ) -> Result<bool> {
        let Some((_, hash)) = lfs_read_fingerprint(self, oid)? else {
            return Ok(false);
        };
        let base = file_ask_id(asker, &hash, None)?;
        if base != *held {
            return Ok(false);
        }
        let txn = self.store.env.read_txn()?;
        let bound = reveal_bound(
            &asker.connection(),
            SEALED_FILE_CLASS,
            asker.project.as_ref(),
        )?;
        let grants = load_active_standing_grants(&self.store, &txn)?;
        if covering_grant(&bound, asker.project, &grants)?.is_some() {
            return Ok(true);
        }
        // An approval once is delivered on its ask's own row, in the read's
        // ask sequence (FIX 6623).
        let mut ask = base;
        while let Some(row) = REVEALS.get(&self.store, &txn, &ask)? {
            if row.state == SecretRevealState::Delivered {
                return Ok(true);
            }
            ask = crate::codebase::entity_id_from_hash_material(
                FILE_REASK_DOMAIN,
                &[ask.as_bytes().as_slice()],
            )?;
        }
        Ok(false)
    }
}

/// The manifest ASSET of the stored object `oid`, and its read's
/// fingerprint: its oid and its exact canonical manifest, hashed under
/// [`LFS_OBJECT_READ_DOMAIN`]. `None` when the object is not stored.
fn lfs_read_fingerprint(vault: &Vault, oid: LfsOid) -> Result<Option<(EntityId, [u8; 32])>> {
    let Some(manifest) = vault.lfs_manifest(oid)? else {
        return Ok(None);
    };
    let canonical = manifest.encode()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(LFS_OBJECT_READ_DOMAIN);
    for part in [oid.as_bytes().as_slice(), canonical.as_slice()] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(Some((manifest.asset_id()?, *hasher.finalize().as_bytes())))
}
