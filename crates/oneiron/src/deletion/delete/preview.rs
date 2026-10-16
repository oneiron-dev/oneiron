//! Snapshot-bound impact preview for the one-action, confirmed delete door.

use super::impact::{HeldBytes, LfsChunkImpact, bytes_impact_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Explicit brief grant recipients, plus the warning that delivered foreign
/// copies cannot be recalled, and which bytes the record shares with others.
/// No raw content is retained in this preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityPreview {
    entity: EntityId,
    fingerprint: [u8; 32],
    note_fingerprint: Option<[u8; 32]>,
    shared_with: Vec<(EntityId, EntityId)>,
    held_bytes: Vec<HeldBytes>,
    lfs_chunks: Vec<LfsChunkImpact>,
}

impl DeleteEntityPreview {
    pub fn entity(&self) -> EntityId {
        self.entity
    }

    /// (grant id, recipient id) for live direct brief shares. Federation
    /// selectors alone do not prove that any named peer already has a copy.
    pub fn shared_with(&self) -> &[(EntityId, EntityId)] {
        &self.shared_with
    }

    /// Federation recipients can retain copies after a local retraction.
    pub const fn remote_copies_may_remain(&self) -> bool {
        true
    }

    /// Each content hash this blob record holds, with the other records in
    /// this vault holding the same bytes. Empty for a record that holds none.
    pub fn held_bytes(&self) -> &[HeldBytes] {
        &self.held_bytes
    }

    /// One row per distinct chunk when this record is an LFS object's
    /// manifest; empty otherwise.
    pub fn lfs_chunks(&self) -> &[LfsChunkImpact] {
        &self.lfs_chunks
    }

    /// Every other record holding any of this record's blob bytes, sorted:
    /// what an erase with the same-bytes flag also takes. LFS chunks are never
    /// in it: an object sharing a chunk holds different contents.
    pub fn same_bytes_matches(&self) -> Vec<EntityId> {
        let mut matches: Vec<EntityId> = self
            .held_bytes
            .iter()
            .flat_map(|row| row.other_holders().iter().copied())
            .collect();
        matches.sort_unstable();
        matches.dedup();
        matches
    }

    /// The preview cannot name a different body, an added/removed grant, or
    /// a changed set of records sharing its bytes.
    pub(crate) fn check_before_unshare(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.check_body(vault, txn)?;
        if crate::share::active_brief_shares_for(
            &vault.store,
            txn,
            &self.entity,
            vault.store.clock.now_recorded_at(),
        )? != self.shared_with
        {
            return Err(Error::ConcurrentWrite("delete preview stale"));
        }
        Ok(())
    }

    /// Repeated in every destructive transaction by the owner-gated delete
    /// rail; a new active grant, a changed body, or a changed set of records
    /// sharing its bytes refuses before publication.
    pub(crate) fn check_after_unshare(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.check_body(vault, txn)?;
        if !crate::share::active_brief_shares_for(
            &vault.store,
            txn,
            &self.entity,
            vault.store.clock.now_recorded_at(),
        )?
        .is_empty()
        {
            return Err(Error::ConcurrentWrite("delete shares changed"));
        }
        Ok(())
    }

    fn check_body(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &self.entity)?
            .ok_or(Error::ConcurrentWrite("delete preview stale"))?;
        if blake3::hash(&raw).as_bytes() != &self.fingerprint
            || crate::note::storage::delete_preview_fingerprint(vault, txn, self.entity, &raw)?
                != self.note_fingerprint
        {
            return Err(Error::ConcurrentWrite("delete preview stale"));
        }
        let (held_bytes, lfs_chunks) = bytes_impact_in_txn(vault, txn, &self.entity, &raw)?;
        if held_bytes != self.held_bytes || lfs_chunks != self.lfs_chunks {
            return Err(Error::ConcurrentWrite("delete preview stale"));
        }
        Ok(())
    }
}

impl Vault {
    /// The owner authority fold and all impact fields use one read snapshot.
    pub(crate) fn preview_entity_delete_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<DeleteEntityPreview> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let shared_with = crate::share::active_brief_shares_for(
            &self.store,
            txn,
            id,
            self.store.clock.now_recorded_at(),
        )?;
        let (held_bytes, lfs_chunks) = bytes_impact_in_txn(self, txn, id, &raw)?;
        Ok(DeleteEntityPreview {
            entity: *id,
            fingerprint: *blake3::hash(&raw).as_bytes(),
            note_fingerprint: crate::note::storage::delete_preview_fingerprint(
                self, txn, *id, &raw,
            )?,
            shared_with,
            held_bytes,
            lfs_chunks,
        })
    }
}
