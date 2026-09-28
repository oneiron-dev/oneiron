//! Snapshot-bound impact preview for the one-action, confirmed delete door.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Explicit brief grant recipients, plus the warning that delivered foreign
/// copies cannot be recalled. No raw content is retained in this preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityPreview {
    entity: EntityId,
    fingerprint: [u8; 32],
    note_fingerprint: Option<[u8; 32]>,
    shared_with: Vec<(EntityId, EntityId)>,
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

    /// The preview cannot name a different body or an added/removed grant.
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
    /// rail; a new active grant or a changed body refuses before publication.
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
        Ok(DeleteEntityPreview {
            entity: *id,
            fingerprint: *blake3::hash(&raw).as_bytes(),
            note_fingerprint: crate::note::storage::delete_preview_fingerprint(
                self, txn, *id, &raw,
            )?,
            shared_with,
        })
    }
}
