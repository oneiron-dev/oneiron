//! Snapshot-bound impact preview for the one-action, confirmed delete door.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Explicit brief grant recipients, the version bytes the record holds, plus
/// the warning that delivered foreign copies cannot be recalled. No raw content
/// is retained in this preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityPreview {
    entity: EntityId,
    fingerprint: [u8; 32],
    note_fingerprint: Option<[u8; 32]>,
    shared_with: Vec<(EntityId, EntityId)>,
    held_bytes: Vec<DeleteHeldBytes>,
}

/// One version-byte object the previewed record holds (ARCH-0005a). A delete
/// of the last reference takes the bytes. A plain delete of one reference of
/// several leaves them to the others, while a hard erase takes the bytes and
/// every other reference to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteHeldBytes {
    asset: EntityId,
    others: Vec<EntityId>,
}

impl DeleteHeldBytes {
    /// The ASSET carrying the bytes.
    pub fn asset(&self) -> EntityId {
        self.asset
    }

    /// The other records whose reference keeps the bytes past a plain delete.
    pub fn others(&self) -> &[EntityId] {
        &self.others
    }

    /// Whether the previewed record is the last reference to the bytes.
    pub fn is_last_reference(&self) -> bool {
        self.others.is_empty()
    }
}

impl DeleteEntityPreview {
    pub fn entity(&self) -> EntityId {
        self.entity
    }

    /// The version bytes the record holds, each one-of-several or the last
    /// reference. Empty for a record that holds none.
    pub fn held_bytes(&self) -> &[DeleteHeldBytes] {
        &self.held_bytes
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
            || held_bytes_in_txn(vault, txn, &self.entity)? != self.held_bytes
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
            held_bytes: held_bytes_in_txn(self, txn, id)?,
        })
    }
}

fn held_bytes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<DeleteHeldBytes>> {
    Ok(vault
        .erased_holdings_in_txn(txn, id)?
        .into_iter()
        .map(|holding| DeleteHeldBytes {
            asset: holding.asset,
            others: holding.others,
        })
        .collect())
}
