//! Resident-scoped diary coreference, separate from cross-vault PERSON identity.
//!
//! A same_as edge between two diary NOTEs has an Empty read scope until
//! *both* authors grant the exact pair. It never pools or merges their text.

use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTE;

fn pair(a: EntityId, b: EntityId) -> (EntityId, EntityId) {
    if a <= b { (a, b) } else { (b, a) }
}

fn author_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<EntityId> {
    let raw = vault
        .store
        .port_entity_record(txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if raw.entity_type != ENTITY_TYPE_NOTE {
        return Err(Error::InvalidEntityType(raw.entity_type));
    }
    let row = raw.encode();
    let body =
        super::decode_note_body_in_txn(&vault.store, txn, &row[ENTITY_METADATA_HEADER_LEN..])?;
    if body.kind != super::NoteKind::Diary {
        return Err(Error::InvalidClaimBody(
            "coreference endpoints must be diary NOTEs",
        ));
    }
    let key = crate::store::Store::encode_edge_key(&id, EdgeKind::AuthoredBy, &body.author_ref);
    if vault.store.edges_out.get(txn, &key)?.is_none() {
        return Err(Error::InvalidClaimBody("diary author edge is missing"));
    }
    Ok(body.author_ref)
}

fn linked_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    left: EntityId,
    right: EntityId,
) -> Result<bool> {
    let key = crate::store::Store::encode_edge_key(&left, EdgeKind::SameAs, &right);
    Ok(vault.store.edges_out.get(txn, &key)?.is_some())
}

/// Checks both live NOTE rows, their author edges, and two live, exact-pair
/// grants in the caller's read transaction. Missing or malformed grants fail closed.
pub(crate) fn shared_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    a: EntityId,
    b: EntityId,
) -> Result<bool> {
    let (left, right) = pair(a, b);
    if left == right || !linked_in(vault, txn, left, right)? {
        return Ok(false);
    }
    let (Ok(left_owner), Ok(right_owner)) =
        (author_in(vault, txn, left), author_in(vault, txn, right))
    else {
        return Ok(false);
    };
    if left_owner == right_owner {
        return Ok(false);
    }
    let mut left_granted = false;
    let mut right_granted = false;
    let now = vault.store.clock.now_recorded_at();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_ACCESS_GRANT])?
    {
        let (key, _) = row?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
            continue;
        }
        let Ok(grant) =
            crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        else {
            continue;
        };
        if grant.scope
            != (AccessGrantScope::DiaryCoreference {
                left_ref: left,
                right_ref: right,
            })
            || grant.capability != AccessGrantCapability::DiaryCoreferenceRead
            || grant.effective_status_at(now) != AccessGrantStatus::Active
        {
            continue;
        }
        left_granted |= grant.principal_ref == left_owner;
        right_granted |= grant.principal_ref == right_owner;
        if left_granted && right_granted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether another resident's diary NOTE can be seen through a mutually
/// granted coreference. The reader must be an author of the other endpoint.
pub(crate) fn readable_through_link(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    reader: EntityId,
) -> Result<bool> {
    if author_in(vault, txn, note).is_err() {
        return Ok(false);
    }
    for direction in [
        crate::ports::EdgeDirection::Out,
        crate::ports::EdgeDirection::In,
    ] {
        for other in vault.filtered_edge_peers(
            txn,
            direction,
            &note,
            EdgeKind::SameAs,
            Some(ENTITY_TYPE_NOTE),
            "diary coreference",
        )? {
            if author_in(vault, txn, other).is_ok_and(|author| author == reader)
                && shared_in(vault, txn, note, other)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

impl Memory<'_> {
    /// Assert coreference between two resident-private diary NOTE entities.
    /// This writes only a non-traversing, zero-weight link, never a merge.
    pub fn link_diary_coreference(&self, a: EntityId, b: EntityId) -> MemoryResult<()> {
        let (left, right) = pair(a, b);
        self.with_verified_actor_write_txn(|txn| {
            let left_owner = author_in(self.vault(), txn, left)?;
            let right_owner = author_in(self.vault(), txn, right)?;
            if left == right
                || left_owner == right_owner
                || (self.actor() != left_owner && self.actor() != right_owner)
            {
                return Err(Error::InvalidClaimBody(
                    "cross-diary link needs distinct resident authors",
                )
                .into());
            }
            if linked_in(self.vault(), txn, left, right)? {
                return Ok(());
            }
            apply_ops(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                txn,
                vec![BatchOp::Edge {
                    src: left,
                    kind: EdgeKind::SameAs,
                    tgt: right,
                    weight: 0.0,
                    vad: crate::Vad::NEUTRAL,
                }],
                self.vault()
                    .text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            Ok(())
        })
    }

    /// Grant the exact link from this resident's diary. Only when the other
    /// author grants the same pair does either scoped reader see the link.
    pub fn grant_diary_coreference(&self, a: EntityId, b: EntityId) -> MemoryResult<EntityId> {
        let (left, right) = pair(a, b);
        self.with_verified_actor_write_txn(|txn| {
            let left_owner = author_in(self.vault(), txn, left)?;
            let right_owner = author_in(self.vault(), txn, right)?;
            if left_owner == right_owner
                || (self.actor() != left_owner && self.actor() != right_owner)
                || !linked_in(self.vault(), txn, left, right)?
            {
                return Err(
                    Error::InvalidClaimBody("resident cannot grant this diary link").into(),
                );
            }
            let id = self.vault().store.clock.entity_id()?;
            let created_at = self.vault().store.clock.now_recorded_at();
            let grant = AccessGrant {
                authority_scope: crate::federation::scope_codec::read_preset(),
                principal_ref: self.actor(),
                scope: AccessGrantScope::DiaryCoreference {
                    left_ref: left,
                    right_ref: right,
                },
                capability: AccessGrantCapability::DiaryCoreferenceRead,
                status: AccessGrantStatus::Active,
                created_at,
                revoked_at: None,
                expires_at: None,
            };
            let data = crate::access_grant::encode_access_grant_body(&grant)?;
            self.vault()
                .apply_access_grant_body(txn, &id, created_at, data)?;
            Ok(id)
        })
    }

    /// Revoke only this resident's own exact-pair grant.
    pub fn revoke_diary_coreference_grant(&self, id: EntityId) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            let raw = self
                .vault()
                .store
                .port_entity_record(txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            if raw.entity_type != crate::registry::ENTITY_TYPE_ACCESS_GRANT {
                return Err(Error::InvalidEntityType(raw.entity_type).into());
            }
            let row = raw.encode();
            let grant =
                crate::access_grant::decode_access_grant_body(&row[ENTITY_METADATA_HEADER_LEN..])?;
            let AccessGrantScope::DiaryCoreference {
                left_ref,
                right_ref,
            } = grant.scope
            else {
                return Err(Error::InvalidClaimBody("not a diary coreference grant").into());
            };
            if grant.principal_ref != self.actor()
                || (author_in(self.vault(), txn, left_ref)? != self.actor()
                    && author_in(self.vault(), txn, right_ref)? != self.actor())
            {
                return Err(Error::InvalidClaimBody("resident does not own this grant").into());
            }
            let now = self
                .vault()
                .store
                .clock
                .now_recorded_at()
                .max(grant.created_at);
            let revoked = grant.revoked(now)?;
            let data = crate::access_grant::encode_access_grant_body(&revoked)?;
            self.vault().apply_access_grant_body(txn, &id, now, data)?;
            Ok(())
        })
    }
}
