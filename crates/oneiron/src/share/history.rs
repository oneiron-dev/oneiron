//! A brief share whose recipient was erased, as stored (FIX 4231): history
//! only.
//!
//! Its body keeps the share's brief, its maximum, its status and its times,
//! and names no recipient. Its admission keeps its Gate decision, its digest
//! and its issuer, as approved. No live decoder reads that body, so the share
//! grants nothing and resolves for no one; the share receipts still read it.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::{ADMISSIONS, Share, ShareAdmission, read_share_in_txn, stored_share_in_txn};
use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantScope, decode_access_grant_body, decode_erased_share_body,
    encode_erased_share_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::store::Store;

/// What an actor's erase does with a brief share that actor received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRecipientErase {
    /// The share stays as inert history: its brief, its maximum, its status,
    /// its times and its admission as approved, naming no recipient.
    KeepInertHistory,
}

/// A share's body is half of its receipt, so a share an erased actor
/// received stays as history naming no one; its approval is never re-proved
/// against the changed body (FIX 4231; a call).
pub const ACTOR_ERASE_SHARE_RECIPIENT: ShareRecipientErase = ShareRecipientErase::KeepInertHistory;

/// A brief share as its receipts read it: who it was for, or no one once that
/// recipient was erased (FIX 4231), and what it granted.
pub(crate) struct ShareView {
    pub(crate) recipient: Option<EntityId>,
    pub(crate) brief_ref: String,
    pub(crate) world_refs: BTreeSet<EntityId>,
    pub(crate) facet_refs: BTreeSet<EntityId>,
    pub(crate) include_unscoped: bool,
    pub(crate) created_at: u64,
    pub(crate) revoked_at: Option<u64>,
}

impl ShareView {
    fn of(share: Share) -> Self {
        Self {
            recipient: Some(share.recipient_ref),
            brief_ref: share.brief_ref,
            world_refs: share.world_refs,
            facet_refs: share.facet_refs,
            include_unscoped: share.include_unscoped,
            created_at: share.created_at,
            revoked_at: share.revoked_at,
        }
    }

    /// [`Share::redaction_scope_hash`] of what it granted.
    pub(crate) fn redaction_scope_hash(&self) -> String {
        redaction_scope_hash(&self.world_refs, &self.facet_refs, self.include_unscoped)
    }
}

/// SHA-256 of a domain-separated, length-framed, canonically ordered typed scope.
pub(super) fn redaction_scope_hash(
    world_refs: &BTreeSet<EntityId>,
    facet_refs: &BTreeSet<EntityId>,
    include_unscoped: bool,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"oneiron.share.redaction_scope.v1\0");
    for refs in [world_refs, facet_refs] {
        hash.update((refs.len() as u64).to_be_bytes());
        for id in refs {
            hash.update(id.as_bytes());
        }
    }
    hash.update([u8::from(include_unscoped)]);
    crate::entity_id::bytes_to_hex_lower(&hash.finalize())
}

/// [`read_share_in_txn`] for the share receipts: an admitted share, and as
/// history one whose issuer was erased (FIX 3520), which grants nothing, or
/// one whose recipient was erased (FIX 4231), whose body names no one. Each
/// keeps its Gate decision, its digest and its times.
pub(crate) fn read_share_history_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(ShareView, ShareAdmission)>> {
    if let Some((share, admission)) = read_share_in_txn(store, txn, id)? {
        return Ok(Some((ShareView::of(share), admission)));
    }
    if let Some((share, admission)) = stored_share_in_txn(store, txn, id)? {
        return Ok(admission
            .issuer
            .is_none()
            .then(|| (ShareView::of(share), admission)));
    }
    let Some(raw) = grant_row_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    let Ok(terms) = decode_erased_share_body(&raw) else {
        return Ok(None);
    };
    let AccessGrantScope::SharedBrief {
        brief_ref,
        world_refs,
        facet_refs,
        include_unscoped,
    } = terms.scope
    else {
        return Ok(None);
    };
    let Some(admission) = ADMISSIONS
        .get(store, txn, id)?
        .as_deref()
        .and_then(ShareAdmission::decode)
    else {
        return Ok(None);
    };
    let view = ShareView {
        recipient: None,
        brief_ref,
        world_refs,
        facet_refs,
        include_unscoped,
        created_at: terms.created_at,
        revoked_at: terms.revoked_at,
    };
    Ok(Some((view, admission)))
}

/// The stored body of the grant `id` names, if it is one.
fn grant_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    match store.port_entity_record(txn, id) {
        Ok(Some(raw)) if raw.entity_type == ENTITY_TYPE_ACCESS_GRANT => Ok(Some(raw.body)),
        // A malformed row is no share. Storage failures still propagate.
        Ok(_) | Err(Error::CorruptedIndex("entity header")) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The live grant of share `id`, when `actor` is the one it was for.
pub(super) fn received_by_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    actor: &EntityId,
) -> Result<Option<AccessGrant>> {
    Ok(grant_row_in_txn(store, txn, id)?
        .and_then(|raw| decode_access_grant_body(&raw).ok())
        .filter(|grant| {
            grant.principal_ref == *actor
                && matches!(grant.scope, AccessGrantScope::SharedBrief { .. })
        }))
}

/// Share `id`'s body as history naming no recipient, as
/// [`ACTOR_ERASE_SHARE_RECIPIENT`] says, written through the one grant body
/// writer in the erase's own transaction at `at`.
pub(super) fn erase_recipient_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    grant: &AccessGrant,
    at: u64,
) -> Result<()> {
    match ACTOR_ERASE_SHARE_RECIPIENT {
        ShareRecipientErase::KeepInertHistory => {
            vault.apply_access_grant_body(wtxn, id, at, encode_erased_share_body(grant)?)
        }
    }
}
