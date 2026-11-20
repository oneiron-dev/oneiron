//! The record tombstones a live federation peer's update carries, and which
//! of them this vault admits (CROSS-VAULT-DELETE-NEVER-ADMITTED = A).
//! Owned by `super`.
//!
//! While the share is live, the owner's delete travels as an update and
//! removes the peer's copy: request-bound, authenticated, same sender, same
//! grant. Membership and topology tombstones stay out. After a leave, only
//! erase requests reach the copy (ARCH-0043 #leaving-a-company).

use std::collections::{BTreeMap, BTreeSet};

use loro::LoroDoc;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::deletion::decode_tombstone_value;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::PactDelivery;
use crate::federation::delivery_record::{FederationDeliveryRecord, delivery_history_in_txn};
use crate::sync::loro_support::map_for_each_tombstone_value;
use crate::sync::types::{TombstoneResidence, WindowKey, tombstone_residence_in};

/// The live lane a federation peer's update arrives on: the grant the bound
/// peer holds here, and the pact that grant delivers through. Both are read
/// again from the live fold before each admission, a deferred update's
/// replay among them.
#[derive(Clone, Copy)]
pub(super) struct DeliveringPact<'a> {
    pub(super) grant: EntityId,
    pub(super) delivery: &'a PactDelivery,
}

/// How one admission treats the tombstones an update carries.
#[derive(Clone, Copy)]
pub(super) enum TombstoneAdmission<'a> {
    /// Any tombstone refuses the whole update: a staged artifact or an
    /// admission that names no live peer lane proves no delivery.
    RefuseUpdate,
    /// The live peer lane: each tombstone the delivering pact proves lands
    /// ([`admitted_peer_tombstones`]) and every other is dropped. With no
    /// delivering pact, every one is dropped.
    LivePeer(Option<DeliveringPact<'a>>),
}

/// One tombstone this vault admits: the row it deletes, the value the sender
/// wrote, and the window here that holds the row, where it lands.
pub(super) struct AdmittedTombstone {
    pub(super) id: EntityId,
    pub(super) value: Vec<u8>,
    pub(super) home: WindowKey,
}

/// Whether a row of `entity_type` is a membership or topology row: a grant,
/// the authority log, the policy manifest, a WORLD or its key pad, an
/// identity topology event, secret custody, or a MACHINE. No peer's
/// tombstone deletes one here, and no sender emits one to a peer. The one
/// list both sides read.
pub(in crate::sync) fn is_membership_or_topology_kind(entity_type: u8) -> bool {
    use crate::registry::{
        ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_FEDERATION_GRANT,
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_OUTBOUND_GRANT,
        ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD,
        ENTITY_TYPE_WORLD_KEY_PAD,
    };
    matches!(
        entity_type,
        ENTITY_TYPE_FEDERATION_GRANT
            | ENTITY_TYPE_ACCESS_GRANT
            | ENTITY_TYPE_OUTBOUND_GRANT
            | ENTITY_TYPE_AUTHORITY_LOG
            | ENTITY_TYPE_POLICY_MANIFEST
            | ENTITY_TYPE_WORLD
            | ENTITY_TYPE_WORLD_KEY_PAD
            | ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
            | ENTITY_TYPE_SECRET_CUSTODY
            | ENTITY_TYPE_MACHINE
    )
}

/// The tombstones of `remote` this vault admits from the peer on `lane`, each
/// with the window here that holds its row: the first of `parts` that does,
/// else the row's own window. A tombstone for the row R is admitted when all
/// hold:
/// - its key is R's canonical id, and its value is one the engine writes: a
///   known reason and the delete's request id;
/// - this vault's delivery ledger holds a row for R that the lane's pact
///   delivered, at any consent epoch, from the pact's peer vault under the
///   lane's grant, and its digest is that of the row this vault holds now:
///   the copy is still the one that sender delivered under that grant;
/// - R's stored kind is no membership or topology row
///   ([`is_membership_or_topology_kind`]);
/// - R sits in that window here.
///
/// Every other tombstone is dropped, and the rest of the update lands: one
/// stale tombstone never stops a peer's sync. A row another vault, another
/// grant or this vault's own writer last wrote keeps its copy.
pub(super) fn admitted_peer_tombstones(
    vault: &Vault,
    remote: &LoroDoc,
    lane: DeliveringPact<'_>,
    parts: &[WindowKey],
) -> Result<Vec<AdmittedTombstone>> {
    let mut sent = Vec::new();
    map_for_each_tombstone_value(&remote.get_map("tombstones"), |key, value| {
        sent.push((key.to_owned(), value.to_vec()));
    });
    if sent.is_empty() {
        return Ok(Vec::new());
    }
    let txn = vault.store.env.read_txn()?;
    let named = sent
        .iter()
        .filter_map(|(key, _)| canonical_id(key))
        .collect::<BTreeSet<_>>();
    let history = delivery_history_in_txn(&vault.store, &txn, &named)?;
    let carried = sent.len();
    let mut admitted = Vec::new();
    for (key, value) in sent {
        let Some(id) = canonical_id(&key) else {
            continue;
        };
        if let Some(home) = admitted_home(vault, &txn, &history, lane, parts, id, &value)? {
            admitted.push(AdmittedTombstone { id, value, home });
        }
    }
    let dropped = carried - admitted.len();
    if dropped > 0 {
        tracing::debug!(
            dropped,
            admitted = admitted.len(),
            "federated tombstones dropped: no matching delivery here"
        );
    }
    Ok(admitted)
}

/// The id `key` names when it is that id's canonical spelling. A
/// case-shifted alias names no row a peer may delete.
fn canonical_id(key: &str) -> Option<EntityId> {
    EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key)
}

/// The window here a tombstone for `id` with `value` lands in, when this
/// vault admits it ([`admitted_peer_tombstones`]); `None` drops it.
fn admitted_home(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    history: &BTreeMap<EntityId, Vec<FederationDeliveryRecord>>,
    lane: DeliveringPact<'_>,
    parts: &[WindowKey],
    id: EntityId,
    value: &[u8],
) -> Result<Option<WindowKey>> {
    let decoded = decode_tombstone_value(value);
    if decoded.reason.is_none() || decoded.request_id.is_none() {
        return Ok(None);
    }
    let Some(row) = vault.get_raw_in(txn, &id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&row) else {
        return Ok(None);
    };
    if is_membership_or_topology_kind(header.entity_type) {
        return Ok(None);
    }
    let held = *blake3::hash(&row).as_bytes();
    let Some(delivered) = history.get(&id).and_then(|records| {
        records.iter().find(|record| {
            record.delivering_pact == lane.delivery.pact
                && record.source_vault == lane.delivery.source_vault
                && record.grant_ref == lane.grant
                && record.delivered_row_hash == held
        })
    }) else {
        return Ok(None);
    };
    for part in parts {
        if tombstone_residence_in(vault, txn, &id, part)? == TombstoneResidence::Match {
            return Ok(Some(part.clone()));
        }
    }
    let month = WindowKey::from_timestamp(header.learned_at);
    let own = match delivered.world {
        Some(world) => WindowKey::for_month_world(&month, world),
        None => month,
    };
    let held_there = tombstone_residence_in(vault, txn, &id, &own)? == TombstoneResidence::Match;
    Ok(held_there.then_some(own))
}
