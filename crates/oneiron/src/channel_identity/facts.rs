//! Channel facts as claims (OF-272): every write of a ChannelIdentity row
//! moves its `channel_identity.*` heads in the same transaction, and the fact
//! readers read those heads, not the row. The row seeds the channel, address
//! and binding; from then on a claim correction owns them, and the assignment
//! slot follows the heads. Custody (who holds the account, the delegated
//! grant and its scopes, the live credential proof) stays on the local row:
//! claims carry facts, never send authority.
use std::collections::BTreeMap;

use super::codec::{
    decode_binding, decode_optional_entity_ref, is_channel_identity_claim_predicate,
};
use super::keys::*;
use super::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState, Custody,
    InboundDisposition,
};
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::temporal::TimeRange;
use rmpv::Value;

/// One identity's facts, read from its live `channel_identity.*` heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityFacts {
    pub channel: String,
    pub auth_mode: String,
    pub address_or_handle: String,
    pub shape: ChannelIdentityShape,
    pub binding: ChannelIdentityBinding,
    pub state: ChannelIdentityState,
    pub pending_fulfillment: Option<String>,
    pub state_changed_at: u64,
    pub quarantine_until: Option<u64>,
    /// The channel actor this identity's reputation rides on.
    pub reputation_ref: Option<EntityId>,
    pub manifest_ref: Option<EntityId>,
}

/// The facts a claim correction owns once the row has seeded them (OF-272):
/// the channel, the address and the binding. A later row write keeps
/// whatever head of these is live, so it never undoes a correction.
const CORRECTABLE_PREDICATES: [&str; 5] = [
    PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
    PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF,
];

impl ChannelIdentityFacts {
    /// What this identity can do for a message arriving now (OF-272): its
    /// state head, read on the machine of the row's custody. The row says
    /// only which machine; a claim never mints a capability. A state that
    /// machine lacks (a delegated row never rotates or quarantines) routes
    /// nothing.
    #[must_use]
    pub fn inbound_with_custody(&self, custody: &Custody) -> InboundDisposition {
        let self_held = matches!(custody, Custody::SelfHeld { .. });
        match self.state {
            ChannelIdentityState::Active => InboundDisposition::Deliver,
            ChannelIdentityState::Rotating if self_held => InboundDisposition::Deliver,
            ChannelIdentityState::Released => InboundDisposition::DeliverRetiring,
            ChannelIdentityState::Quarantine if self_held => InboundDisposition::DeliverRetiring,
            ChannelIdentityState::Requested | ChannelIdentityState::PendingFulfillment => {
                InboundDisposition::NotYetRoutable
            }
            ChannelIdentityState::Tombstone
            | ChannelIdentityState::Rotating
            | ChannelIdentityState::Quarantine => InboundDisposition::Closed,
        }
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("channel identity claim heads")
}

/// The identity's facts from its live heads, or `None` when it has none. A
/// missing or doubled head in a family that has heads fails closed.
pub(crate) fn channel_identity_facts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
) -> Result<Option<ChannelIdentityFacts>> {
    let heads = live_heads_in_txn(store, txn, identity_ref)?;
    if heads.is_empty() {
        return Ok(None);
    }
    let value = |predicate: &str| {
        heads
            .get(predicate)
            .map(|(_, body)| &body.value)
            .ok_or_else(corrupt)
    };
    let text = |predicate: &str| -> Result<String> {
        value(predicate)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(corrupt)
    };
    let facet_ref =
        decode_optional_entity_ref(value(PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF)?)?;
    Ok(Some(ChannelIdentityFacts {
        channel: text(PREDICATE_CHANNEL_IDENTITY_CHANNEL)?,
        auth_mode: text(PREDICATE_CHANNEL_IDENTITY_AUTH_MODE)?,
        address_or_handle: text(PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE)?,
        shape: ChannelIdentityShape::parse(&text(PREDICATE_CHANNEL_IDENTITY_SHAPE)?)
            .ok_or_else(corrupt)?,
        binding: decode_binding(
            &text(PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE)?,
            value(PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET)?,
            facet_ref,
        )?,
        state: ChannelIdentityState::parse(&text(PREDICATE_CHANNEL_IDENTITY_STATE)?)
            .ok_or_else(corrupt)?,
        pending_fulfillment: match value(PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT)? {
            Value::Nil => None,
            other => Some(other.as_str().ok_or_else(corrupt)?.to_owned()),
        },
        state_changed_at: value(PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT)?
            .as_u64()
            .ok_or_else(corrupt)?,
        quarantine_until: match value(PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL)? {
            Value::Nil => None,
            other => Some(other.as_u64().ok_or_else(corrupt)?),
        },
        reputation_ref: decode_optional_entity_ref(value(
            PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
        )?)?,
        manifest_ref: decode_optional_entity_ref(value(PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF)?)?,
    }))
}

/// Each live head of the identity's family: Active and not stale.
fn for_each_live_head(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
    mut visit: impl FnMut(EntityId, ClaimBody) -> Result<()>,
) -> Result<()> {
    for entry in store.port_edges(
        txn,
        identity_ref,
        EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let claim_id = entry?.target;
        let Some(raw) = store.port_entity_record(txn, &claim_id)? else {
            continue;
        };
        if raw.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw.body, true)?;
        if !is_channel_identity_claim_predicate(&body.predicate)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
        {
            continue;
        }
        visit(claim_id, body)?;
    }
    Ok(())
}

/// The family's live heads by predicate: Active and not stale, one each.
fn live_heads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
) -> Result<BTreeMap<String, (EntityId, ClaimBody)>> {
    let mut heads = BTreeMap::new();
    for_each_live_head(store, txn, identity_ref, |claim_id, body| {
        if heads
            .insert(body.predicate.clone(), (claim_id, body))
            .is_some()
        {
            return Err(Error::CorruptedIndex(
                "channel identity claim family has two live heads for one predicate",
            ));
        }
        Ok(())
    })?;
    Ok(heads)
}

/// Every live channel head's value and every live address head's value, for
/// the assignment re-key (OF-272). Unlike the fact reader this takes a
/// doubled head as it is: a correction made across transactions holds two
/// until its old head closes, and the caller decides what that settles.
pub(super) fn assignment_heads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
) -> Result<(Vec<String>, Vec<String>)> {
    let (mut channels, mut addresses) = (Vec::new(), Vec::new());
    for_each_live_head(store, txn, identity_ref, |_, body| {
        let values = match body.predicate.as_str() {
            PREDICATE_CHANNEL_IDENTITY_CHANNEL => &mut channels,
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => &mut addresses,
            _ => return Ok(()),
        };
        values.push(body.value.as_str().ok_or_else(corrupt)?.to_owned());
        Ok(())
    })?;
    Ok((channels, addresses))
}

impl Vault {
    /// The identity's facts, read from its `channel_identity.*` heads.
    pub fn channel_identity_facts(
        &self,
        identity_ref: &EntityId,
    ) -> Result<Option<ChannelIdentityFacts>> {
        let txn = self.store.env.read_txn()?;
        channel_identity_facts_in_txn(&self.store, &txn, identity_ref)
    }

    /// Moves the identity's `channel_identity.*` heads to `identity`, in the
    /// transaction that writes its row. A head already holding the value is
    /// left alone; every other predicate gets a new head that supersedes the
    /// old, so the family never holds two live heads for one predicate. The
    /// row only seeds the channel, address and binding: once one of those has
    /// a live head, a claim correction owns it and this write keeps it.
    pub(super) fn supersede_channel_identity_claim_heads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        identity_ref: &EntityId,
        identity: &ChannelIdentity,
        now: u64,
    ) -> Result<()> {
        let live = live_heads_in_txn(&self.store, &*wtxn, identity_ref)?;
        for body in identity.claim_bodies(*identity_ref)? {
            let existing = live.get(&body.predicate);
            if existing.is_some_and(|(_, head)| {
                head.value == body.value
                    || CORRECTABLE_PREDICATES.contains(&body.predicate.as_str())
            }) {
                continue;
            }
            let new_id = self.store.clock.entity_id()?;
            self.put_channel_identity_claim_in_txn(wtxn, &new_id, &body, now)?;
            if let Some((old_id, _)) = existing {
                crate::counterparty_contact::supersede_family_owned_claim_in_txn(
                    self, wtxn, &new_id, old_id, now,
                )?;
            }
        }
        Ok(())
    }

    /// The family-owned door for one `channel_identity.*` head, on the
    /// engine-owned setting: the identity door already validated the row.
    fn put_channel_identity_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        now: u64,
    ) -> Result<()> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvalidClaimBody(
                "channel_identity claim subject must be an entity",
            ));
        };
        let data = crate::claim::encode_claim_body(body)?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![
                BatchOp::Put {
                    id: *id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: true,
                    hub_sync_imported: false,
                },
                BatchOp::Edge {
                    src: *id,
                    kind: EdgeKind::ClaimOf,
                    tgt: subject,
                    weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                    vad: crate::affect::Vad::NEUTRAL,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}
