//! Owner-enabled phone-line arrival metadata. This does not answer calls or accept audio.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::channel_identity::{ChannelIdentityFacts, InboundDisposition};
use crate::claim::ScopedRead;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use serde::{Deserialize, Serialize};

const LINES: SideTable<EntityId, PhoneLineState, Named> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_PHONE_LINE);
const ARRIVALS: SideTable<[u8; 32], StoredArrival, Named> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_PHONE_ARRIVAL);

/// The owner's explicit setting. A missing setting is off; enabling it grants no reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineConfig {
    pub enabled: bool,
    pub share_scope: Scope,
}

/// The actual identity, receiving agent and channel actor the owner configured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineState {
    pub identity_ref: EntityId,
    pub agent_ref: EntityId,
    pub bridge_actor: EntityId,
    pub owner_actor: EntityId,
    pub enabled: bool,
    /// Consent data only. A future answering reader must enforce this ceiling itself.
    pub share_scope: Scope,
    pub updated_at: u64,
}

/// Untrusted provider metadata, never a recognized person or an instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineArrival {
    pub call_id: String,
    pub caller: Option<String>,
}

/// Quarantined arrival metadata behind an opaque reference in the existing inbox queue.
/// There is no recording, transcript, answered-call or provider-identity claim here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineArrivalRecord {
    pub identity_ref: EntityId,
    pub agent_ref: EntityId,
    pub bridge_actor: EntityId,
    pub share_scope: Scope,
    pub arrival: PhoneLineArrival,
    pub received_at: u64,
    pub payload_ref: String,
    pub correlation_id: String,
    pub attempt_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PhoneLineArrivalReceipt {
    pub record: PhoneLineArrivalRecord,
    pub replayed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum StoredArrival {
    Live {
        input_digest: [u8; 32],
        record: PhoneLineArrivalRecord,
    },
    /// A retry of an erased call must not restore its private metadata.
    Erased,
}

pub(crate) fn invalid() -> Error {
    Error::InvalidConfig("phone line is absent, disabled, mismatched or unauthorized".to_owned())
}

fn live_kind(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, kind: u8) -> Result<bool> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
        return Ok(false);
    }
    let Some(raw) = vault
        .store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
    else {
        return Ok(false);
    };
    Ok(EntityMetadataHeader::parse(&raw).is_some_and(|header| header.entity_type == kind))
}

fn line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
) -> Result<(ChannelIdentityFacts, InboundDisposition, EntityId, EntityId)> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, identity_ref)?.is_live() {
        return Err(invalid());
    }
    let identity = vault
        .get_channel_identity_in_txn(txn, identity_ref)?
        .ok_or_else(invalid)?;
    if identity.is_delegated() {
        return Err(invalid());
    }
    // The body supplies custody; live claim heads own channel, address and binding.
    let facts =
        crate::channel_identity::channel_identity_facts_in_txn(&vault.store, txn, identity_ref)?
            .ok_or_else(invalid)?;
    if facts.channel != "voice" {
        return Err(invalid());
    }
    let inbound = facts.inbound_with_custody(identity.custody());
    let agent = facts.binding.actor_ref().ok_or_else(invalid)?;
    let bridge = facts.reputation_ref.ok_or_else(invalid)?;
    if !live_kind(vault, txn, &agent, ENTITY_TYPE_AGENT_DEF)?
        || !live_kind(vault, txn, &bridge, ENTITY_TYPE_MACHINE)?
        || vault
            .channel_identity_by_assignment_in_txn(txn, &facts.channel, &facts.address_or_handle)?
            .is_none_or(|(actual, _)| actual != *identity_ref)
    {
        return Err(invalid());
    }
    Ok((facts, inbound, agent, bridge))
}

impl Vault {
    /// Stores the authenticated owner's reversible setting, not an identity retirement.
    pub fn configure_phone_line(
        &self,
        owner: &AuthenticatedOwner,
        identity_ref: EntityId,
        desired: PhoneLineConfig,
    ) -> Result<PhoneLineState> {
        let now = self.store.authorization_now()?;
        let mut txn = self.store.env.write_txn()?;
        let owner_actor = owner.revalidate_in_txn(self, &txn)?;
        // Disabling an existing setting does not depend on the old bridge staying live.
        let prior = LINES.get(&self.store, &txn, &identity_ref)?;
        let (agent_ref, bridge_actor) = match prior {
            Some(prior) if !desired.enabled => (prior.agent_ref, prior.bridge_actor),
            _ => {
                let (_, _, agent, bridge) = line_in_txn(self, &txn, &identity_ref)?;
                (agent, bridge)
            }
        };
        let state = PhoneLineState {
            identity_ref,
            agent_ref,
            bridge_actor,
            owner_actor,
            enabled: desired.enabled,
            share_scope: desired.share_scope,
            updated_at: now,
        };
        LINES.put(&self.store, &mut txn, &identity_ref, &state)?;
        txn.commit()?;
        Ok(state)
    }

    /// Owner history remains readable when a line is off or retired.
    pub fn phone_line_state_as(
        &self,
        owner: &AuthenticatedOwner,
        identity_ref: EntityId,
    ) -> Result<Option<PhoneLineState>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        LINES.get(&self.store, &txn, &identity_ref)
    }

    /// Reads by the opaque payload reference kept in the inbox, never by a caller URL.
    pub fn phone_line_arrival_by_ref_as(
        &self,
        owner: &AuthenticatedOwner,
        identity_ref: EntityId,
        payload_ref: &str,
    ) -> Result<Option<PhoneLineArrivalRecord>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        Ok(
            match ARRIVALS.get(&self.store, &txn, &payload_key(payload_ref)?)? {
                Some(StoredArrival::Live { record, .. })
                    if record.identity_ref == identity_ref && record.payload_ref == payload_ref =>
                {
                    Some(record)
                }
                Some(StoredArrival::Live { .. } | StoredArrival::Erased) | None => None,
            },
        )
    }

    /// Removes the private call metadata. The queue retains only opaque refs, not caller text.
    pub fn erase_phone_line_arrival_by_ref_as(
        &self,
        owner: &AuthenticatedOwner,
        identity_ref: EntityId,
        payload_ref: &str,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let key = payload_key(payload_ref)?;
        let erased = matches!(
            ARRIVALS.get(&self.store, &txn, &key)?,
            Some(StoredArrival::Live { ref record, .. })
                if record.identity_ref == identity_ref && record.payload_ref == payload_ref
        );
        if erased {
            ARRIVALS.put(&self.store, &mut txn, &key, &StoredArrival::Erased)?;
            txn.commit()?;
        }
        Ok(erased)
    }
}

/// The read's proof and live policy are checked by the caller in this same writer.
/// This adds exact line standing; neither a DTO nor an actor-class label is a credential.
pub(crate) fn admitted_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    identity_ref: EntityId,
) -> Result<(PhoneLineState, ChannelIdentityFacts)> {
    let state = LINES
        .get(&vault.store, txn, &identity_ref)?
        .ok_or_else(invalid)?;
    let (facts, inbound, agent, bridge) = line_in_txn(vault, txn, &identity_ref)?;
    if !state.enabled
        || state.identity_ref != identity_ref
        || state.agent_ref != agent
        || state.bridge_actor != bridge
        || EntityId::from_hex(read.actor_key().actor_ref())? != bridge
        || !matches!(
            inbound,
            InboundDisposition::Deliver | InboundDisposition::DeliverRetiring
        )
    {
        return Err(invalid());
    }
    Ok((state, facts))
}

pub(crate) fn arrival_key(identity_ref: EntityId, call_id: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.phone-line.arrival.v1\0");
    hash.update(identity_ref.as_bytes());
    hash.update(&(call_id.len() as u64).to_be_bytes());
    hash.update(call_id.as_bytes());
    *hash.finalize().as_bytes()
}

fn payload_key(payload_ref: &str) -> Result<[u8; 32]> {
    let digest = payload_ref
        .strip_prefix("phone-line:arrival:")
        .ok_or_else(invalid)?;
    blake3::Hash::from_hex(digest)
        .map(|hash| *hash.as_bytes())
        .map_err(|_| invalid())
}

pub(crate) fn input_digest(arrival: &PhoneLineArrival) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(arrival).map_err(|_| invalid())?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub(crate) fn replay_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    offered: [u8; 32],
) -> Result<Option<PhoneLineArrivalReceipt>> {
    match ARRIVALS.get(&vault.store, txn, key)? {
        None => Ok(None),
        Some(StoredArrival::Live {
            input_digest,
            record,
        }) if input_digest == offered => Ok(Some(PhoneLineArrivalReceipt {
            record,
            replayed: true,
        })),
        Some(StoredArrival::Live { .. } | StoredArrival::Erased) => Err(invalid()),
    }
}

pub(crate) fn keep_arrival_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    input_digest: [u8; 32],
    record: PhoneLineArrivalRecord,
) -> Result<PhoneLineArrivalReceipt> {
    // The Named row's own wall admits foreign strings and returns the actual kept bytes.
    let bytes = ARRIVALS.put_as_stored(
        &vault.store,
        txn,
        key,
        &StoredArrival::Live {
            input_digest,
            record,
        },
    )?;
    let StoredArrival::Live { record, .. } = ARRIVALS.decode_value(&bytes)? else {
        return Err(invalid());
    };
    Ok(PhoneLineArrivalReceipt {
        record,
        replayed: false,
    })
}

/// Identity deletion removes its phone settings and private arrival metadata in that writer.
pub(crate) fn drop_identity_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    LINES.delete(store, txn, id)?;
    let mut keys = Vec::new();
    for item in ARRIVALS.iter_from(store, txn, &[])? {
        let (key, row) = item?;
        if matches!(row, StoredArrival::Live { ref record, .. } if record.identity_ref == *id) {
            keys.push(key);
        }
    }
    for key in keys {
        ARRIVALS.delete(store, txn, &key)?;
    }
    Ok(())
}

pub(crate) fn erase_line_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut lines = Vec::new();
    for item in LINES.iter_from(&vault.store, txn, &[])? {
        let (id, row) = item?;
        if row.agent_ref == *actor || row.bridge_actor == *actor || row.owner_actor == *actor {
            lines.push(id);
        }
    }
    for id in lines {
        LINES.delete(&vault.store, txn, &id)?;
    }
    Ok(())
}

pub(crate) fn erase_arrival_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut calls = Vec::new();
    for item in ARRIVALS.iter_from(&vault.store, txn, &[])? {
        let (key, row) = item?;
        if matches!(row, StoredArrival::Live { ref record, .. }
            if record.agent_ref == *actor || record.bridge_actor == *actor || record.identity_ref == *actor)
        {
            calls.push(key);
        }
    }
    for key in calls {
        ARRIVALS.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

/// The row's own native decoder remains valid when its foreign text is masked.
pub(crate) fn arrival_accepts_masked(bytes: &[u8]) -> bool {
    ARRIVALS.decode_value(bytes).is_ok()
}
