//! Append-only channel-identity lifecycle receipt ledger. (Distinct from
//! the top-level `channel_identity_lifecycle` module, which consumes it.)

use std::str;

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::*;

const CHANNEL_IDENTITY_LIFECYCLE_LEDGER_VERSION: u8 = 0;

const CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX: &[u8] = b"channel_identity_lifecycle:v0:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelIdentityLifecycleReceiptId {
    bytes: [u8; 16],
}

impl ChannelIdentityLifecycleReceiptId {
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelIdentityLifecycleReceiptRecord {
    pub version: u8,
    pub receipt_id: ChannelIdentityLifecycleReceiptId,
    pub created_at: u64,
    pub identity_id: [u8; 16],
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub verb: String,
    pub intent_kind: String,
    pub outcome: String,
    pub gate_decision_id: Option<GateDecisionId>,
    pub channel: String,
    pub address_or_handle: String,
    pub state: String,
    pub fulfillment_mode: Option<String>,
    pub owner_visible_state: String,
    pub outbound_closed: bool,
    pub identity_retiring: bool,
    pub quarantine_until: Option<u64>,
}

impl Store {
    pub(crate) fn append_channel_identity_lifecycle_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &ChannelIdentityLifecycleReceiptRecord,
    ) -> Result<()> {
        vet_channel_identity_lifecycle_receipt_record(record)?;
        let key = channel_identity_lifecycle_key(record.receipt_id);
        if self.vault_meta.get(wtxn, &key)?.is_some() {
            return Err(Error::InvariantViolation(
                "channel identity lifecycle receipt id collision",
            ));
        }
        let value = encode_channel_identity_lifecycle_receipt(record)?;
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    pub fn channel_identity_lifecycle_receipts(
        &self,
        limit: usize,
    ) -> Result<Vec<ChannelIdentityLifecycleReceiptRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rtxn = self.env.read_txn()?;
        let upper = channel_identity_lifecycle_upper_bound();
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX) {
                break;
            }
            let receipt_id = channel_identity_lifecycle_id_from_key(&key)?;
            let record = decode_channel_identity_lifecycle_receipt(&value)?;
            if record.receipt_id != receipt_id {
                return Err(Error::CorruptedIndex(
                    "channel identity lifecycle ledger key mismatch",
                ));
            }
            records.push(record);
            if records.len() >= limit {
                break;
            }
        }
        Ok(records)
    }
}

fn channel_identity_lifecycle_key(receipt_id: ChannelIdentityLifecycleReceiptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX);
    key.extend_from_slice(&receipt_id.as_bytes());
    key
}

fn channel_identity_lifecycle_id_from_key(key: &[u8]) -> Result<ChannelIdentityLifecycleReceiptId> {
    let bytes = key
        .strip_prefix(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    Ok(ChannelIdentityLifecycleReceiptId { bytes })
}

fn channel_identity_lifecycle_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(CHANNEL_IDENTITY_LIFECYCLE_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("channel identity lifecycle key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("channel identity lifecycle key prefix upper bound must not overflow");
    key
}

fn encode_channel_identity_lifecycle_receipt(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("channel identity lifecycle ledger encode failed"))
}

fn decode_channel_identity_lifecycle_receipt(
    raw: &[u8],
) -> Result<ChannelIdentityLifecycleReceiptRecord> {
    let record: ChannelIdentityLifecycleReceiptRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("channel identity lifecycle ledger"))?;
    vet_channel_identity_lifecycle_receipt_record(&record)?;
    Ok(record)
}

fn vet_channel_identity_lifecycle_receipt_record(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> Result<()> {
    if record.version != CHANNEL_IDENTITY_LIFECYCLE_LEDGER_VERSION
        || record.identity_id == [0; 16]
        || record.actor_class.trim().is_empty()
        || record.verb.trim().is_empty()
        || record.intent_kind.trim().is_empty()
        || record.outcome.trim().is_empty()
        || record.channel.trim().is_empty()
        || record.address_or_handle.trim().is_empty()
        || record.state.trim().is_empty()
        || record.owner_visible_state.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("channel identity lifecycle ledger"));
    }
    Ok(())
}
