//! Append-only channel-identity lifecycle receipt ledger. (Distinct from
//! the top-level `channel_identity_lifecycle` module, which consumes it.)

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideKey, SideTable};

use super::*;

const CHANNEL_IDENTITY_LIFECYCLE_LEDGER_VERSION: u8 = 0;

/// Typed door for the append-only channel-identity lifecycle receipt ledger.
const RECEIPTS: SideTable<
    ChannelIdentityLifecycleReceiptId,
    ChannelIdentityLifecycleReceiptRecord,
    Named,
> = SideTable::new(&side_table::CHANNEL_IDENTITY_LIFECYCLE_RECEIPT);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelIdentityLifecycleReceiptId {
    bytes: [u8; 16],
}

impl SideKey for ChannelIdentityLifecycleReceiptId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            bytes: bytes.try_into().ok()?,
        })
    }
}

impl ChannelIdentityLifecycleReceiptId {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }
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
        crate::ports::recorded_at_in_txn(self, wtxn)?;
        vet_channel_identity_lifecycle_receipt_record(record)?;
        if RECEIPTS.contains(self, wtxn, &record.receipt_id)? {
            return Err(Error::InvariantViolation(
                "channel identity lifecycle receipt id collision",
            ));
        }
        RECEIPTS.put(self, wtxn, &record.receipt_id, record)?;
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
        let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
        for row in RECEIPTS.iter_rev_from(self, &rtxn, &[])? {
            let (receipt_id, record) = row?;
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
