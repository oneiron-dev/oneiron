//! Append-only row change history and proposal inbox. All rows are local vault metadata.
use serde::{Deserialize, Serialize};

use super::notifications::PolicyNotificationTarget;
use crate::error::{Error, Result};
use crate::gate::{PolicyRowChange, PolicyRowScope};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

const SEQUENCE: &[u8] = b"owner_policy:change:seq:v1";
const RECEIPT: &[u8] = b"owner_policy:change:receipt:v1:";
const EVENT: &[u8] = b"owner_policy:change:event:v1:";
const PROPOSAL: &[u8] = b"owner_policy:change:proposal:v1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRowReceipt {
    pub receipt_id: String,
    pub revision: u64,
    pub author: String,
    pub change: PolicyRowChange,
    /// The prior holder ruling on this exact row/scope, retained for one-step reverts.
    pub previous_receipt_id: Option<String>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangedEvent {
    pub kind: String,
    pub receipt_id: String,
    pub author: String,
    pub scope: Option<PolicyRowScope>,
    /// Notification-rule events name a rule target instead of pretending to
    /// name one world or project row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PolicyNotificationTarget>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProposalStatus {
    Pending,
    Approved { receipt_id: String, holder: String },
    Declined { holder: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRowProposal {
    pub proposal_id: String,
    pub author: String,
    pub change: PolicyRowChange,
    pub holders: Vec<String>,
    pub status: PolicyProposalStatus,
    pub at: u64,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("owner policy ledger encode"))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("owner policy ledger"))
}
fn key(prefix: &[u8], id: &str) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}

pub(super) fn append_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    author: EntityId,
    change: PolicyRowChange,
    now: u64,
) -> Result<PolicyRowReceipt> {
    let next = match vault.store.vault_meta.get(txn, SEQUENCE)? {
        None => 1,
        Some(raw) => u64::from_be_bytes(
            raw.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("owner policy sequence"))?,
        )
        .checked_add(1)
        .ok_or(Error::InvariantViolation("owner policy sequence overflow"))?,
    };
    let id = vault.store.clock.entity_id()?.to_hex();
    let mut previous_receipt_id = None;
    for old in read_receipts_in(vault, txn)? {
        if old.change.row_ref() == change.row_ref() && old.change.scope() == change.scope() {
            previous_receipt_id = Some(old.receipt_id);
        }
    }
    let receipt = PolicyRowReceipt {
        receipt_id: id.clone(),
        revision: next,
        author: author.to_hex(),
        change,
        previous_receipt_id,
        at: now,
    };
    let event = PolicyChangedEvent {
        kind: "policy.changed".to_owned(),
        receipt_id: id.clone(),
        author: receipt.author.clone(),
        scope: Some(receipt.change.scope().clone()),
        target: None,
        at: now,
    };
    vault
        .store
        .vault_meta
        .put(txn, SEQUENCE, &next.to_be_bytes())?;
    vault.store.vault_meta.put(
        txn,
        &[RECEIPT, &next.to_be_bytes()].concat(),
        &encode(&receipt)?,
    )?;
    vault
        .store
        .vault_meta
        .put(txn, &key(EVENT, &id), &encode(&event)?)?;
    Ok(receipt)
}

/// The shared typed event stream, bound through the declared table. Key: the
/// receipt id.
const EVENTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::OWNER_POLICY_CHANGE_EVENT);

/// One event on the shared typed stream, for an owner change that keeps its
/// receipts in a family of its own.
pub(super) fn put_event_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event: &PolicyChangedEvent,
) -> Result<()> {
    EVENTS.put(&vault.store, txn, &event.receipt_id, &encode(event)?)
}

fn read_receipts_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<PolicyRowReceipt>> {
    let mut rows = Vec::new();
    for entry in vault.store.vault_meta.prefix_iter(txn, RECEIPT)? {
        let (_, value) = entry?;
        rows.push(decode(&value)?);
    }
    Ok(rows)
}

pub(super) fn read_proposal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> Result<Option<PolicyRowProposal>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(PROPOSAL, id))?
        .map(|raw| decode(&raw))
        .transpose()
}

pub(super) fn put_proposal_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &PolicyRowProposal,
) -> Result<()> {
    vault.store.vault_meta.put(
        txn,
        &key(PROPOSAL, &proposal.proposal_id),
        &encode(proposal)?,
    )?;
    Ok(())
}

impl Vault {
    /// Every landed ruling in ledger order, including ones superseded by a later holder.
    pub fn policy_row_change_log(&self) -> Result<Vec<PolicyRowReceipt>> {
        let txn = self.store.env.read_txn()?;
        read_receipts_in(self, &txn)
    }

    /// Exactly one typed event is stored for every landed change.
    pub fn policy_changed_events(&self) -> Result<Vec<PolicyChangedEvent>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, EVENT)? {
            let (_, value) = entry?;
            rows.push(decode(&value)?);
        }
        Ok(rows)
    }

    /// Pending proposals addressed to a live policy-power holder.
    pub fn policy_row_proposals_for(
        &self,
        holder: &crate::consent::AuthenticatedOwner,
        now: u64,
    ) -> Result<Vec<PolicyRowProposal>> {
        let txn = self.store.env.read_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, PROPOSAL)? {
            let (_, value) = entry?;
            let proposal: PolicyRowProposal = decode(&value)?;
            if matches!(proposal.status, PolicyProposalStatus::Pending)
                && proposal.holders.contains(&holder.actor().to_hex())
                && super::holders_for_change_in_txn(self, &txn, &proposal.change, now)?
                    .contains(&holder.actor())
            {
                rows.push(proposal);
            }
        }
        Ok(rows)
    }
}
