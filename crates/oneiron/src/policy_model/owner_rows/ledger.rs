//! Append-only row change history and proposal inbox. All rows are local vault metadata.
use serde::{Deserialize, Serialize};

use super::notifications::PolicyNotificationTarget;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::batch::secret_scan::admit_typed;
use crate::check_in::CheckInDecision;
use crate::error::{Error, GateError, Result};
use crate::gate::{PolicyRowChange, PolicyRowScope};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

const SEQUENCE: &[u8] = b"owner_policy:change:seq:v1";
const RECEIPT: &[u8] = b"owner_policy:change:receipt:v1:";
const EVENT: &[u8] = b"owner_policy:change:event:v1:";
const PROPOSAL: &[u8] = b"owner_policy:change:proposal:v1:";
/// Where the side-row wall says it found a secret in a ruling (OF-067).
const RECEIPT_PLACE: &str = "side:OWNER_POLICY_CHANGE_RECEIPT";
/// Where the side-row wall says it found a secret in a proposal (OF-067).
const PROPOSAL_PLACE: &str = "side:OWNER_POLICY_CHANGE_PROPOSAL";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRowReceipt {
    pub receipt_id: String,
    pub revision: u64,
    pub author: String,
    pub change: PolicyRowChange,
    /// The prior holder ruling on this exact row/scope, retained for one-step reverts.
    pub previous_receipt_id: Option<String>,
    pub at: u64,
    /// The check-in decision the change ran on (2k4; P25-SHAPE Q1 = A): the
    /// vault's Owner on their own proof, naming the asker's approved
    /// check-in it applied. Absent on another holder's change and on a
    /// receipt kept before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
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

#[doc(hidden)]
pub use oneiron_records::policy_model::owner_rows::ledger::PolicyProposalStatus;

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
    check_in: Option<CheckInDecision>,
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
    let mut receipt = PolicyRowReceipt {
        receipt_id: id.clone(),
        revision: next,
        author: author.to_hex(),
        change,
        previous_receipt_id,
        at: now,
        check_in,
    };
    // OF-067: the owner's row text and reasons as the side-row wall keeps them.
    let receipt_key = [RECEIPT, &next.to_be_bytes()].concat();
    put_receipt_in(vault, txn, &receipt_key, &mut receipt)?;
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
    vault
        .store
        .vault_meta
        .put(txn, &key(EVENT, &id), &encode(&event)?)?;
    Ok(receipt)
}

/// Writes `receipt` at `row_key` as the side-row wall keeps it (OF-067), and
/// `receipt` takes its handles; `true` when the wall placed one.
fn put_receipt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row_key: &[u8],
    receipt: &mut PolicyRowReceipt,
) -> Result<bool> {
    let placed = admit_typed(vault, txn, (RECEIPT_PLACE, row_key), receipt)?;
    vault
        .store
        .vault_meta
        .put(txn, row_key, &encode(&*receipt)?)?;
    Ok(placed)
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

/// Whether the shared typed event stream holds an event for `receipt_id`, in the caller's
/// snapshot: the companion check for an applied unanimity turn-off, whose settlement names
/// the row-change event its landing wrote.
pub(super) fn policy_change_event_exists_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<bool> {
    EVENTS.contains(&vault.store, txn, &receipt_id.to_owned())
}

/// The change receipts, bound through the declared table, for the actor
/// erase's rewrite. Key: the u64be sequence.
const RECEIPTS: SideTable<u64, Vec<u8>, Raw> =
    SideTable::new(&side_table::OWNER_POLICY_CHANGE_RECEIPT);

/// The hard erase's actor scrub over the change receipts (review round 1 of
/// #8085: an erased asker stayed named; FIX
/// [CHECK-IN-POLICY-RECEIPT-REQUESTER-UNSCRUBBED]). A receipt whose check-in
/// decision names `actor` as the asker whose approved check-in the Owner
/// applied keeps its ruling, its author and its decision, and the asker
/// becomes [`ERASED_CALL_IDENTITY`], as a shared act's decision does. A
/// restore's actor sweep runs it again over the restored receipts.
///
/// # Errors
///
/// A stored receipt that does not read; storage errors.
pub(crate) fn erase_change_receipt_requester_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let actor_hex = actor.to_hex();
    for (sequence, raw) in RECEIPTS.scan(&vault.store, wtxn)? {
        let mut receipt: PolicyRowReceipt = decode(&raw)?;
        let Some(requester) = receipt
            .check_in
            .as_mut()
            .and_then(|decision| decision.requester.as_mut())
        else {
            continue;
        };
        if *requester == actor_hex || EntityId::from_hex(requester).is_ok_and(|id| id == *actor) {
            ERASED_CALL_IDENTITY.clone_into(requester);
            RECEIPTS.put(&vault.store, wtxn, &sequence, &encode(&receipt)?)?;
        }
    }
    Ok(())
}

/// Every landed ruling in ledger order: the immutable receipts a queued
/// notice is delivered against (FIX 10031).
pub(super) fn read_receipts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<PolicyRowReceipt>> {
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

/// Writes `proposal` as the side-row wall keeps it (OF-067), and `proposal`
/// takes its handles; `true` when the wall placed one.
pub(super) fn put_proposal_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &mut PolicyRowProposal,
) -> Result<bool> {
    let row_key = key(PROPOSAL, &proposal.proposal_id);
    let placed = admit_typed(vault, txn, (PROPOSAL_PLACE, row_key.as_slice()), proposal)?;
    vault
        .store
        .vault_meta
        .put(txn, &row_key, &encode(proposal)?)?;
    Ok(placed)
}

/// A stored row that does not read as `T`, or is gone: no door of this
/// ledger wrote it.
fn stored_in<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row_key: &[u8],
) -> Result<Option<T>> {
    Ok(vault
        .store
        .vault_meta
        .get(txn, row_key)?
        .and_then(|raw| rmp_serde::from_slice(&raw).ok()))
}

/// The refusal of a masked copy that would change what the row is: its ids,
/// author, holders, status, time or previous link.
fn kept_or_refused(kept: bool) -> Result<()> {
    if kept {
        return Ok(());
    }
    Err(Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["gate.secret_scan.detected"],
    }))
}

impl Vault {
    /// The lift sweep's door for a stored ruling or proposal (OF-067): the row
    /// at `row_key`, its whole key, is written again through the door its own
    /// write took, at the same place and key, so each secret the wall places
    /// goes to custody and leaves its handle. The ruling is not applied again
    /// and no sequence, event or notification is written. Its id, revision,
    /// author, holders, status, time and previous link stay; a masked copy
    /// that would change one refuses as a hit the wall cannot place. `None`
    /// when no ruling or proposal reads there; `Some(true)` when a handle
    /// replaced a secret.
    pub(crate) fn lift_policy_change_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        row_key: &[u8],
    ) -> Result<Option<bool>> {
        if row_key.starts_with(RECEIPT) {
            let Some(before) = stored_in::<PolicyRowReceipt>(self, txn, row_key)? else {
                return Ok(None);
            };
            let mut receipt = before.clone();
            let placed = put_receipt_in(self, txn, row_key, &mut receipt)?;
            kept_or_refused(
                receipt.receipt_id == before.receipt_id
                    && receipt.revision == before.revision
                    && receipt.author == before.author
                    && receipt.previous_receipt_id == before.previous_receipt_id
                    && receipt.at == before.at,
            )?;
            return Ok(Some(placed));
        }
        if row_key.starts_with(PROPOSAL) {
            let Some(before) = stored_in::<PolicyRowProposal>(self, txn, row_key)?
                .filter(|proposal| key(PROPOSAL, &proposal.proposal_id) == row_key)
            else {
                return Ok(None);
            };
            let mut proposal = before.clone();
            let placed = put_proposal_in(self, txn, &mut proposal)?;
            kept_or_refused(
                proposal.proposal_id == before.proposal_id
                    && proposal.author == before.author
                    && proposal.holders == before.holders
                    && proposal.status == before.status
                    && proposal.at == before.at,
            )?;
            return Ok(Some(placed));
        }
        Ok(None)
    }

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
        // Person tier: a holder reads the proposals addressed to them.
        let holder_actor = holder.revalidate_person_in_txn(self, &txn)?;
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, PROPOSAL)? {
            let (_, value) = entry?;
            let proposal: PolicyRowProposal = decode(&value)?;
            if matches!(proposal.status, PolicyProposalStatus::Pending)
                && proposal.holders.contains(&holder_actor.to_hex())
                && super::holders_for_change_in_txn(self, &txn, &proposal.change, now)?
                    .contains(&holder_actor)
            {
                rows.push(proposal);
            }
        }
        Ok(rows)
    }
}

/// Lands one archived `OWNER_POLICY_CHANGE_EVENT` envelope in `txn`: canonical outer decode
/// and the credential predicate, then the embedded event's own canonical round-trip with its
/// key naming its receipt id. No ruling, receipt, sequence row or notification is written.
///
/// # Errors
/// Storage faults; validation stays in the returned outcome.
fn land_archived_policy_change_event_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, value) = match decode_archived_row(&EVENTS, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    let event: PolicyChangedEvent = match decode(&value) {
        Ok(event) => event,
        Err(_) => {
            return Ok(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::InvalidEncoding,
            ));
        }
    };
    let canonical = match encode(&event) {
        Ok(canonical) => canonical,
        Err(_) => {
            return Ok(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::InvalidEncoding,
            ));
        }
    };
    if canonical != value || key != event.receipt_id {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidEncoding,
        ));
    }
    if event.kind.is_empty()
        || EntityId::from_hex(&event.receipt_id).is_err()
        || EntityId::from_hex(&event.author).is_err()
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    install_archived_row(&EVENTS, vault, txn, permit, &key, row)
}

impl Vault {
    /// Lands the owner's archived owner-policy envelopes in dependency order, one outcome
    /// per input row: change events, the secret-scan mode and receipts, and world-privacy
    /// receipts first; then the widen-unanimity row; then world-privacy requests; then
    /// unanimity turn-offs. A row whose companion landed
    /// earlier in this same pass sees it: an applied request names a world-privacy receipt,
    /// and an applied turn-off names a change event. An absent row installs, an identical
    /// row is unchanged, and a different row stays live. No ruling, settings change, wait
    /// settlement, signal or notification is written here: the mode lands without minting
    /// its receipt, event or lift run; pending asks wait for the holders' next answer; and
    /// the ledger's `SEQUENCE` allocates ruling revisions, not event keys, so no counter is
    /// repaired.
    ///
    /// # Errors
    /// Storage faults; validation stays in the returned outcomes.
    pub(crate) fn land_archived_policy_model_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &OwnerArchiveRestorePermit,
        rows: &[ArchiveRetainedSideRow],
    ) -> Result<Vec<ArchivedSideRowOutcome>> {
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by_key(|&index| policy_model_land_rank(&rows[index].source_table));
        let mut landed: Vec<(usize, ArchivedSideRowOutcome)> = Vec::with_capacity(rows.len());
        for index in order {
            let row = &rows[index];
            let outcome = match row.source_table.as_str() {
                name if name == side_table::OWNER_POLICY_CHANGE_EVENT.name => {
                    land_archived_policy_change_event_row_in_txn(vault, txn, permit, row)?
                }
                name if name == side_table::OWNER_POLICY_SECRET_SCAN_MODE.name => {
                    super::secret_scan_switch::land_archived_secret_scan_mode_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                name if name == side_table::OWNER_POLICY_SECRET_SCAN_RECEIPT.name => {
                    super::secret_scan_switch::land_archived_secret_scan_receipt_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_RECEIPT.name => {
                    super::world_privacy_switch::land_archived_world_privacy_receipt_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY.name => {
                    super::world_privacy_will::unanimity::land_archived_unanimity_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_REQUEST.name => {
                    super::world_privacy_will::record::land_archived_world_privacy_request_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF.name => {
                    super::world_privacy_will::unanimity::land_archived_unanimity_off_row_in_txn(
                        vault, txn, permit, row,
                    )?
                }
                // The dispatcher never sends a foreign envelope here; without an
                // owning table the envelope has no decoding.
                _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
            };
            landed.push((index, outcome));
        }
        landed.sort_by_key(|(index, _)| *index);
        Ok(landed.into_iter().map(|(_, outcome)| outcome).collect())
    }
}

/// The landing rank of one PolicyModel envelope: companions before the rows that name
/// them (receipts and change events before requests and turn-offs, the unanimity row
/// before the turn-offs that land it); any unknown envelope last.
fn policy_model_land_rank(source_table: &str) -> u8 {
    match source_table {
        name if name == side_table::OWNER_POLICY_CHANGE_EVENT.name => 0,
        name if name == side_table::OWNER_POLICY_SECRET_SCAN_MODE.name => 1,
        name if name == side_table::OWNER_POLICY_SECRET_SCAN_RECEIPT.name => 2,
        name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_RECEIPT.name => 3,
        name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY.name => 4,
        name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_REQUEST.name => 5,
        name if name == side_table::OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF.name => 6,
        _ => 7,
    }
}
