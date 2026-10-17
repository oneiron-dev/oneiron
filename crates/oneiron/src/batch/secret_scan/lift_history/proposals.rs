//! Closing a lift proposal (OF-067). The owner closes one with a reason, and
//! a proposal closes on its own once its row reads clean: a later run reads
//! the row and finds no hit, the owner answered each key the sweep lifted out
//! of the record through a found-key door, or the row is gone. A closed
//! proposal is kept: it keeps its cause and gains when, by whom and why it
//! closed. None of it holds a value.

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::{
    LiftCause, LiftCloseReason, LiftFamily, PROPOSALS, SecretLiftHistoryProposal, attempts,
    carriers, hex, prefix_end, proposal_key, records, side_rows,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::secret_custody::FoundKeyAction;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

/// The reasons the owner's close takes (CALLS, open): what the sweep found is
/// no secret, the value was rotated or revoked where it is issued, or the
/// owner keeps the row as it stands. The reasons a proposal closes on its own
/// are the sweep's to give.
const OWNER_REASONS: [LiftCloseReason; 3] = [
    LiftCloseReason::NotASecret,
    LiftCloseReason::Rotated,
    LiftCloseReason::Accepted,
];

/// What closes a proposal on its own (CALLS, open): a later run reads its row
/// clean, the owner answered the record's found keys with one of [`ANSWERS`],
/// or the row is gone. A `file` or `history` proposal's row keeps the value
/// by design, so only an answer or a delete closes it.
const AUTO_CLOSE: [LiftCloseReason; 3] = [
    LiftCloseReason::ReadClean,
    LiftCloseReason::Answered,
    LiftCloseReason::Deleted,
];

/// The found-key answers that settle a key for good, part of the auto-close
/// call: a grant leaves the value live where the record keeps it.
const ANSWERS: [FoundKeyAction; 3] = [
    FoundKeyAction::Rotate,
    FoundKeyAction::Delete,
    FoundKeyAction::NotASecret,
];

/// `closed_by` of a proposal that closed on its own.
const CLOSED_BY_SWEEP: &str = "sweep";

/// The Gate content kind of the owner's close.
const CLOSE_CONTENT_KIND: &str = "secret_lift_proposal";

/// Gate reason code: the owner closed a lift proposal.
const REASON_CLOSED: &str = "gate.secret_lift.proposal_closed";

/// The rows of `family` a census page read, past `after` up to `next` (to
/// the family's end when `None`), that hold an open proposal of the row's own
/// (not a `history` one): the walk settles each again, so one that reads
/// clean closes.
pub(super) fn open_in_page(
    vault: &Vault,
    txn: &RoTxn<'_>,
    family: LiftFamily,
    after: &[u8],
    next: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    let prefix = own_key(family, &[]);
    let lower = [prefix.as_slice(), after].concat();
    let start = if after.is_empty() {
        Bound::Included(&lower)
    } else {
        Bound::Excluded(&lower)
    };
    let upper = next.map(|next| [prefix.as_slice(), next].concat());
    let family_end = prefix_end(&prefix);
    let end = match (&upper, &family_end) {
        (Some(upper), _) => Bound::Included(upper),
        (None, Some(end)) => Bound::Excluded(end),
        (None, None) => Bound::Unbounded,
    };
    let mut keys = Vec::new();
    for row in PROPOSALS.iter_range(&vault.store, txn, start, end)? {
        let (row_key, held) = row?;
        if held.is_open()
            && let Some(key) = row_key.get(prefix.len()..)
        {
            keys.push(key.to_vec());
        }
    }
    Ok(keys)
}

/// Closes the open proposal `key`'s row holds of its own once the row reads
/// clean: `read_clean`, or `deleted` when it is gone. `true` when one closed.
pub(super) fn close_clean_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    family: LiftFamily,
    key: &[u8],
) -> Result<bool> {
    let row_key = own_key(family, key);
    let Some(held) = PROPOSALS.get_lenient(&vault.store, txn, &row_key)? else {
        return Ok(false);
    };
    if !held.is_open() {
        return Ok(false);
    }
    let reason = if row_exists(vault, txn, family, key)? {
        LiftCloseReason::ReadClean
    } else {
        LiftCloseReason::Deleted
    };
    if !AUTO_CLOSE.contains(&reason) {
        return Ok(false);
    }
    close_in_txn(
        vault,
        txn,
        &row_key,
        held,
        reason,
        CLOSED_BY_SWEEP.to_owned(),
        None,
    )?;
    Ok(true)
}

/// Closes each open proposal whose row is gone, and each `file` or
/// `history` proposal whose record's found keys the owner answered. Each
/// housekeeping pass runs it, with or without a run; the rows are read again
/// in the transaction that closes them.
pub(super) fn review(vault: &Vault) -> Result<()> {
    let due = {
        let txn = vault.store.env.read_txn()?;
        let mut due = Vec::new();
        for row in PROPOSALS.iter_raw_from(&vault.store, &txn, &[])? {
            let (row_key, bytes) = row?;
            // A row that does not decode is left to the walk, which files
            // it again.
            let Ok(held) = PROPOSALS.decode_value(&bytes) else {
                continue;
            };
            if held.is_open()
                && let Some(reason) = settled(vault, &txn, &row_key, &held)?
            {
                due.push((row_key, reason));
            }
        }
        due
    };
    if due.is_empty() {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    let mut closed = false;
    for (row_key, reason) in due {
        let Some(held) = PROPOSALS.get_lenient(&vault.store, &txn, &row_key)? else {
            continue;
        };
        if !held.is_open() || settled(vault, &txn, &row_key, &held)? != Some(reason) {
            continue;
        }
        close_in_txn(
            vault,
            &mut txn,
            &row_key,
            held,
            reason,
            CLOSED_BY_SWEEP.to_owned(),
            None,
        )?;
        closed = true;
    }
    if closed {
        super::notice::settle_in_txn(vault, &mut txn)?;
    }
    txn.commit()?;
    Ok(())
}

/// Whether a closed proposal opens again when its row holds a hit again: one
/// that closed because the row read clean or was gone. The owner's close and
/// a found-key answer stand.
pub(super) fn reopens(held: &SecretLiftHistoryProposal) -> bool {
    matches!(
        held.close_reason,
        Some(LiftCloseReason::ReadClean | LiftCloseReason::Deleted)
    )
}

/// An open proposal its row's door now gives another cause or reason takes
/// the door's word.
pub(super) fn refresh_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row_key: &[u8],
    mut held: SecretLiftHistoryProposal,
    cause: LiftCause,
    reason: &'static str,
) -> Result<()> {
    if held.cause == cause && held.proposal.detector_reason == reason {
        return Ok(());
    }
    held.cause = cause;
    reason.clone_into(&mut held.proposal.detector_reason);
    PROPOSALS.put(&vault.store, txn, &row_key.to_vec(), &held)
}

/// The owner's close of proposal `id` (its row key, as hex) for `reason`,
/// with its Gate receipt, in `txn`. `actor` is the owner the caller checked.
pub(super) fn dismiss_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    id: &str,
    reason: LiftCloseReason,
) -> Result<SecretLiftHistoryProposal> {
    if !OWNER_REASONS.contains(&reason) {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "the owner closes a lift proposal as not_a_secret, rotated or accepted",
        )));
    }
    let row_key = unhex(id).ok_or(Error::EntityNotFound)?;
    let held = PROPOSALS
        .get(&vault.store, txn, &row_key)?
        .ok_or(Error::EntityNotFound)?;
    if !held.is_open() {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "this lift proposal is already closed",
        )));
    }
    let decision = receipt_in_txn(vault, txn, actor, &row_key, &held, reason)?;
    close_in_txn(
        vault,
        txn,
        &row_key,
        held,
        reason,
        actor.to_hex(),
        Some(format!("gate:{}", decision.to_hex())),
    )
}

/// The key of the proposal a row holds of its own, not a `history` one.
fn own_key(family: LiftFamily, key: &[u8]) -> Vec<u8> {
    proposal_key(family, LiftCause::Unplaceable, key)
}

/// Why an open proposal closes on its own now, short of a run reading its
/// row: the row is gone, or the record's found keys are answered.
fn settled(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row_key: &[u8],
    held: &SecretLiftHistoryProposal,
) -> Result<Option<LiftCloseReason>> {
    let Some(key) = row_key.get(held.family.code().len() + 2..) else {
        return Ok(None);
    };
    let reason = if !row_exists(vault, txn, held.family, key)? {
        Some(LiftCloseReason::Deleted)
    } else if held.family == LiftFamily::Records
        && matches!(held.cause, LiftCause::File | LiftCause::History)
        && answered(vault, txn, key)?
    {
        Some(LiftCloseReason::Answered)
    } else {
        None
    };
    Ok(reason.filter(|reason| AUTO_CLOSE.contains(reason)))
}

/// Whether the owner answered each key a mask lifted out of record `key`
/// with one of [`ANSWERS`].
fn answered(vault: &Vault, txn: &RoTxn<'_>, key: &[u8]) -> Result<bool> {
    let Some(record) = records::record_id(key) else {
        return Ok(false);
    };
    let actions = crate::secret_custody::found_key_actions_in_txn(&vault.store, txn, &record)?;
    Ok(!actions.is_empty()
        && actions
            .iter()
            .all(|action| action.is_some_and(|action| ANSWERS.contains(&action))))
}

fn row_exists(vault: &Vault, txn: &RoTxn<'_>, family: LiftFamily, key: &[u8]) -> Result<bool> {
    match family {
        LiftFamily::Records => records::exists(vault, txn, key),
        LiftFamily::Attempts => attempts::exists(vault, txn, key),
        LiftFamily::SideRows => side_rows::exists(vault, txn, key),
        LiftFamily::Carriers => Ok(carriers::stored(vault, txn, key)?.is_some()),
    }
}

/// Stamps `held` closed and stores it.
fn close_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row_key: &[u8],
    mut held: SecretLiftHistoryProposal,
    reason: LiftCloseReason,
    by: String,
    receipt: Option<String>,
) -> Result<SecretLiftHistoryProposal> {
    held.id = hex(row_key);
    held.closed_at = Some(crate::ports::recorded_at_in_txn(&vault.store, txn)?);
    held.closed_by = Some(by);
    held.close_reason = Some(reason);
    held.close_receipt = receipt;
    PROPOSALS.put(&vault.store, txn, &row_key.to_vec(), &held)?;
    Ok(held)
}

/// Appends the owner's close to the Gate receipt family: the proposal, its
/// row's path, its cause and the reason. No value, no digest.
fn receipt_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    row_key: &[u8],
    held: &SecretLiftHistoryProposal,
    reason: LiftCloseReason,
) -> Result<GateDecisionId> {
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![REASON_CLOSED.into()],
        receipt_reasons: vec![
            format!("proposal:{}", hex(row_key)),
            format!("path:{}", held.proposal.path),
            format!("cause:{}", held.cause.code()),
            format!("close:{}", reason.code()),
        ],
        system_notices: Vec::new(),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: CLOSE_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: row_key.to_vec(),
        read_frontier_hash: [0; 32],
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}

/// Lowercase or uppercase hex as bytes; `None` for anything else.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}
