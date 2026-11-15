//! The conflict item: the set a bound Resolution read of `ai.verdict` names,
//! opened instead of asked.
//!
//! Its operands are that read's operands: one candidate per member, exactly
//! as the verdict takes it, with the confidence and the prospective query
//! hints a kept alternative lands with, and the stored heads the set stands
//! against, each with the version the job read. A later Settle item of the
//! batch names the marker this item opens by this item's local name.
//!
//! Only a queued extraction attempt stages one: the commit's stamp must name
//! an attempt that is still in the queue as a Micro, Meso or Macro
//! consolidation attempt with a partition payload. An agent run cannot stage
//! one: its stamp carries its own run lease, which is never a queued
//! extraction branch.
//!
//! Staging rebuilds the verdict's set in the batch's write transaction and
//! hands it to native's marker builder: the verdict's read for the stamp's
//! actor, its operand checks, the shared set selection, the heads equality,
//! one verified member per selected candidate, the duplicate refusal, the
//! derive verdict over the subject, and the marker write in a savepoint.
//! Only the marker lands, exactly as native's Escalate, with derive
//! provenance and no decision memo. A refusal lands nothing, writes the
//! item's receipt, and the batch goes on; a storage error aborts the commit.

pub(super) mod inputs;

use super::batch::DerivedConflict;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn};
use super::extraction_opening::{ExtractionOpening, open_attempt, open_verdict_read};
use super::extraction_set::{RebuildInput, SetRebuildError, rebuild_conflict_set};
use super::verified_landing::{refuse, refuse_or_abort};
use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};

/// The refusal of a conflict item whose commit runs outside a queued
/// extraction attempt: it names no attempt, or its attempt is not in the
/// queue as a Micro, Meso or Macro consolidation attempt with a partition
/// payload.
pub const CONFLICT_NEEDS_EXTRACTION_ATTEMPT: &str =
    "gate.deny.derive.conflict_needs_extraction_attempt";

/// The refusal of a conflict item whose operands are not one servable native
/// conflict: a row, pin or span the extraction read does not serve this
/// actor, an operand the native checks refuse, or operands that are not
/// exactly one native conflict.
pub const CONFLICT_OPERANDS_REFUSED: &str = "gate.deny.derive.conflict_operands_refused";

/// The refusal of a conflict item whose heads differ from the rebuilt set's
/// prior heads, in order or version.
pub const CONFLICT_HEADS_DIFFER: &str = "gate.deny.derive.conflict_heads_differ";

/// The refusal of a conflict item whose set already stands opened: a row is
/// already stored at the set's marker id.
pub const CONFLICT_DUPLICATE: &str = "gate.deny.derive.conflict_duplicate";

/// The reason a landed conflict item's receipt names.
const CONFLICT_ALLOWED: &str = "gate.allow.derive.conflict";

/// Stages a conflict item: the set the bound Resolution read names, opened
/// instead of asked, in the batch's write transaction (`txn` reborrowed as a
/// read for every read). Outside a queued extraction attempt the item is
/// refused; inside one its operands are checked, its set is rebuilt with the
/// shared native code, its members are verified, and the one canonical
/// marker lands with derive provenance. Each refusal writes the item's
/// receipt and lands nothing, and the batch goes on.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit, never a refusal.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedConflict,
) -> Result<ItemOutcome> {
    let Some(attempt_id) = open_attempt(vault, txn, context.stamp)? else {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_NEEDS_EXTRACTION_ATTEMPT.to_owned()],
        );
    };
    let opening = match open_verdict_read(vault, txn, context.stamp) {
        Ok(Some(opening)) => opening,
        Ok(None) => return refuse(vault, txn, context, &[CONFLICT_OPERANDS_REFUSED.to_owned()]),
        Err(error) => {
            return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
        }
    };
    let ExtractionOpening {
        actor,
        read,
        turn_owned,
        memory,
        reader_scope,
    } = opening;
    let now_ms = context.now.saturating_mul(1_000);
    let (selected, members) = {
        let read_txn: &heed::RoTxn<'_> = txn;
        let turn_read = turn_owned.as_ref().unwrap_or(&read);
        match rebuild_conflict_set(RebuildInput {
            memory: &memory,
            read: &read,
            turn_read,
            txn: read_txn,
            reader_scope: reader_scope.as_ref(),
            attempt: attempt_id,
            members: &item.members,
            heads: &item.heads,
            set_members: item.set_members.as_deref(),
            now_ms,
        }) {
            Ok(rebuilt) => (rebuilt.selected, rebuilt.members),
            Err(SetRebuildError::Operands(error)) => {
                return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
            }
            Err(SetRebuildError::HeadsDiffer(error)) => {
                return refuse_or_abort(vault, txn, context, error, CONFLICT_HEADS_DIFFER);
            }
            Err(SetRebuildError::Abort(error)) => return Err(error),
        }
    };
    // The marker id: a row already stored at it refuses the item.
    let marker = crate::dreamer_consolidation::conflict_open_marker_id(&selected.set, attempt_id)?;
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        if vault.get_claim_in_txn(read_txn, &marker)?.is_some() {
            return refuse(vault, txn, context, &[CONFLICT_DUPLICATE.to_owned()]);
        }
    }
    // The derive verdict over the conflict's subject, as the artifact
    // profile stager takes it: the marker is new, so the subject is the
    // stored record the verdict judges.
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(selected.set.identity.subject),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, &[refusal.token().to_owned()]),
    };
    // In a savepoint: the one marker builder with derive provenance, then
    // the shared writer. A refusal of the write gate rolls the savepoint
    // back and refuses the item with the gate's reason codes, as the Claim
    // stager does for a gate refusal.
    let member_refs: Vec<_> = members.iter().collect();
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let parts = match crate::dreamer_consolidation::open_conflict::open_marker_parts(
        actor,
        attempt_id,
        &selected.set,
        &member_refs,
        inputs::derive_provenance(context, &item.local),
        now_ms,
    ) {
        Ok(parts) => parts,
        Err(error) => {
            savepoint.abort();
            return Err(error);
        }
    };
    match crate::dreamer_consolidation::open_conflict::write_open_marker_in_txn(
        vault,
        &mut savepoint,
        actor,
        parts,
        now_ms,
    ) {
        Ok(()) => savepoint.commit()?,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            savepoint.abort();
            let reasons: Vec<String> = reason_codes.iter().map(|code| (*code).to_owned()).collect();
            return refuse(vault, txn, context, &reasons);
        }
        Err(error) => {
            savepoint.abort();
            return Err(error);
        }
    }
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(marker),
        &[CONFLICT_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![marker],
        approval: None,
        receipt: Some(receipt),
    })
}
