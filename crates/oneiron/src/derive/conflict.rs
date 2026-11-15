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

mod inputs;

use super::batch::DerivedConflict;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, check_engine_claim_pins, check_extraction_operands_in_txn,
    check_pack_candidates, select_routed_conflict,
};
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::verbs::CandidateOperand;
use crate::{EntityId, Vault};

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
    let Some(attempt_id) = context.stamp.attempt else {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_NEEDS_EXTRACTION_ATTEMPT.to_owned()],
        );
    };
    let attempt = EntityId::from_bytes_unchecked(*attempt_id.as_bytes());
    if crate::snapshot_read::queued_extraction_branch_opt_in_txn(vault, txn, attempt)?.is_none() {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_NEEDS_EXTRACTION_ATTEMPT.to_owned()],
        );
    }
    // The verdict's read for the stamp's actor, inside this write: the lane
    // key the verdict's read lane builds for a non-owner actor, replicated
    // without opening a transaction (the lane itself opens one), with the
    // verdict's TURN reader, authority proof and reader scope. Grant time
    // judges at the committed floor, as every other derive stager's reads do.
    let actor = context.stamp.actor;
    let Some(key) = crate::claim::ScopedReadActorKey::for_engine_actor(actor) else {
        return refuse(vault, txn, context, &[CONFLICT_OPERANDS_REFUSED.to_owned()]);
    };
    let read = vault
        .scoped_read(key.require_access_grants(Some(actor.entity_ref())))
        .with_claim_status(crate::ports::ClaimReadStatus::Recorded);
    let turn_read = match crate::snapshot_read::extraction_turn_read(&read, None) {
        Ok(turn_read) => turn_read,
        Err(error) => {
            return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
        }
    };
    let turn_read = turn_read.as_ref().unwrap_or(&read);
    let memory = vault.memory(actor.entity_ref(), actor.actor_class());
    let reader_scope = {
        let read_txn: &heed::RoTxn<'_> = txn;
        if let Err(error) = memory.prove_read_authority_in_txn(read_txn) {
            return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
        }
        match crate::snapshot_read::extraction_reader_scope_in_txn(&memory, read_txn, None) {
            Ok(scope) => scope,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
            }
        }
    };
    // The verdict's operand checks, over the members' operands with the
    // item's heads as the priors (no listed pins: a conflict asks no
    // correction read).
    let operands: Vec<CandidateOperand> = item
        .members
        .iter()
        .map(|member| member.operand.clone())
        .collect();
    let (branch, bound) = {
        let read_txn: &heed::RoTxn<'_> = txn;
        match check_extraction_operands_in_txn(
            &memory,
            &read,
            read_txn,
            reader_scope.as_ref(),
            attempt_id,
            &operands,
            Some((&[], &item.heads)),
        ) {
            Ok(checked) => checked,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
            }
        }
    };
    // The native set rebuild over the checked rows, then the shared set
    // selection with the item's selector.
    let checked = match check_pack_candidates(&operands, &bound, attempt_id, &branch) {
        Ok(checked) => checked,
        // A claim-domain failure of an operand is the request's, as the
        // Settle stager reads it; anything else is the store's.
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, &[CONFLICT_OPERANDS_REFUSED.to_owned()]);
        }
        Err(error) => return Err(error),
    };
    let selected = {
        let read_txn: &heed::RoTxn<'_> = txn;
        let rebuild = ExtractionRebuildContext {
            memory: &memory,
            read: &read,
            turn_read,
            txn: read_txn,
            operands: &operands,
        };
        match select_routed_conflict(&checked.rows, &bound, &rebuild, item.set_members.as_deref()) {
            Ok(selected) => selected,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
            }
        }
    };
    // The item's heads, in order, must equal the selected set's prior
    // heads, by the verdict's own check.
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        if let Err(error) =
            check_engine_claim_pins(&read, read_txn, &item.heads, &selected.set.prior_heads)
        {
            return refuse_or_abort(vault, txn, context, error, CONFLICT_HEADS_DIFFER);
        }
    }
    // The members: each selected proposal stamped with its item member's
    // confidence and normalised hints, then verified as native verifies it
    // at the commit's clock. The claim id does not move: the deterministic
    // id hashes only the identity axes (attempt, subject, predicate, value,
    // world, facet, relationship, project, topic), and confidence and hints
    // are not among them.
    let now_ms = context.now.saturating_mul(1_000);
    let mut members = Vec::with_capacity(selected.set.candidate_indexes.len());
    for index in &selected.set.candidate_indexes {
        let (member, proposal) = match (item.members.get(*index), selected.proposals.get(*index)) {
            (Some(member), Some(proposal)) => (member, proposal),
            _ => return refuse(vault, txn, context, &[CONFLICT_OPERANDS_REFUSED.to_owned()]),
        };
        let mut stamped = proposal.clone();
        stamped.candidate = inputs::member_candidate(
            &proposal.candidate,
            member.confidence,
            &member.prospective_queries,
        )?;
        let verified = {
            let read_txn: &heed::RoTxn<'_> = txn;
            match bound.verify_observation_candidate_in_txn(
                &memory,
                turn_read,
                read_txn,
                &member.operand,
                &stamped,
                now_ms,
            ) {
                Ok(verified) => verified,
                Err(error) => {
                    return refuse_or_abort(vault, txn, context, error, CONFLICT_OPERANDS_REFUSED);
                }
            }
        };
        members.push(verified);
    }
    // The marker id: a row already stored at it refuses the item.
    let marker = crate::dreamer_consolidation::conflict_open_marker_id(&selected.set, attempt_id)?;
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        if vault.get_claim_in_txn(read_txn, &marker)?.is_some() {
            return refuse(vault, txn, context, &[CONFLICT_DUPLICATE.to_owned()]);
        }
    }
    // The derive verdict over the conflict's subject, as the Settle stager
    // takes it.
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

/// Refuses the item with `token` for a request refusal, or aborts the commit
/// for anything else: only `BAD_REQUEST` and `FORBIDDEN` refuse. A storage
/// failure reaches here as `INTERNAL_SERVER_ERROR` (the one `From<Error>`
/// mapping), and aborts as one: there is no `From<MemoryError> for Error`,
/// so the abort carries the message as the I/O error the mapping reads as
/// internal. A receipt carries the token only: never an error message, an id
/// the actor does not read, or words of a TURN.
fn refuse_or_abort(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    error: MemoryError,
    token: &str,
) -> Result<ItemOutcome> {
    if error.code == MEMORY_CODE_BAD_REQUEST || error.code == MEMORY_CODE_FORBIDDEN {
        refuse(vault, txn, context, &[token.to_owned()])
    } else {
        Err(Error::Io(std::io::Error::other(error.to_string())))
    }
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    reasons: &[String],
) -> Result<ItemOutcome> {
    let reasons = reasons.to_vec();
    let receipt = refusal_receipt_in_txn(vault, txn, context, None, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
