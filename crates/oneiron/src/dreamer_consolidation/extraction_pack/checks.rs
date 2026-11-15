//! Shared extraction operand checks for the verdict and the observations page.
//!
//! The verdict and the page both prove the queued branch, recheck turn evidence
//! and pins, rebuild the bound projection, and check subjects before native
//! candidate checks run. The order and refusals below match the native verdict
//! exactly, so both callers read the same rows in the same snapshot.

use super::super::ConsolidationBranchPlan;
use super::{BoundBranchInput, BoundBranchRead, project_bound_branch};
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::snapshot_read::{
    EvidenceSourceStatus, EvidenceSpansRequest, SourceVersion, SourceVersionCheck,
    evidence_spans_in_txn, extraction_turn_in_txn, extraction_turn_read,
    observed_claim_reads_in_txn, queued_extraction_branch_in_txn, source_version_in_txn,
};
use crate::verbs::{CandidateOperand, PinnedClaim, TurnEvidence};

/// Checks the queued branch, turn evidence with pins, bound projection, and subjects.
/// The caller proves binding, authority, and reader scope before calling.
/// Verdict passes its listed and prior pins while the page passes none.
/// Returns the queued branch with its rebuilt bound read for native checks.
pub(crate) fn check_extraction_operands_in_txn(
    memory: &Memory<'_>,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    attempt: AttemptId,
    candidates: &[CandidateOperand],
    pins: Option<(&[PinnedClaim], &[PinnedClaim])>,
) -> MemoryResult<(ConsolidationBranchPlan<EntityId>, BoundBranchRead)> {
    let vault = memory.vault();
    let turn_read = extraction_turn_read(read, None)?;
    let turn_read = turn_read.as_ref().unwrap_or(read);
    let attempt_entity = EntityId::from_bytes_unchecked(*attempt.as_bytes());
    let (scope, branch) = queued_extraction_branch_in_txn(vault, txn, attempt_entity)?;
    check_operand_rows(
        memory,
        (read, turn_read),
        txn,
        reader_scope,
        candidates,
        pins,
        (scope, &branch),
    )?;
    let bound = project_bound_branch(
        vault,
        txn,
        read,
        &BoundBranchInput {
            attempt,
            branch: &branch,
            caller: None,
            destination: None,
        },
    )
    .map_err(bound_branch_error)?;
    check_operand_subjects(read, txn, reader_scope, candidates)?;
    Ok((branch, bound))
}

/// Rechecks cited turn projections, spans, and claim pins before interpreting proposals.
fn check_operand_rows(
    memory: &Memory<'_>,
    (read, turn_read): (&ScopedRead<'_>, &ScopedRead<'_>),
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    candidates: &[CandidateOperand],
    pins: Option<(&[PinnedClaim], &[PinnedClaim])>,
    queued: (
        DreamerConsolidationScope,
        &ConsolidationBranchPlan<EntityId>,
    ),
) -> MemoryResult<()> {
    for candidate in candidates {
        for evidence in &candidate.evidence {
            let _served = check_turn_evidence(
                memory,
                (read, turn_read),
                txn,
                reader_scope,
                evidence,
                queued,
            )?;
        }
    }
    if let Some((listed, priors)) = pins {
        for pin in listed.iter().chain(priors.iter()) {
            check_source_pin(
                (read, turn_read),
                txn,
                reader_scope,
                &pin.claim,
                &pin.version,
                ENTITY_TYPE_CLAIM,
            )?;
        }
    }
    Ok(())
}

/// Rechecks one turn locator in the same order as the checked verdict pack.
pub(crate) fn check_turn_evidence(
    memory: &Memory<'_>,
    (read, turn_read): (&ScopedRead<'_>, &ScopedRead<'_>),
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    evidence: &TurnEvidence,
    queued: (
        DreamerConsolidationScope,
        &ConsolidationBranchPlan<EntityId>,
    ),
) -> MemoryResult<(EntityId, crate::snapshot_read::EvidenceSpans)> {
    let turn = check_source_pin(
        (read, turn_read),
        txn,
        reader_scope,
        &evidence.turn,
        &evidence.version,
        ENTITY_TYPE_TURN,
    )?;
    let key = queued
        .1
        .parts
        .iter()
        .find(|part| part.turns.contains(&turn))
        .map(|part| queued.1.part_key(part.conversation_ref))
        .ok_or_else(extraction_not_served)?;
    if extraction_turn_in_txn(
        memory.vault(),
        txn,
        (read, turn_read),
        reader_scope,
        queued.0,
        &key,
        turn,
    )?
    .is_none()
    {
        return Err(extraction_not_served());
    }
    let served = evidence_spans_in_txn(
        memory,
        turn_read,
        txn,
        &EvidenceSpansRequest {
            source: turn,
            version: Some(evidence.version.clone()),
            ranges: evidence.span.into_iter().collect(),
        },
    )?;
    match served.status {
        EvidenceSourceStatus::Current => {}
        EvidenceSourceStatus::Moved => return Err(extraction_source_moved()),
        EvidenceSourceStatus::Withheld => return Err(extraction_not_served()),
    }
    Ok((turn, served))
}

/// Checks that each proposed subject reads without treating its proposed value as a fact.
fn check_operand_subjects(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    candidates: &[CandidateOperand],
) -> MemoryResult<()> {
    for candidate in candidates {
        let subject = extraction_reference(&candidate.subject)?;
        if !observed_claim_reads_in_txn(read.vault(), txn, read, reader_scope, subject)? {
            return Err(extraction_not_served());
        }
        crate::claim::validate_predicate(&candidate.predicate, false).map_err(|_| {
            MemoryError::bad_request("extracted candidate's predicate breaks the claim grammar")
        })?;
        if candidate.value.is_null() || candidate.evidence.is_empty() {
            return Err(MemoryError::bad_request(
                "an extraction operand needs a non-null proposed value and TURN evidence",
            ));
        }
    }
    Ok(())
}

/// Reads and rechecks one pinned row under the dreamer live record reach.
fn check_source_pin(
    (read, turn_read): (&ScopedRead<'_>, &ScopedRead<'_>),
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    reference: &str,
    version: &SourceVersion,
    kind: u8,
) -> MemoryResult<EntityId> {
    let id = extraction_reference(reference)?;
    if version.entity != id {
        return Err(MemoryError::bad_request(
            "an extraction pin names another row",
        ));
    }
    if !observed_claim_reads_in_txn(read.vault(), txn, read, reader_scope, id)? {
        return Err(extraction_not_served());
    }
    let row = read
        .get_entities_parts_in_txn(txn, std::slice::from_ref(&id))?
        .pop()
        .flatten()
        .ok_or_else(extraction_not_served)?;
    if row.0 != kind || version.entity_type != kind {
        return Err(MemoryError::bad_request(
            "extraction evidence locators must name TURNs and claim pins must name CLAIMs",
        ));
    }
    let version_read = if kind == ENTITY_TYPE_TURN {
        turn_read
    } else {
        read
    };
    match version.recheck_in_txn(version_read, txn)? {
        SourceVersionCheck::Current => Ok(id),
        SourceVersionCheck::Withheld => Err(extraction_not_served()),
        SourceVersionCheck::Moved => Err(extraction_source_moved()),
    }
}

/// Reads an identifier in its only accepted lowercase hexadecimal spelling.
fn extraction_reference(reference: &str) -> MemoryResult<EntityId> {
    let id = EntityId::from_hex(reference).map_err(|_| {
        MemoryError::bad_request("extraction references must be 32 lowercase hex digits")
    })?;
    if id.to_hex() != reference {
        return Err(MemoryError::bad_request(
            "extraction references must be 32 lowercase hex digits",
        ));
    }
    Ok(id)
}

/// Requires the job's ordered claim references and source pins to equal the engine's set.
pub(crate) fn check_engine_claim_pins(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    offered: &[PinnedClaim],
    expected: &[EntityId],
) -> MemoryResult<()> {
    if offered.len() != expected.len() {
        return Err(MemoryError::bad_request(
            "the extraction pack claim pins differ from the engine's rebuilt set",
        ));
    }
    for (offered, expected) in offered.iter().zip(expected) {
        let Some((version, _)) = source_version_in_txn(read, txn, expected)? else {
            return Err(extraction_not_served());
        };
        if offered.claim != expected.to_hex() || offered.version != version {
            return Err(MemoryError::bad_request(
                "the extraction pack claim pins differ from the engine's rebuilt order or versions",
            ));
        }
    }
    Ok(())
}

/// Refuses a row the bound page would not serve without revealing its contents.
pub(crate) fn extraction_not_served() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "every extraction pack row must be served under the Dreamer attempt's live read",
        &["Use only rows served to this attempt and their current source versions."],
    )
}

/// Maps the bound branch read readability refusals to the unserved row refusal.
/// Every other projection failure keeps its own memory code.
pub(crate) fn bound_branch_error(error: crate::Error) -> MemoryError {
    match error {
        crate::Error::InvalidClaimBody(
            "branch source is not readable"
            | "branch document read refused"
            | "prior head exact read refused"
            | "witnessed turn message read refused",
        ) => extraction_not_served(),
        error => error.into(),
    }
}

/// Preserves the existing derive source moved refusal with its structured reason.
fn extraction_source_moved() -> MemoryError {
    crate::Error::Gate(crate::error::GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![crate::derive::SOURCE_MOVED],
    })
    .into()
}
