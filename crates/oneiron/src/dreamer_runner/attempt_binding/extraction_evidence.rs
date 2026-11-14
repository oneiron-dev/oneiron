//! One-snapshot evidence checks for a bound extraction verdict pack.

use super::DreamerAttemptBinding;
use crate::EntityId;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::dreamer_consolidation::ConsolidationBranchPlan;
use crate::dreamer_consolidation::extraction_pack::{
    BoundBranchInput, map_candidate_alias, project_bound_branch, rebuild_checked_pack,
};
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::snapshot_read::{
    EvidenceSourceStatus, EvidenceSpansRequest, SourceVersion, SourceVersionCheck,
    evidence_spans_in_txn, extraction_reader_scope_in_txn, extraction_turn_in_txn,
    observed_claim_reads_in_txn, queued_extraction_branch_in_txn, source_version_in_txn,
};
use crate::verbs::{ExtractionPack, PinnedClaim};

impl DreamerAttemptBinding {
    /// Checks every pack operand and its rebuilt contract in one live read snapshot.
    pub(super) fn checked_extraction_pack(&self, pack: &ExtractionPack) -> MemoryResult<()> {
        let vault = &*self.vault;
        let memory = vault.memory(self.stamp.actor, self.actor().actor_class());
        let read = memory.read_lane(ClaimReadStatus::Recorded)?;
        let _pins = read.prepare_point_read::<MemoryError>()?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        self.check_in_txn(&txn)?;
        memory.prove_read_authority_in_txn(&txn)?;
        let reader_scope = extraction_reader_scope_in_txn(&memory, &txn, None)?;
        read.read_projected_in_txn(&txn, &[], None, |txn, _| {
            let (scope, branch) = queued_extraction_branch_in_txn(vault, txn, self.attempt())?;
            check_pack_rows(
                &memory,
                &read,
                txn,
                reader_scope.as_ref(),
                pack,
                (scope, &branch),
            )?;
            let bound = project_bound_branch(
                vault,
                txn,
                &read,
                &BoundBranchInput {
                    attempt: self.lease.attempt(),
                    branch: &branch,
                    caller: None,
                    destination: None,
                },
            )?;
            check_pack_subjects(&read, txn, reader_scope.as_ref(), pack)?;
            let rebuilt = rebuild_checked_pack(
                pack,
                &bound,
                self.lease.attempt(),
                &branch.axes(),
                &read,
                txn,
            )
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            check_engine_claim_pins(&read, txn, &pack.listed, &rebuilt.listed)?;
            check_engine_claim_pins(&read, txn, &pack.priors, &rebuilt.priors)?;
            compare_pack_questions(&pack.questions, &rebuilt.questions, &rebuilt.candidate_ids)
        })?;
        Ok(())
    }
}

/// Rechecks cited TURN projections, spans and claim pins before interpreting proposals.
fn check_pack_rows(
    memory: &Memory<'_>,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    pack: &ExtractionPack,
    queued: (
        DreamerConsolidationScope,
        &ConsolidationBranchPlan<EntityId>,
    ),
) -> MemoryResult<()> {
    for candidate in &pack.candidates {
        for evidence in &candidate.evidence {
            let turn = check_source_pin(
                read,
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
                read,
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
                read,
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
        }
    }
    for pin in pack.listed.iter().chain(&pack.priors) {
        check_source_pin(
            read,
            txn,
            reader_scope,
            &pin.claim,
            &pin.version,
            ENTITY_TYPE_CLAIM,
        )?;
    }
    Ok(())
}

/// Checks that each proposed subject reads without treating its proposed value as a fact.
fn check_pack_subjects(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    reader_scope: Option<&Scope>,
    pack: &ExtractionPack,
) -> MemoryResult<()> {
    for candidate in &pack.candidates {
        let subject = extraction_reference(&candidate.subject)?;
        if !observed_claim_reads_in_txn(read.vault(), txn, read, reader_scope, subject)? {
            return Err(extraction_not_served());
        }
        crate::claim::validate_predicate(&candidate.predicate, false)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        if candidate.value.is_null() || candidate.evidence.is_empty() {
            return Err(MemoryError::bad_request(
                "an extraction operand needs a non-null proposed value and TURN evidence",
            ));
        }
    }
    Ok(())
}

/// Requires the job's ordered claim references and source pins to equal the engine's set.
fn check_engine_claim_pins(
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

/// Reads and rechecks one pinned row under the Dreamer's live record reach.
fn check_source_pin(
    read: &ScopedRead<'_>,
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
    match version.recheck_in_txn(read, txn)? {
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

/// Refuses a row the bound page would not serve without revealing its contents.
fn extraction_not_served() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "every extraction pack row must be served under the Dreamer attempt's live read",
        &["Use only rows served to this attempt and their current source versions."],
    )
}

/// Preserves the existing derive source-moved refusal and its structured reason.
fn extraction_source_moved() -> MemoryError {
    crate::Error::Gate(crate::error::GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![crate::derive::SOURCE_MOVED],
    })
    .into()
}

/// Compares each rebuilt key and Choice contract in its native question order.
fn compare_pack_questions(
    offered: &[crate::verbs::PackQuestion],
    rebuilt: &[crate::verbs::PackQuestion],
    candidates: &[EntityId],
) -> MemoryResult<()> {
    for index in 0..offered.len().max(rebuilt.len()) {
        let same = match (offered.get(index), rebuilt.get(index)) {
            (Some(offered), Some(rebuilt)) => {
                let options = offered
                    .options
                    .iter()
                    .map(|option| map_candidate_alias(option, candidates))
                    .collect::<crate::Result<Vec<_>>>()
                    .map_err(|error| {
                        MemoryError::bad_request(format!(
                            "extraction question {index} has an invalid option: {error}"
                        ))
                    })?;
                offered.key == rebuilt.key && options == rebuilt.options
            }
            _ => false,
        };
        if !same {
            return Err(MemoryError::bad_request(format!(
                "extraction question {index} differs from its native key or options"
            )));
        }
    }
    Ok(())
}
