//! The recorded step candidates a lent operand names, and each operand's relationship set.
//!
//! An operand may name the recorded generation step candidates it is folded from. Each
//! named step's record is read in the operand check's own snapshot under the gate of the
//! receipt door: every queued TURN still serves and every row the step's request was read
//! from still reads for the caller at its recorded version. The step's reply is then read
//! back by the step's own candidate reader, over the label table the record keeps and each
//! recorded TURN range served again, and the operand must agree with the candidates it
//! names. So what a decision is shown for such an operand is what the generation step
//! produced.
//!
//! The check also fixes the relationship set each operand is assembled under. On a branch
//! whose scope holds none, a candidate is bound to the relationships every labelled word it
//! was drawn from shares (S63E-RULED): for an operand that names recorded candidates, the
//! words of every TURN their steps showed, as a native call binds over its TURNs; for an
//! operand that names none, the words of every TURN the branch queued, since any of them
//! may have produced it. A candidate that corrects a head binds the head's set, so a head
//! whose set lies outside the candidate's is offered to no correction
//! ([`takes_head_relationship`]).
//!
//! Which candidates fold into one operand is not proved here: the fold follows each
//! member's own correction answer, which no record holds.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use super::super::ConsolidationBranchPlan;
use super::super::extraction_step::{
    ExtractionStepPiece, RecordedExtractionCandidate, RecordedExtractionStep,
};
use super::BoundBranchRead;
use super::checks::{check_turn_evidence, every_queued_turn_serves_in_txn};
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::federation::Scope;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_TURN;
use crate::snapshot_read::{
    EvidenceRange, SourceVersion, SourceVersionCheck, observed_claim_reads_in_txn,
};
use crate::verbs::{CandidateOperand, TurnEvidence};

/// Borrows what the operand check reads its rows under: the caller's live reads, the one
/// snapshot, the caller's grant scope and the queued branch.
pub(super) struct OperandReads<'a> {
    /// Borrows the actor-scoped memory that admitted the operands.
    pub(super) memory: &'a Memory<'a>,
    /// Borrows the caller's live read.
    pub(super) read: &'a ScopedRead<'a>,
    /// Borrows the relationship-gated TURN reader.
    pub(super) turn_read: &'a ScopedRead<'a>,
    /// Borrows the transaction that holds the snapshot.
    pub(super) txn: &'a heed::RoTxn<'a>,
    /// Borrows the caller's grant scope, or none where none applies.
    pub(super) reader_scope: Option<&'a Scope>,
    /// Holds the queued scope with the queued branch.
    pub(super) queued: (
        DreamerConsolidationScope,
        &'a ConsolidationBranchPlan<EntityId>,
    ),
}

/// One recorded step read back, with the TURNs its call showed.
struct RecordedStep {
    /// Holds the step's reply with what its candidates read through.
    reply: RecordedExtractionStep,
    /// Names every TURN the step's call showed.
    turns: BTreeSet<EntityId>,
}

/// Reads every recorded step candidate `candidates` name, compares each naming operand
/// with them, and returns the relationship set each operand is assembled under, by
/// operand position: `None` is unbound.
///
/// # Errors
///
/// A step that this attempt holds no record of, or whose record the caller may not be
/// served, answers as an unknown step does. Refused by name: a step reference in another
/// spelling, a record that keeps no label table, a named candidate the step did not keep
/// about a listed subject, and an operand that differs from the candidates it names.
pub(super) fn bind_operands_in_txn(
    reads: &OperandReads<'_>,
    attempt: AttemptId,
    candidates: &[CandidateOperand],
    bound: &BoundBranchRead,
) -> MemoryResult<Vec<Option<BTreeSet<EntityId>>>> {
    let vault = reads.memory.vault();
    if candidates
        .iter()
        .any(|operand| !operand.from_steps.is_empty())
        && !every_queued_turn_serves_in_txn(
            vault,
            reads.txn,
            (reads.read, reads.turn_read),
            reads.reader_scope,
            reads.queued,
        )?
    {
        return Err(unknown_step());
    }
    let mut steps: BTreeMap<[u8; 32], RecordedStep> = BTreeMap::new();
    let mut queued_bound: Option<Option<BTreeSet<EntityId>>> = None;
    let mut relationships = Vec::with_capacity(candidates.len());
    for (position, operand) in candidates.iter().enumerate() {
        if operand.from_steps.is_empty() {
            let set = match &queued_bound {
                Some(set) => set.clone(),
                None => {
                    let set = bound.candidate_relationship_in_txn(vault, reads.txn, None)?;
                    queued_bound = Some(set.clone());
                    set
                }
            };
            relationships.push(set);
            continue;
        }
        let mut turns = BTreeSet::new();
        let mut recorded = Vec::with_capacity(operand.from_steps.len());
        for named in &operand.from_steps {
            let hash = extraction_step_hash(&named.step)?;
            let step = match steps.entry(hash) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) => {
                    slot.insert(read_recorded_step(reads, attempt, &hash, bound)?)
                }
            };
            turns.extend(step.turns.iter().copied());
            recorded.push(step.reply.candidate(named.index).map_err(|reason| {
                MemoryError::bad_request(format!(
                    "extraction operand {position} names a recorded candidate its step did not keep: {reason}"
                ))
            })?);
        }
        compare_operand(position, operand, &recorded)?;
        relationships.push(bound.candidate_relationship_in_txn(vault, reads.txn, Some(&turns))?);
    }
    Ok(relationships)
}

/// Reads the record of step `hash` under the receipt door's gate and serves each TURN
/// range it names again, through the function that served it to the step.
fn read_recorded_step(
    reads: &OperandReads<'_>,
    attempt: AttemptId,
    hash: &[u8; 32],
    bound: &BoundBranchRead,
) -> MemoryResult<RecordedStep> {
    let vault = reads.memory.vault();
    let still_reads = |version: &SourceVersion| -> crate::Result<bool> {
        let version_read = if version.entity_type == ENTITY_TYPE_TURN {
            reads.turn_read
        } else {
            reads.read
        };
        Ok(observed_claim_reads_in_txn(
            vault,
            reads.txn,
            reads.read,
            reads.reader_scope,
            version.entity,
        )? && version.recheck_in_txn(version_read, reads.txn)? == SourceVersionCheck::Current)
    };
    let record =
        crate::llm::request_hash_step_record_in_txn(vault, reads.txn, attempt, hash, still_reads)?;
    let (Some(labels), Some(ranges)) = (&record.labels, &record.ranges) else {
        return Err(MemoryError::bad_request(
            "an extraction operand names a step whose record keeps no call labels; a step recorded before records kept them cannot be named",
        ));
    };
    let mut pieces = Vec::with_capacity(ranges.len());
    let mut turns = BTreeSet::new();
    for range in ranges {
        let version = record
            .versions
            .iter()
            .find(|version| version.entity == range.turn)
            .ok_or_else(unknown_step)?;
        let evidence = TurnEvidence {
            turn: range.turn.to_hex(),
            version: version.clone(),
            span: (range.start < range.end).then_some(EvidenceRange {
                start: range.start,
                end: range.end,
            }),
        };
        let (turn, served) = check_turn_evidence(
            reads.memory,
            (reads.read, reads.turn_read),
            reads.txn,
            reads.reader_scope,
            &evidence,
            reads.queued,
        )?;
        let (start, text) = match served.spans.into_iter().next() {
            Some(span) => (span.start, span.text),
            None => (0, String::new()),
        };
        // The words read as the step's call showed them only while the same range comes
        // back: a reader whose masked text has changed since is served another one.
        if start != range.start || start + text.len() as u64 != range.end {
            return Err(unknown_step());
        }
        turns.insert(turn);
        pieces.push(ExtractionStepPiece {
            turn,
            start,
            text,
            version: version.clone(),
        });
    }
    let relationship = bound.candidate_relationship_in_txn(vault, reads.txn, Some(&turns))?;
    let reply = RecordedExtractionStep::read(bound, &record, labels, pieces, relationship)?;
    Ok(RecordedStep { reply, turns })
}

/// Requires `operand` to agree with the `recorded` candidates it names: each is about its
/// subject, one of them carries its predicate, value, relationship and topic, and each of
/// its TURN quotes and cited claims is carried by one of them.
fn compare_operand(
    position: usize,
    operand: &CandidateOperand,
    recorded: &[RecordedExtractionCandidate],
) -> MemoryResult<()> {
    let differs = |what: &str| {
        MemoryError::bad_request(format!(
            "extraction operand {position} differs from the recorded candidates it names: {what}"
        ))
    };
    if recorded
        .iter()
        .any(|candidate| candidate.subject != operand.subject)
    {
        return Err(differs("its subject is not every named candidate's"));
    }
    let proposes = |candidate: &RecordedExtractionCandidate| {
        candidate.predicate == operand.predicate
            && candidate.value == operand.value
            && candidate.rel == operand.rel
            && candidate.topic == operand.topic
    };
    if !recorded.iter().any(proposes) {
        let field = match recorded.first() {
            Some(first) if first.predicate != operand.predicate => "predicate",
            Some(first) if first.value != operand.value => "value",
            Some(first) if first.rel != operand.rel => "relationship",
            _ => "topic",
        };
        return Err(differs(&format!(
            "its {field} is not the first named candidate's, and no named candidate carries its whole proposal"
        )));
    }
    for cited in &operand.evidence {
        if !recorded
            .iter()
            .any(|candidate| candidate.evidence.contains(cited))
        {
            return Err(differs("it cites a TURN quote none of them carries"));
        }
    }
    for cited in &operand.claim_evidence {
        if !recorded
            .iter()
            .any(|candidate| candidate.claim_evidence.contains(cited))
        {
            return Err(differs("it cites a claim none of them cites"));
        }
    }
    Ok(())
}

/// Whether a candidate assembled under `within` may take the relationship set
/// of head `claim`, which a candidate that corrects the head binds: every
/// set when the candidate is unbound, else a set that lies inside `within`.
/// A head that holds within all relationships lies inside no set.
pub(super) fn takes_head_relationship(
    bound: &BoundBranchRead,
    claim: EntityId,
    within: Option<&BTreeSet<EntityId>>,
) -> bool {
    let Some(within) = within else {
        return true;
    };
    bound.prior(claim).is_some_and(|prior| {
        prior
            .body
            .rel
            .as_ref()
            .is_some_and(|rel| rel.iter().all(|id| within.contains(id)))
    })
}

/// Answers as the receipt door answers an unknown step hash.
fn unknown_step() -> MemoryError {
    MemoryError::from(crate::Error::EntityNotFound)
}

/// Decodes a step's request hash in its only accepted lowercase hexadecimal spelling.
///
/// # Errors
///
/// Anything other than 64 lowercase hexadecimal digits.
pub(crate) fn extraction_step_hash(value: &str) -> MemoryResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MemoryError::bad_request(
            "an extraction step key must be 64 lowercase hex digits",
        ));
    }
    let mut hash = [0; 32];
    for (out, pair) in hash.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(hash)
}
