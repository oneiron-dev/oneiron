//! The shared set rebuild for the extraction stagers: the verdict's
//! operands, the pack check, the shared set selection, the heads equality
//! and one verified member per selected candidate, in the batch's write.
//!
//! Both the Conflict stager and the ConflictResolution stager rebuild the
//! verdict's set identically; only their refusal tokens differ. This file owns
//! the rebuild so the two stagers share one copy of the order. Each stager
//! maps a refusal to its own token; a storage error aborts the commit.
use super::batch::DerivedConflictMember;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::evidence::VerifiedCandidate;
use crate::dreamer_consolidation::extraction_pack::{
    BoundBranchRead, CheckedPack, ExtractionRebuildContext, SelectedConflict,
    check_engine_claim_pins, check_extraction_operands_in_txn, check_pack_candidates,
    select_routed_conflict,
};
use crate::error::Error;
use crate::memory::{Memory, MemoryError};
use crate::verbs::PinnedClaim;

/// What the rebuild reads: the verdict's read, the item's members and heads,
/// the selector and the commit's clock. Every read runs in the caller's one
/// live transaction; nothing here opens one.
pub(super) struct RebuildInput<'a> {
    /// The actor's memory, which admitted the operands.
    pub(super) memory: &'a Memory<'a>,
    /// The verdict's read for the actor.
    pub(super) read: &'a crate::claim::ScopedRead<'a>,
    /// The verdict's TURN reader.
    pub(super) turn_read: &'a crate::claim::ScopedRead<'a>,
    /// The batch's write, reborrowed as a read.
    pub(super) txn: &'a heed::RoTxn<'a>,
    /// The reader scope, when the actor is not the owner.
    pub(super) reader_scope: Option<&'a crate::federation::Scope>,
    /// The queued extraction attempt.
    pub(super) attempt: AttemptId,
    /// The item's members, in pack order.
    pub(super) members: &'a [DerivedConflictMember],
    /// The stored heads the set stands against, as the job read them.
    pub(super) heads: &'a [PinnedClaim],
    /// The pack's `set_members` selector, when the members form more than one set.
    pub(super) set_members: Option<&'a [usize]>,
    /// The commit's clock, in milliseconds.
    pub(super) now_ms: u64,
}

/// The rebuilt set: the bound projection, the selected conflict with its
/// checked proposals, the checked pack (for the correcting-operand bindings)
/// and one verified member per selected candidate, in set order.
pub(super) struct RebuiltSet {
    /// The bound branch projection the rebuild checked against.
    pub(super) bound: BoundBranchRead,
    /// The selected conflict with the checked proposals in pack order.
    pub(super) selected: SelectedConflict,
    /// The checked pack, with each row's bound correcting head.
    pub(super) checked: CheckedPack,
    /// One verified member per selected candidate, in set order.
    pub(super) members: Vec<VerifiedCandidate>,
}

/// What a rebuild met instead of a set: which refusal, or the store's error.
pub(super) enum SetRebuildError {
    /// The operands are not one servable native conflict.
    Operands(MemoryError),
    /// The heads differ from the rebuilt set's prior heads.
    HeadsDiffer(MemoryError),
    /// The store's error, which aborts the commit.
    Abort(Error),
}

/// Rebuilds the verdict's set for `input`: the operand checks, the pack
/// check, the shared selection, the heads equality and one verified member
/// per selected candidate. Answers the rebuilt set or which refusal it met;

/// each stager maps a refusal to its own token.
///
/// # Errors
///
/// The verdict's refusal (operands or heads differ), or the store's error.
pub(super) fn rebuild_conflict_set(
    input: RebuildInput<'_>,
) -> std::result::Result<RebuiltSet, SetRebuildError> {
    use SetRebuildError::{Abort, HeadsDiffer, Operands};
    let operands: Vec<crate::verbs::CandidateOperand> = input
        .members
        .iter()
        .map(|member| member.operand.clone())
        .collect();
    let (branch, bound) = match check_extraction_operands_in_txn(
        input.memory,
        input.read,
        input.txn,
        input.reader_scope,
        input.attempt,
        &operands,
        Some((&[], input.heads)),
    ) {
        Ok(checked) => checked,
        Err(error) => return Err(Operands(error)),
    };
    let checked = match check_pack_candidates(&operands, &bound, input.attempt, &branch) {
        Ok(checked) => checked,
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return Err(Operands(MemoryError::bad_request(
                "the extraction operands are not one servable conflict",
            )));
        }
        Err(error) => return Err(Abort(error)),
    };
    let selected = {
        let rebuild = ExtractionRebuildContext {
            memory: input.memory,
            read: input.read,
            turn_read: input.turn_read,
            txn: input.txn,
            operands: &operands,
        };
        match select_routed_conflict(&checked.rows, &bound, &rebuild, input.set_members) {
            Ok(selected) => selected,
            Err(error) => return Err(Operands(error)),
        }
    };
    if let Err(error) = check_engine_claim_pins(
        input.read,
        input.txn,
        input.heads,
        &selected.set.prior_heads,
    ) {
        return Err(HeadsDiffer(error));
    }
    let mut members = Vec::with_capacity(selected.set.candidate_indexes.len());
    for index in &selected.set.candidate_indexes {
        let (member, proposal) = match (input.members.get(*index), selected.proposals.get(*index)) {
            (Some(member), Some(proposal)) => (member, proposal),
            _ => {
                return Err(Operands(MemoryError::bad_request(
                    "the selected set names a missing member",
                )));
            }
        };
        let mut stamped = proposal.clone();
        stamped.candidate = super::conflict::inputs::member_candidate(
            &proposal.candidate,
            member.confidence,
            &member.prospective_queries,
        )
        .map_err(Abort)?;
        let verified = match bound.verify_observation_candidate_in_txn(
            input.memory,
            input.turn_read,
            input.txn,
            &member.operand,
            &stamped,
            input.now_ms,
        ) {
            Ok(verified) => verified,
            Err(error) => return Err(Operands(error)),
        };
        members.push(verified);
    }
    Ok(RebuiltSet {
        bound,
        selected,
        checked,
        members,
    })
}
