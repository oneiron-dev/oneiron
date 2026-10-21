//! Settling a parked contradiction (OF-023; ARCH-0003 `dr:H0636-4`).
//!
//! A `conflict.open` marker stays open until a standing `conflict.resolved`
//! names it. The Dreamer's own correction closes the markers its replacement
//! answers (`dreamer_promotion/corrections.rs`); every other marker waits here
//! for an authorised responder: the vault's root owner, the Dreamer, whose
//! review stands from birth, or a person or agent the owner delegated
//! `memory.conflict_review` on the conflict's subject
//! (`Memory::settle_conflict`).
//!
//! A responder keeps one member, holds them all, or dismisses the marker.
//! Keeping one supersedes each other live member with it, so the winner is
//! the ordinary `supersedes` edge and no Conflict entity exists. A candidate
//! the marker's round dropped is retained on the marker (FIX 496): keeping
//! it lands it first, in the settlement's transaction and under the current
//! Gate, and a revert retracts the winner that settlement landed. A Keep
//! after that revert lands it afresh, and a Keep of imported words stages it
//! in its import's review and leaves the marker open (`retained_keep.rs`,
//! FIX 5752, FIX 5754). Holding them all leaves every member active: the
//! observed-versus-stated answer, where `observed` never outranks
//! `user_stated`. The open marker is never edited; it stays as audit
//! evidence beside the claim that answers it.
//!
//! The Dreamer asks its host's decision ladder ([`ConflictSettleDecisions`])
//! and applies the answer at once; the owner reverts it
//! (`Memory::revert_conflict_settlement`), and a reverted conflict, or one
//! under the owner's hold, is the owner's to answer. An abstention or an
//! escalation leaves the marker parked for the owner.

use std::collections::BTreeSet;

use rmpv::Value;
use serde_json::json;

use super::retained_conflict::RetainedAlternative;
use super::retained_keep::{ConflictSettleOutcome, KeptAlternative, SettlementApplied, StagedKeep};
use super::support::invalid_consolidation;
use super::value_projection::rmpv_to_json;
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject, PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED, claim_surfaceable,
};
use crate::error::{Error, Result};
use crate::llm::decision::catalogue::CONFLICT_SETTLE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionRung, Reversibility, cut_text, fit_state,
};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::retrieval_depth::RetrievalDeadline;
use crate::write_envelope::{WriteActor, WriteEnvelope};
use crate::{ClaimBody, EntityId, TimeRange, Vault};

/// The marker-value keys that name a contradiction's claims: the
/// consolidation marker's prior heads and candidates, and the older
/// `members` spelling.
const MEMBER_KEYS: [&str; 4] = ["prior_head", "prior_heads", "candidates", "members"];
/// The repository conflict shares the predicate under its own schema; its
/// reconciliation task settles it, never this door.
const REPO_CONFLICT_KIND: &str = "repo_branch";
/// The most members one ladder question offers to keep, under the Choice
/// contract's 64 options with hold-both, dismiss and escalate beside them.
const MAX_KEEP_OPTIONS: usize = 61;
/// The resolution key naming the retained alternative a Keep landed.
pub(super) const MATERIALIZED_KEY: &str = "materialized";

/// A responder's answer to one open conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSettlement {
    /// This member stands, and each other live member is superseded by it.
    Keep(EntityId),
    /// The owner approves this member, a Keep of the conflict still waiting
    /// in its import's review, and keeps it in the same step: it stands
    /// approved, and each other live member is superseded by it (FIX 6151).
    /// An optional act of the vault's root owner beside Approve and Keep,
    /// which stay as they are.
    ApproveAndKeep(EntityId),
    /// Every member stays active: the pair is held and its gap is known.
    HoldBoth,
    /// The marker named no real contradiction; every member stays as it is.
    Dismiss,
}

impl ConflictSettlement {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Keep(_) => "keep",
            Self::ApproveAndKeep(_) => "approve_and_keep",
            Self::HoldBoth => "hold_both",
            Self::Dismiss => "dismiss",
        }
    }

    /// The member or retained alternative this settlement keeps, if any.
    const fn kept(self) -> Option<EntityId> {
        match self {
            Self::Keep(kept) | Self::ApproveAndKeep(kept) => Some(kept),
            Self::HoldBoth | Self::Dismiss => None,
        }
    }
}

/// Which open conflicts an owner lets a delegate settle: one subject's, or
/// every subject's in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReviewScope {
    Subject(EntityId),
    Vault,
}

/// One unanswered `conflict.open` marker and the claims it names.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenConflict {
    pub marker: EntityId,
    pub subject: EntityId,
    /// The stored claims the marker names, in its own order. An id it names
    /// that is no stored claim (a candidate its round dropped) is left out.
    /// A Keep staged at a fresh id, after a revert or after the owner
    /// declined one (FIX 7072), linked to the marker, follows them (FIX
    /// 6152). A staged Keep the owner declined stays a member.
    pub members: Vec<EntityId>,
    /// The candidates the marker's round dropped, retained on it whole (FIX
    /// 496): none is a stored claim or active truth. Keeping one lands it.
    pub alternatives: Vec<RetainedAlternative>,
    /// The contested predicates, as the marker records them.
    pub predicates: Vec<String>,
    /// The marker itself, still Proposed while it waits in its own review.
    pub body: ClaimBody,
    /// A retracted answer names the marker: a settlement was reverted, so it
    /// waits for the owner and the Dreamer leaves it.
    pub reverted: bool,
}

/// What a settlement wrote: the answering `conflict.resolved` and each member
/// the kept one superseded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledConflict {
    pub resolved: EntityId,
    pub superseded: Vec<EntityId>,
}

/// A settlement's durable outcome, with the Gate receipt that recorded who
/// answered and under which Grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictSettleReceipt {
    pub marker: EntityId,
    pub settlement: ConflictSettlement,
    pub resolved: EntityId,
    pub superseded: Vec<EntityId>,
    pub receipt_ref: String,
}

/// What reverting one settlement did (OF-023, owner ruling 10-18): the marker
/// it reopened, the members standing again in place, the Dreamer's fresh
/// copies of its own MACHINE members as (member, copy), the members a later
/// write closed, left as they are, and the retained alternative the
/// settlement landed, retracted when it still stood (FIX 496).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertedSettlement {
    pub marker: EntityId,
    pub restored: Vec<EntityId>,
    pub copied: Vec<(EntityId, EntityId)>,
    pub left_closed: Vec<EntityId>,
    pub retracted: Option<EntityId>,
}

/// One standing settlement an owner may revert: its answer, the marker it
/// answers, the settlement, what it kept and superseded, and whether the
/// Dreamer made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledAnswer {
    pub resolved: EntityId,
    pub marker: EntityId,
    pub subject: EntityId,
    pub settlement: String,
    pub kept: Option<EntityId>,
    pub superseded: Vec<EntityId>,
    pub by_dreamer: bool,
}

/// A revert's durable outcome, with the Gate receipt that recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictRevertReceipt {
    pub resolved: EntityId,
    pub reverted: RevertedSettlement,
    pub receipt_ref: String,
}

/// The ids under `key` in a claim value map: one binary id, or an array.
pub(crate) fn marker_ids<'v>(value: &'v Value, key: &str) -> impl Iterator<Item = EntityId> + 'v {
    let found = match value {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value),
        _ => None,
    };
    let values: &'v [Value] = match found {
        Some(Value::Array(values)) => values,
        Some(value) => std::slice::from_ref(value),
        None => &[],
    };
    values.iter().filter_map(|value| match value {
        Value::Binary(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .and_then(|bytes| EntityId::from_bytes(bytes).ok()),
        _ => None,
    })
}

pub(super) fn string_at<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    match value {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value),
        _ => None,
    }
}

fn is_repo_conflict(body: &ClaimBody) -> bool {
    string_at(&body.value, "kind").and_then(Value::as_str) == Some(REPO_CONFLICT_KIND)
}

/// The ids a marker names, deduplicated in order: the consolidation keys, then
/// a supersession coaching marker's evidence refs (its new and old claim).
fn named_ids(body: &ClaimBody) -> Vec<EntityId> {
    let mut seen = BTreeSet::new();
    let evidence = body
        .evidence
        .as_ref()
        .map(|evidence| marker_ids(evidence, "refs"));
    MEMBER_KEYS
        .iter()
        .flat_map(|key| marker_ids(&body.value, key).collect::<Vec<_>>())
        .chain(evidence.into_iter().flatten())
        .filter(|id| seen.insert(*id))
        .collect()
}

/// The predicates a marker contests: a coaching marker's value is the
/// predicate; a consolidation marker lists them, or names its one.
fn contested_predicates(body: &ClaimBody) -> Vec<String> {
    if let Some(predicate) = body.value.as_str() {
        return vec![predicate.to_owned()];
    }
    if let Some(Value::Array(items)) = string_at(&body.value, "predicates") {
        let listed: Vec<String> = items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect();
        if !listed.is_empty() {
            return listed;
        }
    }
    string_at(&body.value, "predicate")
        .and_then(Value::as_str)
        .map(|predicate| vec![predicate.to_owned()])
        .unwrap_or_default()
}

/// Whether `body` is a marker still asking: Active, not refused, and not a
/// repository conflict.
fn open_marker_body(body: &ClaimBody) -> bool {
    body.predicate == PREDICATE_CONFLICT_OPEN
        && body.lifecycle == ClaimLifecycleStatus::Active
        && body.approval != ClaimApprovalStatus::Rejected
        && !is_repo_conflict(body)
}

fn open_conflict_from(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
    body: ClaimBody,
    reverted: bool,
) -> Result<Option<OpenConflict>> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    // A landing a reverted settlement made of a retained candidate is no
    // member: the candidate stays keepable (FIX 5752). A Keep of it staged
    // since in its import's review is one, standing for it (FIX 6152)
    // unless the owner declined it there; a declined one stays a member
    // standing for nothing (FIX 7072).
    let named = named_ids(&body);
    let kept =
        super::retained_keep::keep_history_in_txn(vault, txn, marker, subject, &named, reverted)?;
    let staged = kept.staged.iter().map(|(_, staged)| *staged);
    let mut members = Vec::new();
    for id in named.into_iter().chain(staged) {
        if !members.contains(&id)
            && !kept.landings.iter().any(|(_, landed)| *landed == id)
            && vault
                .get_claim_in_txn(txn, &id)?
                .is_some_and(|member| member.predicate != PREDICATE_CONFLICT_OPEN)
        {
            members.push(id);
        }
    }
    // A retained candidate that is now a stored claim reads as a member.
    let alternatives = super::retained_keep::keepable(
        super::retained_conflict::retained_alternatives(&body.value),
        &members,
        &kept,
    );
    Ok(Some(OpenConflict {
        marker,
        subject,
        members,
        alternatives,
        predicates: contested_predicates(&body),
        body,
        reverted,
    }))
}

/// Whether `body` is an answer to an open marker that was taken back: a
/// retracted `conflict.resolved`, the trace a reverted settlement leaves.
fn reverted_answer(body: &ClaimBody) -> bool {
    body.predicate == PREDICATE_CONFLICT_RESOLVED
        && body.lifecycle == ClaimLifecycleStatus::Retracted
}

/// Every open conflict, on `subject` alone when one is named, oldest marker
/// id first. A marker a standing `conflict.resolved` names is answered and
/// left out; a refused, closed or stale answer answers nothing.
pub(crate) fn open_conflicts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: Option<EntityId>,
) -> Result<Vec<OpenConflict>> {
    let mut markers = Vec::new();
    let mut answered = BTreeSet::new();
    let mut reverted = BTreeSet::new();
    let mut sort = |id: EntityId, body: ClaimBody| {
        if body.predicate == PREDICATE_CONFLICT_RESOLVED {
            if claim_surfaceable(&body) {
                answered.extend(marker_ids(&body.value, "open_marker"));
            } else if reverted_answer(&body) {
                reverted.extend(marker_ids(&body.value, "open_marker"));
            }
        } else if open_marker_body(&body) {
            markers.push((id, body));
        }
    };
    match subject {
        Some(subject) => {
            for id in vault.claims_for_subject_in_txn(txn, &subject)? {
                if let Some(body) = vault.get_claim_in_txn(txn, &id)? {
                    sort(id, body);
                }
            }
        }
        None => {
            for predicate in [PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED] {
                vault.for_each_readable_claim_with_predicate_in_txn(
                    txn,
                    predicate,
                    |id, body| {
                        sort(id, body);
                        Ok(())
                    },
                )?;
            }
        }
    }
    markers.sort_by_key(|(id, _)| *id);
    let mut open = Vec::new();
    for (id, body) in markers {
        if answered.contains(&id) {
            continue;
        }
        let was_reverted = reverted.contains(&id);
        if let Some(conflict) = open_conflict_from(vault, txn, id, body, was_reverted)? {
            open.push(conflict);
        }
    }
    Ok(open)
}

/// The open conflict `marker` asks, or an error when it is no marker, is
/// closed, or a standing answer already names it.
pub(crate) fn open_conflict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
) -> Result<OpenConflict> {
    let body = vault
        .get_claim_in_txn(txn, &marker)?
        .ok_or(Error::EntityNotFound)?;
    if !open_marker_body(&body) {
        return Err(invalid_consolidation("not an open conflict marker"));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_consolidation("conflict subject"));
    };
    let mut reverted = false;
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(answer) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if answer.predicate != PREDICATE_CONFLICT_RESOLVED
            || !marker_ids(&answer.value, "open_marker").any(|named| named == marker)
        {
            continue;
        }
        if claim_surfaceable(&answer) {
            return Err(invalid_consolidation("the conflict is already settled"));
        }
        reverted |= reverted_answer(&answer);
    }
    open_conflict_from(vault, txn, marker, body, reverted)?
        .ok_or(invalid_consolidation("conflict subject"))
}

/// Writes `settlement` for `conflict` in the caller's transaction, after the
/// caller has checked the responder's authority (and, for `ApproveAndKeep`,
/// approved the staged member, which is then kept as `Keep` keeps a member).
/// `Keep` needs a standing member on the conflict's own subject, or one of
/// its retained alternatives, which lands first under the current Gate (FIX
/// 496) and must then stand, and the answer records it as landed, beside the
/// alternative it was made of; one from imported words is staged in its
/// import's review instead, and nothing else is written (FIX 5754, FIX
/// 6152). Each other Active member on that subject is superseded by it (a
/// staged replacement that lost drops its binding, and a pending review tray
/// closes), under the claim lifecycle's own guards: a generated claim still
/// never supersedes user-stated truth.
/// Only a `person` closes user-stated truth at all: an agent's settlement
/// that would is refused, and the conflict stays for the owner. `close_as`
/// attributes a delegate's close; the owner's close is the owner's. The
/// answering claim then records the settlement on the marker's own axes.
pub(crate) fn apply_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conflict: &OpenConflict,
    settlement: ConflictSettlement,
    envelope: &WriteEnvelope,
    close_as: Option<WriteActor>,
    person: bool,
    now: u64,
) -> Result<SettlementApplied> {
    let on_subject =
        |body: &ClaimBody| matches!(body.subject, ClaimSubject::Entity(s) if s == conflict.subject);
    let mut superseded = Vec::new();
    let mut materialized = None;
    let mut standing = None;
    if let Some(selected) = settlement.kept() {
        let mut winner = selected;
        // A retained alternative lands first, as its round proposed it and
        // under the current Gate (FIX 496); a refusal leaves the marker open.
        if let Some(alternative) = conflict
            .alternatives
            .iter()
            .find(|alternative| alternative.id == selected)
        {
            match super::retained_keep::keep_in_txn(vault, txn, conflict.marker, alternative, now)?
            {
                KeptAlternative::Landed(landed) => {
                    winner = landed;
                    materialized = Some((selected, landed));
                }
                KeptAlternative::ImportReview(staged) => {
                    return Ok(SettlementApplied::ImportReviewPending(staged));
                }
            }
        } else if !conflict.members.contains(&winner) {
            return Err(invalid_consolidation(
                "the kept claim is not a member of the conflict",
            ));
        }
        let kept = vault
            .get_claim_in_txn(txn, &winner)?
            .ok_or(Error::EntityNotFound)?;
        if !claim_surfaceable(&kept) || !on_subject(&kept) {
            return Err(invalid_consolidation(
                "the kept claim does not stand on the conflict's subject",
            ));
        }
        let reasons = || vec!["gate.memory.conflict_settlement".to_owned()];
        for &loser in conflict.members.iter().filter(|id| **id != winner) {
            let Some(body) = vault.get_claim_in_txn(txn, &loser)? else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active {
                continue;
            }
            if !on_subject(&body) {
                return Err(invalid_consolidation(
                    "a conflict member is off the conflict's subject",
                ));
            }
            if !person && matches!(body.source, None | Some(ClaimSource::UserStated)) {
                return Err(invalid_consolidation(
                    "only a person supersedes user-stated truth",
                ));
            }
            vault.cancel_deferred_claim_in_txn(txn, &loser)?;
            vault.store.close_pending_gate_consent_in_txn(
                txn,
                &loser,
                now,
                "superseded",
                reasons(),
                None,
            )?;
            vault.supersede_claim_in_txn_as(txn, &winner, &loser, now, close_as)?;
            // The lifecycle projector may raise a Proposed row's tray again;
            // a settled loser keeps no actionable consent.
            vault.store.close_pending_gate_consent_in_txn(
                txn,
                &loser,
                now,
                "superseded",
                reasons(),
                None,
            )?;
            superseded.push(loser);
        }
        standing = Some(winner);
    }
    let mut resolution = vec![(Value::from("settlement"), Value::from(settlement.label()))];
    if let Some(winner) = standing {
        resolution.push((
            Value::from("kept"),
            Value::Binary(winner.as_bytes().to_vec()),
        ));
        resolution.push((
            Value::from("superseded"),
            Value::Array(
                superseded
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ));
    }
    if let Some((selector, born)) = materialized {
        resolution.push((
            Value::from(MATERIALIZED_KEY),
            Value::Binary(born.as_bytes().to_vec()),
        ));
        resolution.push((
            Value::from(super::retained_keep::SELECTOR_KEY),
            Value::Binary(selector.as_bytes().to_vec()),
        ));
    }
    let candidate = super::persistence::resolved_candidate(
        &conflict.body,
        conflict.marker,
        Value::Map(resolution),
    );
    let resolved = EntityId::now();
    // Rule A: the answer is concluded from the marker it settles and every
    // member it weighed.
    let birth = {
        let inputs: Vec<EntityId> = std::iter::once(conflict.marker)
            .chain(conflict.members.iter().copied())
            .chain(materialized.map(|(_, born)| born))
            .collect();
        RowBirth::written(
            envelope.actor(),
            MadeByClass::Concluded,
            "dreamer.settlement",
            &inputs,
            &[],
            now,
        )
    };
    // A MACHINE's answer (the Dreamer's) carries its retained signature, or
    // put admission refuses it; a person's and an agent's pass unchanged.
    let mut envelope = envelope.clone();
    vault.sign_retained_machine_claim_in_txn(&*txn, &resolved, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &resolved,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(&resolved, birth)
        .apply(txn)?;
    Ok(SettlementApplied::Settled(SettledConflict {
        resolved,
        superseded,
    }))
}

/// The standing settlements, on `subject` alone when one is named, newest
/// answer first, at most `limit`. A correction's answer is no settlement
/// and is left out.
pub(crate) fn settled_answers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: Option<EntityId>,
    limit: usize,
) -> Result<Vec<SettledAnswer>> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let mut answers = Vec::new();
    vault.for_each_readable_claim_with_predicate_in_txn(
        txn,
        PREDICATE_CONFLICT_RESOLVED,
        |id, body| {
            let ClaimSubject::Entity(on) = body.subject else {
                return Ok(());
            };
            if !claim_surfaceable(&body) || subject.is_some_and(|subject| subject != on) {
                return Ok(());
            }
            let Some(marker) = marker_ids(&body.value, "open_marker").next() else {
                return Ok(());
            };
            let Some(resolution) = string_at(&body.value, "resolution") else {
                return Ok(());
            };
            let Some(settlement) = string_at(resolution, "settlement").and_then(Value::as_str)
            else {
                return Ok(());
            };
            answers.push(SettledAnswer {
                resolved: id,
                marker,
                subject: on,
                settlement: settlement.to_owned(),
                kept: marker_ids(resolution, "kept").next(),
                superseded: marker_ids(resolution, "superseded").collect(),
                by_dreamer: crate::memory::claim_author(&body) == Some(dreamer),
            });
            Ok(())
        },
    )?;
    answers.sort_by(|a, b| b.resolved.cmp(&a.resolved));
    answers.truncate(limit);
    Ok(answers)
}

/// Reverts the settlement `resolved` answers, in the caller's transaction,
/// after the caller has checked the owner's authority. The answer is
/// retracted as `reverter`'s, so its marker is open again and, as a reverted
/// one, the owner's to answer. Each member the kept one superseded stands
/// again: in place, its `supersedes` link gone; a Dreamer-born MACHINE
/// member, whose signed history never reopens, as the Dreamer's fresh copy
/// born of it. A member some later write closed stays as it is. A winner
/// the settlement landed from a retained alternative is retracted while it
/// still stands. Nothing is deleted: the answer and every closed row stay as
/// history.
pub(crate) fn revert_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resolved: EntityId,
    reverter: WriteActor,
    now: u64,
) -> Result<RevertedSettlement> {
    let answer = vault
        .get_claim_in_txn(txn, &resolved)?
        .ok_or(Error::EntityNotFound)?;
    if answer.predicate != PREDICATE_CONFLICT_RESOLVED || !claim_surfaceable(&answer) {
        return Err(invalid_consolidation("not a standing conflict answer"));
    }
    let marker = marker_ids(&answer.value, "open_marker")
        .next()
        .ok_or(invalid_consolidation("the answer names no marker"))?;
    let resolution = string_at(&answer.value, "resolution")
        .filter(|resolution| string_at(resolution, "settlement").is_some())
        .ok_or(invalid_consolidation("not a settlement's answer"))?;
    let kept = marker_ids(resolution, "kept").next();
    let superseded: Vec<EntityId> = marker_ids(resolution, "superseded").collect();
    let born = marker_ids(resolution, MATERIALIZED_KEY).next();
    vault.retract_claim_in_txn_as(txn, &resolved, now, Some(reverter))?;
    let mut reverted = RevertedSettlement {
        marker,
        restored: Vec::new(),
        copied: Vec::new(),
        left_closed: Vec::new(),
        retracted: None,
    };
    let Some(kept) = kept else {
        return Ok(reverted);
    };
    for loser in superseded {
        match restore_member_in_txn(vault, txn, kept, loser, resolved, &SETTLEMENT_REVERT, now)? {
            MemberRestore::Restored => reverted.restored.push(loser),
            MemberRestore::Copied(copy) => reverted.copied.push((loser, copy)),
            MemberRestore::LeftClosed => reverted.left_closed.push(loser),
        }
    }
    // A winner this settlement landed from its marker's retained candidates
    // is retracted with it (FIX 496), unless a later write already closed
    // it. A winner that stood before the settlement keeps standing.
    if born == Some(kept)
        && vault
            .get_claim_in_txn(txn, &kept)?
            .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
    {
        vault.retract_claim_in_txn_as(txn, &kept, now, Some(reverter))?;
        reverted.retracted = Some(kept);
    }
    Ok(reverted)
}

/// Where a revert's fresh Dreamer copy says it came from: its provenance
/// surface and its birth reason.
pub(super) struct RevertSurface {
    pub(super) surface: &'static str,
    pub(super) birth: &'static str,
}

const SETTLEMENT_REVERT: RevertSurface = RevertSurface {
    surface: "conflict_settlement_revert",
    birth: "dreamer.settlement_revert",
};

/// How a member a reverted write superseded stands after the revert.
pub(super) enum MemberRestore {
    /// In place, its `supersedes` link gone.
    Restored,
    /// As the Dreamer's fresh copy of its own MACHINE member.
    Copied(EntityId),
    /// As it was: a later write closed it, or another standing claim
    /// supersedes it too.
    LeftClosed,
}

/// Stands `loser` again after `kept`, the write the owner took back (or the
/// member a reverted answer kept), superseded it: in place, or, for a
/// Dreamer-born MACHINE member whose signed history never reopens, as the
/// Dreamer's fresh copy born of it and of `reverted`. A member another
/// standing claim supersedes too stays closed, so the revert undoes no
/// write but its own.
pub(super) fn restore_member_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kept: EntityId,
    loser: EntityId,
    reverted: EntityId,
    surface: &RevertSurface,
    now: u64,
) -> Result<MemberRestore> {
    if superseded_elsewhere_in_txn(vault, txn, kept, loser)? {
        return Ok(MemberRestore::LeftClosed);
    }
    if vault.restore_superseded_claim_in_txn(txn, &kept, &loser, now)? {
        return Ok(MemberRestore::Restored);
    }
    Ok(
        restore_dreamer_member_in_txn(vault, txn, kept, loser, reverted, surface, now)?
            .map_or(MemberRestore::LeftClosed, MemberRestore::Copied),
    )
}

/// Whether a standing claim other than `kept` supersedes `loser` as well.
/// Every superseder is read: past the scan's threshold row it raises one
/// check and reads on (rule 5).
fn superseded_elsewhere_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kept: EntityId,
    loser: EntityId,
) -> Result<bool> {
    use crate::ports::{EdgeDirection, EdgeStoreRead};
    use crate::scan_check::{EngineScan, ScanCount};
    let kind = crate::edge::EdgeKind::Supersedes;
    let scope = [
        &[EdgeDirection::In as u8][..],
        loser.as_bytes(),
        &[kind as u8][..],
    ]
    .concat();
    let mut count = ScanCount::start(&vault.store, txn, EngineScan::EdgePeerRows, &scope)?;
    let mut standing = false;
    for peer in vault.port_edge_peers(txn, &loser, EdgeDirection::In, kind)? {
        count.row();
        let peer = peer?;
        if peer != kept
            && vault
                .get_claim_in_txn(txn, &peer)?
                .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
        {
            standing = true;
            break;
        }
    }
    count.finish(vault);
    Ok(standing)
}

/// Stands a Dreamer-born MACHINE member `loser` again as the Dreamer's fresh
/// copy of it, when `kept` superseded it and it is still closed: the copy
/// carries its predicate, value, confidence, window and axes, and is born of
/// the member and the reverted write. `None` for any other member.
fn restore_dreamer_member_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kept: EntityId,
    loser: EntityId,
    reverted: EntityId,
    surface: &RevertSurface,
    now: u64,
) -> Result<Option<EntityId>> {
    use crate::ports::EdgeStoreRead;
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    let Some(body) = vault.get_claim_in_txn(txn, &loser)? else {
        return Ok(None);
    };
    if body.lifecycle != ClaimLifecycleStatus::Superseded
        || crate::memory::claim_author(&body) != Some(dreamer)
        || !crate::authority::machine_claim_needs_history(&vault.store, txn, &body)?
    {
        return Ok(None);
    }
    if vault
        .port_edge_get(&*txn, &kept, crate::edge::EdgeKind::Supersedes, &loser)?
        .is_none()
    {
        return Ok(None);
    }
    let candidate = super::persistence::on_axes_of(
        crate::write_envelope::ClaimCandidate::new(
            body.predicate.clone(),
            body.subject,
            body.value.clone(),
            body.confidence,
        )
        .with_validity(body.valid_from, None),
        &body,
    );
    let mut envelope = WriteEnvelope::new(
        WriteActor::new(dreamer, crate::edge::EdgeActorClass::System),
        body.source.unwrap_or(ClaimSource::Generated),
        crate::write_envelope::WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from(surface.surface)),
            (
                Value::from("restores"),
                Value::Binary(loser.as_bytes().to_vec()),
            ),
            (
                Value::from("reverted"),
                Value::Binary(reverted.as_bytes().to_vec()),
            ),
        ]))?,
        if body.approval == ClaimApprovalStatus::Proposed {
            ClaimApprovalStatus::Proposed
        } else {
            ClaimApprovalStatus::Auto
        },
    );
    let copy = EntityId::now();
    let birth = RowBirth::written(
        envelope.actor(),
        MadeByClass::Concluded,
        surface.birth,
        &[loser, reverted],
        &[],
        now,
    );
    vault.sign_retained_machine_claim_in_txn(&*txn, &copy, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &copy,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(&copy, birth)
        .apply(txn)?;
    Ok(Some(copy))
}

/// The dial a settlement ask runs under unless the host picks another. It
/// ends below Human: the owner's open-conflict list is already the person's
/// surface, so the ladder queues no second ask.
pub const CONFLICT_SETTLE_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

const HOLD_BOTH: &str = "hold_both";
const DISMISS: &str = "dismiss";
const ESCALATE: &str = "escalate";
const KEEP_PREFIX: &str = "keep:";

/// The shared decision path a settlement ask goes through: the host's ladder,
/// the principal the answer is for, the dial and learned bands, the host's
/// wording of the question, and the call's clock. A provider sees the marker
/// and its members as evidence ids; the contested predicates and each member's
/// predicate, value, source, approval and window are its state. Past the
/// ladder's bound, each member rides by id with a preview of its value.
pub struct ConflictSettleDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub deadline: &'a RetrievalDeadline,
}

impl ConflictSettleDecisions<'_> {
    /// Rules on one open conflict: `None` when the ladder abstains, escalates
    /// or answers outside the vocabulary. Past the ladder's state bound, every
    /// member is still asked about, by id with its value's text cut to fit; a
    /// conflict whose ids alone pass the bound is the ladder's refusal. Only a
    /// standing member can be kept. The question is keyed by the contested
    /// predicates, so each learns its own bands.
    pub fn rule(
        &self,
        vault: &Vault,
        conflict: &OpenConflict,
    ) -> Result<Option<ConflictSettlement>> {
        let txn = vault.store.env.read_txn()?;
        let mut members = Vec::new();
        let mut values = Vec::new();
        let mut keepable = Vec::new();
        for id in &conflict.members {
            let Some(body) = vault.get_claim_in_txn(&txn, id)? else {
                continue;
            };
            let standing = claim_surfaceable(&body);
            if standing && keepable.len() < MAX_KEEP_OPTIONS {
                keepable.push(*id);
            }
            let value = rmpv_to_json(&body.value);
            values.push((id.to_hex(), value.to_string()));
            members.push(json!({
                "id": id.to_hex(),
                "keep_option": standing.then(|| format!("{KEEP_PREFIX}{}", id.to_hex())),
                "predicate": body.predicate,
                "value": value,
                "source": body.source.map(|source| source.as_str()),
                "approval": body.approval.as_str(),
                "confidence": body.confidence,
                "valid_from": body.valid_from,
                "valid_to": body.valid_to,
            }));
        }
        drop(txn);
        // A candidate the round dropped rides as retained, never as a stored
        // claim; keeping it lands it (FIX 496). One whose staged Keep the
        // owner declined is the owner's to keep again, never this ladder's
        // (FIX 7072).
        for alternative in conflict
            .alternatives
            .iter()
            .filter(|alternative| alternative.declined.is_empty())
        {
            let keep_option = if keepable.len() < MAX_KEEP_OPTIONS {
                keepable.push(alternative.id);
                Some(format!("{KEEP_PREFIX}{}", alternative.id.to_hex()))
            } else {
                None
            };
            let value = rmpv_to_json(&alternative.value);
            values.push((alternative.id.to_hex(), value.to_string()));
            members.push(json!({
                "id": alternative.id.to_hex(),
                "keep_option": keep_option,
                "retained": true,
                "predicate": alternative.predicate,
                "value": value,
                "source": alternative.source.as_str(),
                "confidence": alternative.confidence,
            }));
        }
        // Whole, each member rides with its claim's fields; past the bound, by
        // id with its value's canonical text cut to fit, never one left out.
        let whole = json!({
            "predicates": conflict.predicates,
            "members": members,
        });
        let longest = values.iter().map(|(_, text)| text.len()).max().unwrap_or(0);
        let state = fit_state(longest, |cut| {
            if cut.is_none() {
                return whole.clone();
            }
            let members: Vec<_> = values
                .iter()
                .map(|(id, text)| json!({"id": id, "value": cut_text(text, cut)}))
                .collect();
            json!({
                "predicates": conflict.predicates,
                "members": members,
                "cut_at_bytes": cut,
            })
        });
        let mut options: Vec<String> = [HOLD_BOTH, DISMISS, ESCALATE]
            .iter()
            .map(|label| (*label).to_owned())
            .collect();
        options.extend(
            keepable
                .iter()
                .map(|id| format!("{KEEP_PREFIX}{}", id.to_hex())),
        );
        let key = conflict.predicates.join("\n");
        let question = CONFLICT_SETTLE.question(
            &[key.as_bytes()],
            self.wording.clone(),
            AnswerContract::Choice { options },
        )?;
        let mut evidence = vec![conflict.marker];
        evidence.extend(conflict.members.iter().copied());
        // Keeping one closes the others, so a cut abstains rather than taking
        // a held answer.
        let decision = self.ladder.run(
            &question,
            self.principal,
            &evidence,
            &state,
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            self.deadline,
        )?;
        let DecisionAnswer::Choice(answer) = &decision.answer else {
            return Ok(None);
        };
        Ok(match answer.as_str() {
            HOLD_BOTH => Some(ConflictSettlement::HoldBoth),
            DISMISS => Some(ConflictSettlement::Dismiss),
            other => other.strip_prefix(KEEP_PREFIX).and_then(|hex| {
                keepable
                    .iter()
                    .find(|id| id.to_hex() == hex)
                    .map(|id| ConflictSettlement::Keep(*id))
            }),
        })
    }
}

/// One Dreamer pass over the parked conflicts it reviews.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParkedConflictPass {
    pub asked: usize,
    pub settled: Vec<ConflictSettleReceipt>,
    /// Kept alternatives from imported words, staged in their import's
    /// review (FIX 5754): each conflict stays open.
    pub staged: Vec<StagedKeep>,
    /// Abstained, escalated, refused or failed: each stays for the owner.
    pub left_parked: usize,
    /// The last marker asked about: the next pass starts after it.
    pub last: Option<EntityId>,
}

/// Asks `decisions` about up to `limit` open conflicts `memory`'s actor may
/// settle and settles each answer through the same authorised door a person
/// uses. The pass starts at the first marker after `after` and wraps to the
/// oldest, so the conflicts a ladder leaves parked never starve newer ones.
/// A failure on one conflict is logged by a closed name and leaves it
/// parked; the pass goes on.
pub fn settle_parked_conflicts(
    memory: &crate::memory::Memory<'_>,
    decisions: &ConflictSettleDecisions<'_>,
    after: Option<EntityId>,
    limit: usize,
    now: u64,
) -> crate::memory::MemoryResult<ParkedConflictPass> {
    settle_parked_conflicts_while(memory, decisions, after, limit, now, &mut || true)
}

/// [`settle_parked_conflicts`] under a host's pause (FIX 7376): no next
/// conflict is asked once `may_start` says no. The one in flight finishes
/// its ruling and settlement, and the pass returns as it stands. A conflict
/// left unasked is neither counted nor left parked: `last` stays on the last
/// one asked, and the next pass starts after it.
pub fn settle_parked_conflicts_while(
    memory: &crate::memory::Memory<'_>,
    decisions: &ConflictSettleDecisions<'_>,
    after: Option<EntityId>,
    limit: usize,
    now: u64,
    may_start: &mut impl FnMut() -> bool,
) -> crate::memory::MemoryResult<ParkedConflictPass> {
    let mut pass = ParkedConflictPass::default();
    let open = memory.open_conflicts(None, None, usize::MAX)?;
    let start = after.map_or(0, |after| {
        open.partition_point(|conflict| conflict.marker <= after)
    });
    let (older, newer) = open.split_at(start);
    for conflict in newer.iter().chain(older).take(limit) {
        if !may_start() {
            break;
        }
        pass.asked += 1;
        pass.last = Some(conflict.marker);
        let settlement = match decisions.rule(memory.vault(), conflict) {
            Ok(Some(settlement)) => settlement,
            Ok(None) => {
                pass.left_parked += 1;
                continue;
            }
            Err(error) => {
                tracing::warn!(target: "oneiron::dreamer", kind = ?error.kind(), marker = %conflict.marker.to_hex(), "a settlement ask failed; the conflict stays parked");
                pass.left_parked += 1;
                continue;
            }
        };
        match memory.settle_conflict(None, conflict.marker, settlement, now) {
            Ok(ConflictSettleOutcome::Settled(receipt)) => pass.settled.push(receipt),
            Ok(ConflictSettleOutcome::ImportReviewPending { staged, .. }) => {
                pass.staged.push(staged);
            }
            Err(_) => {
                tracing::warn!(target: "oneiron::dreamer", marker = %conflict.marker.to_hex(), "a ruled settlement was refused; the conflict stays parked");
                pass.left_parked += 1;
            }
        }
    }
    Ok(pass)
}
