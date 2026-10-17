//! Settling a parked contradiction (OF-023; ARCH-0003 `dr:H0636-4`).
//!
//! A `conflict.open` marker stays open until a standing `conflict.resolved`
//! names it. The Dreamer's own correction closes the markers its replacement
//! answers (`dreamer_promotion/corrections.rs`); every other marker waits here
//! for an authorised responder: the vault's root owner, or a person or agent
//! the owner delegated `memory.conflict_review` on the conflict's subject
//! (`Memory::settle_conflict`).
//!
//! A responder keeps one member, holds them all, or dismisses the marker.
//! Keeping one supersedes each other live member with it, so the winner is
//! the ordinary `supersedes` edge and no Conflict entity exists. Holding them
//! all leaves every member active: the observed-versus-stated answer, where
//! `observed` never outranks `user_stated`. The open marker is never edited;
//! it stays as audit evidence beside the claim that answers it.
//!
//! The Dreamer asks its host's decision ladder ([`ConflictSettleDecisions`])
//! and settles only what its own delegation covers. A ladder answer is never
//! the authority: an abstention, an escalation or a missing Grant leaves the
//! marker parked for the owner.

use std::collections::BTreeSet;

use rmpv::Value;
use serde_json::json;

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
    DecisionRung, MAX_DECISION_STATE_BYTES, Reversibility,
};
use crate::provenance::birth::{MAX_BIRTH_INPUTS, RowBirth};
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

/// A responder's answer to one open conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSettlement {
    /// This member stands, and each other live member is superseded by it.
    Keep(EntityId),
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
            Self::HoldBoth => "hold_both",
            Self::Dismiss => "dismiss",
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
    pub members: Vec<EntityId>,
    /// The contested predicates, as the marker records them.
    pub predicates: Vec<String>,
    /// The marker itself, still Proposed while it waits in its own review.
    pub body: ClaimBody,
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

fn string_at<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
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
) -> Result<Option<OpenConflict>> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    let mut members = Vec::new();
    for id in named_ids(&body) {
        if vault
            .get_claim_in_txn(txn, &id)?
            .is_some_and(|member| member.predicate != PREDICATE_CONFLICT_OPEN)
        {
            members.push(id);
        }
    }
    Ok(Some(OpenConflict {
        marker,
        subject,
        members,
        predicates: contested_predicates(&body),
        body,
    }))
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
    let mut sort = |id: EntityId, body: ClaimBody| {
        if body.predicate == PREDICATE_CONFLICT_RESOLVED {
            if claim_surfaceable(&body) {
                answered.extend(marker_ids(&body.value, "open_marker"));
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
        if let Some(conflict) = open_conflict_from(vault, txn, id, body)? {
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
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(answer) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if answer.predicate == PREDICATE_CONFLICT_RESOLVED
            && claim_surfaceable(&answer)
            && marker_ids(&answer.value, "open_marker").any(|named| named == marker)
        {
            return Err(invalid_consolidation("the conflict is already settled"));
        }
    }
    open_conflict_from(vault, txn, marker, body)?.ok_or(invalid_consolidation("conflict subject"))
}

/// Writes `settlement` for `conflict` in the caller's transaction, after the
/// caller has checked the responder's authority. `Keep` needs a standing
/// member on the conflict's own subject; each other Active member on that
/// subject is superseded by it (a staged replacement that lost drops its
/// binding, and a pending review tray closes), under the claim lifecycle's
/// own guards: a generated claim still never supersedes user-stated truth.
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
) -> Result<SettledConflict> {
    let on_subject =
        |body: &ClaimBody| matches!(body.subject, ClaimSubject::Entity(s) if s == conflict.subject);
    let mut superseded = Vec::new();
    if let ConflictSettlement::Keep(winner) = settlement {
        if !conflict.members.contains(&winner) {
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
    }
    let mut resolution = vec![(Value::from("settlement"), Value::from(settlement.label()))];
    if let ConflictSettlement::Keep(winner) = settlement {
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
    let candidate = super::persistence::resolved_candidate(
        &conflict.body,
        conflict.marker,
        Value::Map(resolution),
    );
    let resolved = EntityId::now();
    // Rule A: the answer is concluded from the marker it settles and the
    // members it weighed, the first MAX_BIRTH_INPUTS of them.
    let birth = {
        let inputs: Vec<EntityId> = std::iter::once(conflict.marker)
            .chain(conflict.members.iter().copied())
            .take(MAX_BIRTH_INPUTS)
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
    Ok(SettledConflict {
        resolved,
        superseded,
    })
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
/// predicate, value, source, approval and window are its bounded state.
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
    /// or answers outside the vocabulary, or the conflict's state is past the
    /// ladder's bound. Only a standing member can be kept. The question is
    /// keyed by the contested predicates, so each learns its own bands.
    pub fn rule(
        &self,
        vault: &Vault,
        conflict: &OpenConflict,
    ) -> Result<Option<ConflictSettlement>> {
        let txn = vault.store.env.read_txn()?;
        let mut members = Vec::new();
        let mut keepable = Vec::new();
        for id in &conflict.members {
            let Some(body) = vault.get_claim_in_txn(&txn, id)? else {
                continue;
            };
            let standing = claim_surfaceable(&body);
            if standing && keepable.len() < MAX_KEEP_OPTIONS {
                keepable.push(*id);
            }
            members.push(json!({
                "id": id.to_hex(),
                "keep_option": standing.then(|| format!("{KEEP_PREFIX}{}", id.to_hex())),
                "predicate": body.predicate,
                "value": rmpv_to_json(&body.value),
                "source": body.source.map(|source| source.as_str()),
                "approval": body.approval.as_str(),
                "confidence": body.confidence,
                "valid_from": body.valid_from,
                "valid_to": body.valid_to,
            }));
        }
        drop(txn);
        let state = json!({
            "predicates": conflict.predicates,
            "members": members,
        });
        if serde_json::to_vec(&state).map_or(true, |bytes| bytes.len() > MAX_DECISION_STATE_BYTES) {
            return Ok(None);
        }
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

/// One Dreamer pass over the parked conflicts its delegation covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParkedConflictPass {
    pub asked: usize,
    pub settled: Vec<ConflictSettleReceipt>,
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
    let mut pass = ParkedConflictPass::default();
    let open = memory.open_conflicts(None, None, usize::MAX)?;
    let start = after.map_or(0, |after| {
        open.partition_point(|conflict| conflict.marker <= after)
    });
    let (older, newer) = open.split_at(start);
    for conflict in newer.iter().chain(older).take(limit) {
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
            Ok(receipt) => pass.settled.push(receipt),
            Err(_) => {
                tracing::warn!(target: "oneiron::dreamer", marker = %conflict.marker.to_hex(), "a ruled settlement was refused; the conflict stays parked");
                pass.left_parked += 1;
            }
        }
    }
    Ok(pass)
}
