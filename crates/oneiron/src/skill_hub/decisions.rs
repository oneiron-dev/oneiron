//! The merge doors' typed questions (OF-493) on the host's ladder: the one useful-upstream
//! yes/no both doors ask, and a claim refinement's held-out replay score. Neither door takes a
//! host's answer; each reads the ladder's typed receipt.

use serde_json::{Value, json};

use super::package_codec::invalid;
use super::{HubPackage, SharedSkillDelta};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::llm::decision::catalogue::CLAIM_REPLAY;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionQuestion, MAX_DECISION_STATE_BYTES, Reversibility, TypedDecision, cut_text, fit_state,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill::SkillRecord;
use crate::{EntityId, Result};

/// The host's typed path for the useful-upstream question: its ladder, dial, learned bands
/// and the call's clock. The question is the prepared ask's own, bound to its candidate, and
/// the ask's resident is the principal. The doors still check that the receipt names both and
/// that a System One or escalation seat answered first.
pub struct UsefulUpstreamDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub deadline: &'a RetrievalDeadline,
}

impl UsefulUpstreamDecisions<'_> {
    pub(super) fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        evidence: &[EntityId],
        state: &Value,
        reversibility: Reversibility,
    ) -> Result<TypedDecision> {
        self.ladder.run(
            question,
            resident,
            evidence,
            state,
            self.dial,
            &self.bands,
            reversibility,
            self.deadline,
        )
    }
}

/// A submitted shared-skill delta as the useful-upstream question reads it: the base's
/// instructions beside the package's SKILL.md, the delta's provenance and the package's file
/// count. Both texts are cut, halving, until the whole fits; a provider reads the candidate by
/// id for the rest.
pub(super) fn shared_skill_state(
    resident: EntityId,
    base: (EntityId, &SkillRecord, &str),
    candidate: (EntityId, &SkillRecord, &HubPackage),
    delta: &SharedSkillDelta,
) -> Value {
    let (base_id, base, baseline) = base;
    let (candidate_id, record, package) = candidate;
    let proposed = package
        .files
        .iter()
        .find(|file| file.path == "SKILL.md")
        .map(|file| String::from_utf8_lossy(&file.content))
        .unwrap_or_default();
    fit_state(baseline.len().max(proposed.len()), |cut| {
        json!({
            "resident": resident.to_hex(),
            "base": {
                "id": base_id.to_hex(), "skill_id": base.skill_id, "version": base.version,
                "instructions": cut_text(baseline, cut),
            },
            "candidate": {
                "id": candidate_id.to_hex(), "skill_id": record.skill_id,
                "version": record.version, "instructions": cut_text(&proposed, cut),
                "files": package.files.len(),
            },
            "delta": delta,
        })
    })
}

/// A session-branch claim edit as the useful-upstream question reads it: the base claim and
/// the proposed one, values cut, halving, until the whole fits.
pub(super) fn claim_pair_state(
    resident: EntityId,
    base: (EntityId, &ClaimBody),
    candidate: (EntityId, &ClaimBody),
) -> Value {
    let base_text = value_text(base.1);
    let candidate_text = value_text(candidate.1);
    fit_state(base_text.len().max(candidate_text.len()), |cut| {
        json!({
            "resident": resident.to_hex(),
            "base": claim_state(base.0, base.1, cut_text(&base_text, cut)),
            "candidate": claim_state(candidate.0, candidate.1, cut_text(&candidate_text, cut)),
        })
    })
}

/// The host's typed path for a claim refinement's held-out replay: its ladder, dial, learned
/// bands, its wording of the `[0, 1]` score and the call's clock. Each arm is one question
/// over the same owner-reserved labels, and the ask's resident is the principal.
pub struct ClaimReplayDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub deadline: &'a RetrievalDeadline,
}

impl ClaimReplayDecisions<'_> {
    /// How well one arm's claim fits the owner's held-out labels, from 0 to 1. Every label is
    /// an evidence id, and state as far as the labels fit (`labels_omitted` counts the rest).
    /// An abstained, escalated or unconfident score fails the merge before it settles.
    pub(super) fn score(
        &self,
        resident: EntityId,
        arm: &str,
        scored: (EntityId, &ClaimBody),
        labels: &[(EntityId, ClaimBody)],
    ) -> Result<f32> {
        let question = CLAIM_REPLAY.question(
            &[],
            self.wording.clone(),
            AnswerContract::Score { min: 0.0, max: 1.0 },
        )?;
        let mut evidence = vec![scored.0];
        evidence.extend(labels.iter().map(|(id, _)| *id));
        // The arm's claim is admitted with the score, and an admitted claim edit has no undo.
        let decision = self.ladder.run(
            &question,
            resident,
            &evidence,
            &replay_state(arm, scored, labels),
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            self.deadline,
        )?;
        match decision.answer {
            DecisionAnswer::Score(value)
                if decision.human_ask.is_none()
                    && decision
                        .probability
                        .is_some_and(|p| p >= decision.receipt.band.high) =>
            {
                Ok(value as f32)
            }
            _ => Err(invalid(
                "held-out claim replay abstained or requested escalation",
            )),
        }
    }
}

/// The scored arm and the labels, values cut until the whole fits. Past what any cut fits,
/// the labels shown halve; the rest stay evidence ids, never dropped from the question.
fn replay_state(
    arm: &str,
    scored: (EntityId, &ClaimBody),
    labels: &[(EntityId, ClaimBody)],
) -> Value {
    let scored_text = value_text(scored.1);
    let texts: Vec<String> = labels.iter().map(|(_, body)| value_text(body)).collect();
    let longest = texts
        .iter()
        .map(String::len)
        .chain([scored_text.len()])
        .max()
        .unwrap_or(0);
    let mut shown = labels.len();
    loop {
        let state = fit_state(longest, |cut| {
            json!({
                "arm": arm,
                "claim": claim_state(scored.0, scored.1, cut_text(&scored_text, cut)),
                "labels": labels[..shown]
                    .iter()
                    .zip(&texts)
                    .map(|((id, body), text)| claim_state(*id, body, cut_text(text, cut)))
                    .collect::<Vec<_>>(),
                "labels_omitted": labels.len() - shown,
            })
        });
        let fits =
            serde_json::to_vec(&state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES);
        if fits || shown == 0 {
            return state;
        }
        shown /= 2;
    }
}

fn value_text(body: &ClaimBody) -> String {
    body.value
        .as_str()
        .map_or_else(|| body.value.to_string(), str::to_owned)
}

fn claim_state(id: EntityId, body: &ClaimBody, value: &str) -> Value {
    let subject = match &body.subject {
        ClaimSubject::Entity(entity) => json!(entity.to_hex()),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => json!({"from": source.to_hex(), "to": target.to_hex(), "edge": kind.name()}),
    };
    json!({
        "id": id.to_hex(),
        "subject": subject,
        "predicate": body.predicate,
        "value": value,
        "source": body.source.map(|source| source.as_str()),
        "approval": body.approval.as_str(),
        "confidence": body.confidence,
        "valid_from": body.valid_from,
        "valid_to": body.valid_to,
    })
}
