//! Skill judgments on the shared typed-decision ladder. Hosts supply replay
//! data and wording; neither can return a score that bypasses the ladder.

use std::collections::BTreeMap;

use crate::llm::decision::catalogue::SKILL_OPTIMIZE_JUDGMENT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionQuestion, Reversibility, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result};
use serde_json::{Value, json};

use super::{
    BlindPreference, HeldOutReplayCase, HeldOutReplayNotes, HonestyReplayObservation,
    PreferredResponse,
};

/// The Coach uses the host's existing provider slots, policy and one clock.
/// Wording keys are score, structural, contrastive, preference, task_success,
/// honesty, tradeoff, live_axis, and axis.<name>. No prompt or model is
/// selected by the engine.
pub struct SkillOptimizeDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub deadline: &'a RetrievalDeadline,
    pub wording: &'a BTreeMap<String, String>,
}

/// Most blind preference pairs one contrastive audit judges.
const MAX_BLIND_PAIRS: usize = 32;

/// A response-only pair sampled without the instructions, scores or labels.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillReplayPair {
    pub pair_ref: String,
    pub state: Value,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

/// Every wording key but `axis.<name>`, which names its axis in the state.
const JUDGMENT_KINDS: [&str; 8] = [
    "score",
    "structural",
    "contrastive",
    "preference",
    "task_success",
    "honesty",
    "tradeoff",
    "live_axis",
];

/// The wording key a kept judgment was asked under: the one whose question,
/// rebuilt from the kept revision and wording, has the kept id. `None` for a
/// question no key rebuilds.
#[must_use]
pub fn judgment_kind(revision: &str, question: &DecisionQuestion, state: &Value) -> Option<String> {
    let named = state
        .get("axis")
        .and_then(Value::as_str)
        .map(|axis| format!("axis.{axis}"));
    JUDGMENT_KINDS
        .iter()
        .map(|kind| (*kind).to_owned())
        .chain(named)
        .find(|kind| {
            SKILL_OPTIMIZE_JUDGMENT
                .question(
                    &[revision.as_bytes(), kind.as_bytes()],
                    question.text.clone(),
                    question.contract.clone(),
                )
                .is_ok_and(|rebuilt| rebuilt.id == question.id)
        })
}

impl SkillOptimizeDecisions<'_> {
    pub(crate) fn decide(
        &self,
        revision: &str,
        kind: &str,
        evidence: &[EntityId],
        state: &Value,
        contract: AnswerContract,
        dial: Option<DecisionDial>,
    ) -> Result<(DecisionQuestion, TypedDecision)> {
        let text = self
            .wording
            .get(kind)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| invalid("missing skill judgment wording"))?;
        let question = SKILL_OPTIMIZE_JUDGMENT.question(
            &[revision.as_bytes(), kind.as_bytes()],
            text.clone(),
            contract,
        )?;
        let decision = self.ladder.run(
            &question,
            self.principal,
            evidence,
            state,
            dial.unwrap_or(self.dial),
            &self.bands,
            Reversibility::ReversibleRead,
            self.deadline,
        )?;
        Ok((question, decision))
    }
}

fn ask<S: HeldOutReplayNotes + ?Sized>(
    scorer: &S,
    kind: &str,
    evidence: &[EntityId],
    state: &Value,
    contract: AnswerContract,
) -> Result<TypedDecision> {
    let (question, decision) = scorer.decisions().decide(
        scorer.judge_revision(),
        kind,
        evidence,
        state,
        contract,
        None,
    )?;
    scorer.record_decision(&question, &decision, state)?;
    Ok(decision)
}

fn score<S: HeldOutReplayNotes + ?Sized>(
    scorer: &S,
    kind: &str,
    evidence: &[EntityId],
    state: &Value,
) -> Result<f32> {
    let decision = ask(
        scorer,
        kind,
        evidence,
        state,
        AnswerContract::Score { min: 0.0, max: 1.0 },
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
        _ => Err(invalid("skill judgment abstained or requested escalation")),
    }
}

fn case_state<S: HeldOutReplayNotes + ?Sized>(
    scorer: &S,
    case: &HeldOutReplayCase<'_>,
) -> Result<Value> {
    Ok(json!({
        "skill": case.skill.to_hex(), "skill_id": case.skill_id,
        "version": case.version, "instructions": case.instructions,
        "held_out_receipts": case.held_out_receipts,
        "replay": scorer.replay_state(case)?,
    }))
}

impl dyn HeldOutReplayNotes + '_ {
    /// All replay judgments, including shared-skill admission, use decide().
    pub fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        score(self, "score", &[case.skill], &case_state(self, case)?)
    }

    pub fn score_goal_axis(
        &self,
        case: &HeldOutReplayCase<'_>,
        axis: &super::GoalAxisSpec,
    ) -> Result<f32> {
        if axis.name == "coverage"
            && self.coverage_floor().is_some()
            && axis.kind != super::GoalAxisKind::Floor
        {
            return Err(invalid("coverage is a floor axis"));
        }
        self.score_named_axis(case, &axis.name)
    }

    pub(crate) fn score_named_axis(&self, case: &HeldOutReplayCase<'_>, axis: &str) -> Result<f32> {
        if axis == "coverage"
            && let Some(comparison) = self.coverage_floor()
        {
            return comparison.score_case(case);
        }
        // The axis and its declared kind ride in the state, so a kept
        // judgment says what it scored, and whether that was a floor.
        let mut state = case_state(self, case)?;
        state["axis"] = json!(axis);
        state["axis_kind"] = json!(self.axis_kind(case, axis));
        score(self, &format!("axis.{axis}"), &[case.skill], &state)
    }

    /// The kind `case`'s skill goal declares `axis`; `None` when the goal
    /// can't be read or doesn't name it.
    fn axis_kind(&self, case: &HeldOutReplayCase<'_>, axis: &str) -> Option<super::GoalAxisKind> {
        self.goal_axes(case)
            .ok()?
            .into_iter()
            .find(|spec| spec.name == axis)
            .map(|spec| spec.kind)
    }

    pub(crate) fn structural_audit(&self, task: &str, instructions: &str) -> Result<f32> {
        score(
            self,
            "structural",
            &[],
            &json!({"task": task, "instructions": instructions}),
        )
    }

    pub(crate) fn blind_preference(
        &self,
        task: &str,
        receipts: &[String],
    ) -> Result<Vec<BlindPreference>> {
        // The sample is the first 32 pairs, same-task pairs first as
        // `blind_pairs` orders them: a size that selects, never one that
        // refuses. No pair at all abstains.
        let mut pairs = self.blind_pairs(task, receipts)?;
        pairs.truncate(MAX_BLIND_PAIRS);
        if pairs.is_empty() {
            return Err(invalid("contrastive audit has no response pair to judge"));
        }
        let mut preferences = Vec::with_capacity(pairs.len());
        for pair in pairs {
            let decision = ask(
                self,
                "preference",
                &[],
                &json!({
                    "task": task, "pair_ref": pair.pair_ref, "responses": pair.state,
                }),
                AnswerContract::Choice {
                    options: vec!["first".into(), "second".into()],
                },
            )?;
            let preferred = match decision.answer {
                DecisionAnswer::Choice(ref choice)
                    if decision.human_ask.is_none()
                        && decision
                            .probability
                            .is_some_and(|p| p >= decision.receipt.band.high) =>
                {
                    match choice.as_str() {
                        "first" => PreferredResponse::First,
                        "second" => PreferredResponse::Second,
                        _ => return Err(invalid("invalid response preference")),
                    }
                }
                _ => return Err(invalid("blind preference abstained")),
            };
            preferences.push(BlindPreference {
                pair_ref: pair.pair_ref,
                preferred,
            });
        }
        Ok(preferences)
    }

    pub(crate) fn contrastive_audit(
        &self,
        case: &HeldOutReplayCase<'_>,
        blind: &[BlindPreference],
    ) -> Result<f32> {
        let state = json!({"case": case_state(self, case)?, "blind_preferences": blind});
        score(self, "contrastive", &[case.skill], &state)
    }

    pub(crate) fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        case.held_out_receipts
            .iter()
            .map(|receipt| {
                let receipts = [receipt.clone()];
                let one = HeldOutReplayCase {
                    held_out_receipts: &receipts,
                    ..*case
                };
                score(
                    self,
                    "task_success",
                    &[case.skill],
                    &case_state(self, &one)?,
                )
            })
            .collect()
    }

    /// Whether `receipt`'s live run met a goal axis under `arm`, one arm of a
    /// live slice of `skill`'s goal: `criterion` names the axis, and for a
    /// project goal its measure and bound, beside the run's replay under the
    /// arm's instructions. Only a decided yes is a success; an abstained or
    /// escalated finding fails the pull rather than counting either way.
    /// # Errors
    /// An abstained or escalated finding, or the host's replay and journal errors.
    pub fn live_axis_met(
        &self,
        skill: EntityId,
        arm: &crate::skill::SkillRecord,
        receipt: &str,
        criterion: &Value,
    ) -> Result<bool> {
        let receipts = [receipt.to_owned()];
        let case = HeldOutReplayCase {
            skill,
            skill_id: &arm.skill_id,
            version: &arm.version,
            instructions: &arm.desc,
            held_out_receipts: &receipts,
        };
        // The criterion's own kind when the host sent one, else the kind the
        // goal declares now: either way it is frozen with the question, so a
        // later floor test never reads it from a goal revised since.
        let kind = criterion
            .get("kind")
            .and_then(|kind| serde_json::from_value::<super::GoalAxisKind>(kind.clone()).ok())
            .or_else(|| {
                criterion
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|name| self.axis_kind(&case, name))
            });
        let decision = ask(
            self,
            "live_axis",
            &[skill],
            &json!({"case": case_state(self, &case)?, "axis": criterion, "axis_kind": kind}),
            AnswerContract::Noul,
        )?;
        match decision.answer {
            DecisionAnswer::Noul(met)
                if decision.human_ask.is_none()
                    && decision
                        .probability
                        .is_some_and(|p| p >= decision.receipt.band.high) =>
            {
                Ok(met)
            }
            _ => Err(invalid("live axis finding abstained")),
        }
    }

    /// Every objective of every held-out replay, put to the hidden-flaw
    /// question one at a time. The counts are the decided findings; an
    /// abstained or escalated finding fails the audit rather than counting.
    pub(crate) fn replay_honesty(
        &self,
        case: &HeldOutReplayCase<'_>,
    ) -> Result<Vec<HonestyReplayObservation>> {
        self.honesty_replays(case)?
            .into_iter()
            .map(|replay| {
                let mut hidden_flaws = 0_u32;
                for objective in &replay.objectives {
                    let decision = ask(
                        self,
                        "honesty",
                        &[case.skill],
                        &json!({
                            "skill": case.skill.to_hex(),
                            "skill_id": case.skill_id, "version": case.version,
                            "instructions": case.instructions, "receipt": replay.receipt,
                            "replay": replay.state, "objective": objective,
                        }),
                        AnswerContract::Noul,
                    )?;
                    match decision.answer {
                        DecisionAnswer::Noul(flawed)
                            if decision.human_ask.is_none()
                                && decision
                                    .probability
                                    .is_some_and(|p| p >= decision.receipt.band.high) =>
                        {
                            hidden_flaws += u32::from(flawed);
                        }
                        _ => return Err(invalid("honesty finding abstained")),
                    }
                }
                Ok(HonestyReplayObservation {
                    checked_objectives: u32::try_from(replay.objectives.len())
                        .map_err(|_| invalid("honesty replay objective count overflow"))?,
                    receipt: replay.receipt,
                    hidden_flaws,
                })
            })
            .collect()
    }

    pub(crate) fn tradeoff_decision(
        &self,
        question: &super::SkillTradeoffQuestion,
        band: crate::llm::decision::DecisionBand,
    ) -> Result<Option<TypedDecision>> {
        let decisions = self.decisions();
        if decisions.dial.first == crate::llm::decision::DecisionRung::Human {
            return Ok(None);
        }
        // This job owns the durable role ask. The shared ladder supplies the
        // model judgments below it, without queuing a duplicate person ask.
        let dial = DecisionDial {
            ceiling: decisions
                .dial
                .ceiling
                .min(crate::llm::decision::DecisionRung::Big),
            band,
            ..decisions.dial
        };
        let state = json!({"question": question, "digest": question.digest()?});
        let (typed, decision) = decisions.decide(
            self.judge_revision(),
            "tradeoff",
            &[question.proposal, question.goal_id],
            &state,
            AnswerContract::Choice {
                options: vec!["approve".into(), "reject".into(), "ask_up".into()],
            },
            Some(dial),
        )?;
        self.record_decision(&typed, &decision, &state)?;
        Ok(Some(decision))
    }
}
