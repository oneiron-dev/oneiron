//! The typed pack that decides which listed claim each extracted candidate
//! corrects: one question per candidate and option group, over `none` and
//! the claims the listing shows about its subject. Its call shows every
//! question, subject and claim by a call-local label (FIX 7506 P2), field by
//! field, never by rewriting inside a value; its decisions keep the
//! canonical options. A candidate that restates a listed claim unchanged
//! reinforces it and is never asked whether it corrects it (FIX 8295).

use super::super::decisions::{id_options, named_id};
use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::llm::decision::AnswerContract;
use crate::llm::decision::catalogue::CORRECTION;

impl ConsolidationExecutor<'_> {
    /// Which listed claim each parsed candidate corrects, in order. A
    /// candidate whose subject the listing shows claims about, that its child
    /// may read and write, gets one question over `none` and those claims'
    /// ids, all candidates in one pack; one with no such claim, or no answer,
    /// corrects none. The pack's ask goes to its candidates' project's route,
    /// or to the owners when they span projects. None when the step trapped.
    pub(in crate::dreamer_consolidation) async fn decide_corrections(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &crate::dreamer_wake::WakePassDeadline,
        parsed: &[ParsedCandidate<'_>],
        resources: &BranchResources<'_>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<Correction>>> {
        let mut labels = CallLabelMap::default();
        let mut questions = Vec::new();
        // Each candidate's question indexes, and every listed claim asked about.
        let mut asks: Vec<Vec<usize>> = vec![Vec::new(); parsed.len()];
        let mut listed: Vec<(EntityId, EntityId, &str, &str)> = Vec::new();
        let pins = resources.pins();
        for (position, candidate) in parsed.iter().enumerate() {
            let shown: Vec<_> = pins
                .correctable(candidate.subject, candidate.scope)
                .filter(|(claim, ..)| !reinforces(candidate, resources, *claim))
                .collect();
            let ids: Vec<EntityId> = shown.iter().map(|(claim, ..)| *claim).collect();
            for (group, (options, wire_options)) in
                id_options(&ids, true, &mut labels).into_iter().enumerate()
            {
                let (position_key, group_key) = (position.to_string(), group.to_string());
                let question = CORRECTION.question(
                    &[position_key.as_bytes(), group_key.as_bytes()],
                    self.decisions.correction_wording.clone(),
                    AnswerContract::Choice { options },
                )?;
                labels.show_choices(question.id, wire_options);
                asks[position].push(questions.len());
                questions.push(question);
            }
            for (claim, predicate, value) in shown {
                if !listed.iter().any(|row| row.0 == claim) {
                    listed.push((claim, candidate.subject, predicate, value));
                }
            }
        }
        if questions.is_empty() {
            return Ok(Some(parsed.iter().map(|_| Correction::none()).collect()));
        }
        // Every question is labelled before the state names any, so each
        // request the pack splits into reads the same labels.
        self.label_questions(&mut labels, &questions);
        let state = correction_state(parsed, &asks, &questions, &listed, &mut labels);
        let asked: Vec<&ParsedCandidate<'_>> = parsed
            .iter()
            .zip(&asks)
            .filter(|(_, asked)| !asked.is_empty())
            .map(|(candidate, _)| candidate)
            .collect();
        // The pack reads the listed claims and candidates drawn from these
        // turns. The turns also keep one extraction's asks apart from
        // another's over the same listing.
        let mut evidence: Vec<EntityId> = listed.iter().map(|row| row.0).collect();
        let mut turns: Vec<EntityId> = asked
            .iter()
            .flat_map(|candidate| candidate.evidence_turn_refs.iter().copied())
            .filter(|turn| !evidence.contains(turn))
            .collect();
        turns.sort_unstable();
        turns.dedup();
        evidence.extend(turns);
        let project = asked
            .first()
            .map(|candidate| candidate.project)
            .filter(|project| asked.iter().all(|candidate| candidate.project == *project));
        let to = self.ask_route(step_ctx.vault, project)?;
        // The pack is the attempt's one correction read: the attempt names it.
        let key =
            EntityId::from_bytes(*step_ctx.attempt_id.as_bytes()).map_err(crate::Error::from)?;
        let Some(decided) = self
            .decide(
                step_ctx, pass, resources, &to, key, &questions, &evidence, &state, &labels,
                charges,
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            asks.iter()
                .map(|asked| {
                    let decisions: Vec<KeptDecision> =
                        asked.iter().map(|&at| decided[at].clone()).collect();
                    Correction {
                        corrects: named_id(decisions.iter().collect()),
                        decisions,
                    }
                })
                .collect(),
        ))
    }
}

/// Whether `candidate` restates listed `claim` unchanged: it cites the claim
/// and carries the claim's own predicate and value (its subject is the
/// claim's, as the listing shows it about that subject). It reinforces the
/// claim, so that pair is never asked and corrects none.
fn reinforces(
    candidate: &ParsedCandidate<'_>,
    resources: &BranchResources<'_>,
    claim: EntityId,
) -> bool {
    candidate.locators.iter().any(
        |locator| matches!(locator, EvidenceLocator::Claim { claim_id, .. } if *claim_id == claim),
    ) && resources.prior(claim).is_ok_and(|prior| {
        candidate.predicate.as_deref() == Some(prior.body.predicate.as_str())
            && rmpv_to_json(&prior.body.value) == candidate.value
    })
}

/// What the correction pack decided for one parsed candidate: the listed
/// claim it corrects, if any, and its questions' decisions.
pub(in crate::dreamer_consolidation) struct Correction {
    pub(super) corrects: Option<EntityId>,
    pub(super) decisions: Vec<KeptDecision>,
}

impl Correction {
    /// A candidate the pack asked nothing about: it corrects none.
    fn none() -> Self {
        Self {
            corrects: None,
            decisions: Vec::new(),
        }
    }

    /// Whether one of its questions waits on a role's answer.
    pub(super) fn waiting(&self) -> bool {
        self.decisions.iter().any(KeptDecision::waiting)
    }
}

/// The candidates and the listed claims as the correction pack reads them:
/// each candidate with its questions, subject, predicate and value, each
/// value as its JSON text, cut shorter (halving) until the whole fits. Each
/// question, subject and claim goes by its label in `labels`.
fn correction_state(
    parsed: &[ParsedCandidate<'_>],
    asks: &[Vec<usize>],
    questions: &[crate::llm::decision::DecisionQuestion],
    listed: &[(EntityId, EntityId, &str, &str)],
    labels: &mut CallLabelMap,
) -> serde_json::Value {
    let values: Vec<String> = parsed
        .iter()
        .map(|candidate| candidate.value.to_string())
        .collect();
    let longest = values
        .iter()
        .map(String::len)
        .chain(listed.iter().map(|row| row.3.len()))
        .max()
        .unwrap_or(0);
    let mut candidates = Vec::new();
    for ((candidate, asked), value) in parsed.iter().zip(asks).zip(&values) {
        if asked.is_empty() {
            continue;
        }
        let refs: Vec<String> = asked
            .iter()
            .map(|&at| {
                labels
                    .assign(LabelKind::Question, questions[at].id)
                    .to_string()
            })
            .collect();
        let subject = labels
            .assign(LabelKind::Entity, candidate.subject)
            .to_string();
        candidates.push((refs, subject, candidate.predicate.as_deref(), value));
    }
    let listed: Vec<(String, String, &str, &str)> = listed
        .iter()
        .map(|(claim, subject, predicate, value)| {
            (
                labels.assign(LabelKind::Claim, *claim).to_string(),
                labels.assign(LabelKind::Entity, *subject).to_string(),
                *predicate,
                *value,
            )
        })
        .collect();
    crate::llm::decision::fit_state(longest, |cut| {
        let candidates: Vec<serde_json::Value> = candidates
            .iter()
            .map(|(refs, subject, predicate, value)| {
                serde_json::json!({
                    "questions": refs,
                    "subject": subject,
                    "predicate": predicate,
                    "value": crate::llm::decision::cut_text(value, cut),
                })
            })
            .collect();
        let listed: Vec<serde_json::Value> = listed
            .iter()
            .map(|(claim, subject, predicate, value)| {
                serde_json::json!({
                    "claim": claim,
                    "subject": subject,
                    "predicate": predicate,
                    "value": crate::llm::decision::cut_text(value, cut),
                })
            })
            .collect();
        serde_json::json!({
            "candidates": candidates,
            "listed": listed,
            "cut_at_bytes": cut,
        })
    })
}
