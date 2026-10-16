//! The consolidation's typed questions through the host's ladder: how a conflict set
//! resolves and which candidate's identity a merge keeps, and which listed claim an
//! extracted candidate corrects. The verdict role's generation is each pack's first read.

use std::time::{Duration, Instant};

use serde_json::json;

use super::*;
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionQuestion, DecisionRung,
    GeneratedDecisions, GeneratedRung, GeneratedStep, HeldLadder, ProviderPin, Reversibility,
    TypedDecision, cut_text, fit_state,
};
use crate::retrieval_depth::RetrievalDeadline;

/// The answer that names no listed id.
pub(super) const NONE: &str = "none";
/// The most ids one choice offers beside [`NONE`]; the contract allows 64 options.
const IDS_PER_QUESTION: usize = 63;

/// The host's ladder for the Dreamer's typed questions, the dial and learned bands they
/// route under, and its wording of each question. The verdict role's generated read sits at
/// the dial's first rung, in place of that slot's provider.
#[derive(Clone)]
pub struct ConsolidationDecisions {
    pub ladder: HeldLadder,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// How a conflict set resolves.
    pub resolution_wording: String,
    /// Which candidate's identity a merge keeps.
    pub identity_wording: String,
    /// Which listed claim an extracted candidate corrects.
    pub correction_wording: String,
}

impl ConsolidationDecisions {
    /// The shipped wording on an unstaffed ladder: the verdict role's read, at the big
    /// rung, is the one rung, and every band starts in shadow.
    pub fn shipped() -> Result<Self> {
        let wording: Wording = serde_json::from_str(include_str!("decision_wording.json"))
            .map_err(|_| invalid_consolidation("shipped decision wording is not readable"))?;
        Ok(Self {
            ladder: HeldLadder::unstaffed(),
            dial: DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            resolution_wording: wording.resolution,
            identity_wording: wording.identity,
            correction_wording: wording.correction,
        })
    }
}

/// The shipped wording, as data.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    resolution: String,
    identity: String,
    correction: String,
}

/// `ids` as a choice's option groups, each of at most [`IDS_PER_QUESTION`] ids, with
/// [`NONE`] first when `none` holds or there is more than one group.
pub(super) fn id_options(ids: &[EntityId], none: bool) -> Vec<Vec<String>> {
    let none = none || ids.len() > IDS_PER_QUESTION;
    ids.chunks(IDS_PER_QUESTION)
        .map(|group| {
            none.then(|| NONE.to_owned())
                .into_iter()
                .chain(group.iter().map(EntityId::to_hex))
                .collect()
        })
        .collect()
}

/// The id one set of group answers names: of the ids named, the one read most probable.
pub(super) fn named_id(decisions: Vec<&TypedDecision>) -> Option<EntityId> {
    decisions
        .into_iter()
        .filter_map(|decision| match (&decision.answer, decision.probability) {
            (DecisionAnswer::Choice(label), Some(probability)) if label != NONE => {
                EntityId::from_hex(label).ok().map(|id| (id, probability))
            }
            _ => None,
        })
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(id, _)| id)
}

impl ConsolidationExecutor<'_> {
    /// `questions` over `state` through the host's ladder, the verdict role's generation
    /// the dial's first read, on the time the pass has left. Each generation's spend joins
    /// `charges`. None when the step trapped: the attempt is parked.
    #[expect(
        clippy::too_many_arguments,
        reason = "the step, its pass clock and scope join the pack and the charge tally"
    )]
    pub(super) async fn decide(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        scope: &crate::llm::Scope,
        questions: &[DecisionQuestion],
        evidence: &[EntityId],
        state: &serde_json::Value,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<TypedDecision>>> {
        let vault = step_ctx.vault;
        let call = self.role(DREAMER_VERDICT_ROLE);
        let seal = |request: LlmRequest| -> Result<LlmRequest> {
            let mut request = vault
                .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
                .into_request();
            super::super::roles::bind_reasoning(vault, call.backend, &mut request)?;
            Ok(request)
        };
        let rung = GeneratedRung {
            pin: ProviderPin {
                rung: self.decisions.dial.first,
                model: call.model.to_string(),
                version: call.model.to_string(),
            },
            backend: call.backend,
            step: GeneratedStep::Durable {
                step: step_ctx,
                guard: self.guard,
            },
            request: verdict_shell(&call, scope)?,
            seal: &seal,
        };
        let asked: Vec<&DecisionQuestion> = questions.iter().collect();
        let decided = self
            .decisions
            .ladder
            .ladder()
            .run_pack_generated(
                &rung,
                &asked,
                self.actor.entity_ref(),
                evidence,
                state,
                self.decisions.dial,
                &self.decisions.bands,
                Reversibility::ReversibleRead,
                &RetrievalDeadline::hard(
                    Instant::now(),
                    Duration::from_millis(pass.remaining_ms()),
                ),
            )
            .await?;
        match decided {
            GeneratedDecisions::Decided { decisions, steps } => {
                for (hash, usage) in steps {
                    charges.record_terminal(vault, step_ctx.attempt_id, hash, &usage)?;
                }
                Ok(Some(decisions))
            }
            GeneratedDecisions::Trapped => Ok(None),
            GeneratedDecisions::Unread(_) => Err(invalid_consolidation(
                "a durable decision read came back unread",
            )
            .into()),
        }
    }
}

/// The verdict role's request for a typed read: its model, scope and binding, with no
/// messages yet.
fn verdict_shell(call: &RoleCall<'_>, scope: &crate::llm::Scope) -> Result<LlmRequest> {
    Ok(LlmRequest {
        model: call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: scope.clone(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::Durable {
                fallback: crate::llm::DeterministicFallback {
                    name: "json_rules_v1".into(),
                    config: None,
                },
            },
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: call.inference.selected_locality().ok_or_else(|| {
                crate::Error::InvalidConfig("consolidation host binding needs locality".into())
            })?,
        }
        .with_purpose_defaults(),
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    })
}

/// A conflict as its pack reads it: the predicate, the prior heads and each candidate,
/// every value as its JSON text, cut shorter (halving) until the whole fits.
pub(super) fn conflict_state(
    identity: &ConflictIdentity,
    members: &[&PromotionCandidate],
    priors: &[super::super::PriorHead],
) -> Result<serde_json::Value> {
    let priors: Vec<(String, &str, Option<&str>, String)> = priors
        .iter()
        .map(|prior| {
            (
                prior.claim_id.to_hex(),
                prior.body.predicate.as_str(),
                prior.body.source.map(ClaimSource::as_str),
                rmpv_to_json(&prior.body.value).to_string(),
            )
        })
        .collect();
    let candidates = members
        .iter()
        .map(|member| {
            let facts = candidate_facts(&member.candidate)?;
            Ok((
                member.claim_id.to_hex(),
                facts.predicate.to_string(),
                rmpv_to_json(&facts.value).to_string(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let longest = priors
        .iter()
        .map(|prior| prior.3.len())
        .chain(candidates.iter().map(|candidate| candidate.2.len()))
        .max()
        .unwrap_or(0);
    Ok(fit_state(longest, |cut| {
        let priors: Vec<_> = priors
            .iter()
            .map(|(claim, predicate, source, value)| {
                json!({"claim": claim, "predicate": predicate, "source": source,
                    "value": cut_text(value, cut)})
            })
            .collect();
        let candidates: Vec<_> = candidates
            .iter()
            .map(|(claim, predicate, value)| {
                json!({"claim": claim, "predicate": predicate, "value": cut_text(value, cut)})
            })
            .collect();
        json!({
            "predicate": identity.predicate,
            "prior_heads": priors,
            "candidates": candidates,
            "cut_at_bytes": cut,
        })
    }))
}
