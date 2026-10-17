//! Host-routed, lease-bounded generation. No durable-step memo or memory output is written.

use std::collections::BTreeMap;

use super::{
    ReviewBundleExplanation, ReviewBundleInput, ReviewComplexity, ReviewExplainerCallReceipt,
    ReviewExplainerEscalation, ReviewExplainerOutput, ReviewExplainerReceipt,
};
use crate::attempt_queue::AttemptRecord;
use crate::llm::{
    BudgetDenied, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart,
    FinishReason, HostInferenceContext, LlmBackend, LlmCapability, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality, ReasoningEffort, ResponseFormat, Scope,
    TierPrecedence,
};
use crate::{EntityId, Error, Vault};

#[derive(Debug, thiserror::Error)]
pub enum ReviewExplainerError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Provider(#[from] LlmError),
    #[error(transparent)]
    Budget(#[from] BudgetDenied),
    #[error("review explainer: {0}")]
    Invalid(&'static str),
}

type Result<T> = std::result::Result<T, ReviewExplainerError>;

/// Resolved by the host's ordinary model-role/route machinery, never by model name here.
pub struct ReviewExplainerRoute<'a> {
    pub backend: &'a dyn LlmBackend,
    pub model: ModelId,
    pub locality: ModelLocality,
    pub tier: TierPrecedence,
    pub inference: HostInferenceContext<'a>,
}

/// All calls borrow the same running attempt, scope and budget. Higher routes are optional.
pub struct ReviewExplainerExecution<'a> {
    pub attempt: &'a AttemptRecord,
    pub skill: EntityId,
    pub scope: Scope,
    pub guard: &'a BudgetGuard,
    pub light: ReviewExplainerRoute<'a>,
    pub middling: Option<ReviewExplainerRoute<'a>>,
    pub very_complex: Option<ReviewExplainerRoute<'a>>,
}

/// Regenerate from retained versions and the currently selected Active skill. The receipt
/// and explanation are returned together, not inserted as a NOTE, CLAIM or text document.
/// A missing higher route or exhausted escalation lease preserves the useful light draft.
pub async fn explain_review_bundle(
    vault: &Vault,
    proposal: &EntityId,
    execution: &ReviewExplainerExecution<'_>,
    at: u64,
) -> Result<ReviewBundleExplanation> {
    let input = vault.review_bundle_input(proposal)?;
    let loaded = vault.load_leased_callable_skill_pack(
        execution.attempt,
        &execution.skill,
        execution.light.model.as_str(),
        at,
    )?;
    let instructions = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == "SKILL.md"))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .filter(|text| !text.trim().is_empty())
        .ok_or(ReviewExplainerError::Invalid("skill has no UTF-8 SKILL.md"))?;
    let hash = loaded
        .record
        .content_hash
        .ok_or(ReviewExplainerError::Invalid(
            "skill has no source identity",
        ))?;
    let input_bytes = serde_json::to_vec(&input)
        .map_err(|_| ReviewExplainerError::Invalid("input cannot be encoded"))?;
    let mut receipt = ReviewExplainerReceipt {
        proposal: input.proposal.clone(),
        forks: input
            .forks
            .iter()
            .map(|fork| fork.record.fork.clone())
            .collect(),
        input_hash: blake3::hash(&input_bytes).to_hex().to_string(),
        skill: execution.skill,
        skill_version: loaded.record.version.clone(),
        skill_content_hash: hash.to_hex(),
        calls: Vec::new(),
        escalation: ReviewExplainerEscalation::NotNeeded,
        at,
    };
    let (mut output, call) = generate(
        vault,
        execution,
        &execution.light,
        instructions,
        &input,
        None,
        ReasoningEffort::Low,
    )
    .await?;
    receipt.calls.push(call);
    let mut completed = ReviewComplexity::Easy;
    let mut required = output.complexity();
    while required > completed {
        let (route, effort) = match required {
            ReviewComplexity::Easy => unreachable!("easy completed by the first call"),
            ReviewComplexity::Middling => (&execution.middling, ReasoningEffort::Medium),
            ReviewComplexity::VeryComplex => (&execution.very_complex, ReasoningEffort::High),
        };
        let Some(route) = route else {
            receipt.escalation = ReviewExplainerEscalation::RouteUnavailable;
            break;
        };
        match generate(
            vault,
            execution,
            route,
            instructions,
            &input,
            Some(&output),
            effort,
        )
        .await
        {
            Ok((refined, call)) => {
                completed = required;
                required = required.max(refined.complexity());
                output = refined;
                receipt.calls.push(call);
                receipt.escalation = ReviewExplainerEscalation::Completed;
            }
            Err(ReviewExplainerError::Budget(
                BudgetDenied::Exhausted | BudgetDenied::AdmissionDenied,
            )) => {
                receipt.escalation = ReviewExplainerEscalation::BudgetLimited;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    // A verdict, purge or additional fork while the model was running invalidates
    // this projection. Never attach a stale explanation to a newer pending set.
    if vault.review_bundle_input(proposal)? != input {
        return Err(ReviewExplainerError::Invalid(
            "pending review bundle changed",
        ));
    }
    Ok(ReviewBundleExplanation {
        explainer: output,
        receipt,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "one call borrows the host route, skill, input and existing budget"
)]
async fn generate(
    vault: &Vault,
    execution: &ReviewExplainerExecution<'_>,
    route: &ReviewExplainerRoute<'_>,
    instructions: &str,
    input: &ReviewBundleInput,
    previous: Option<&ReviewExplainerOutput>,
    effort: ReasoningEffort,
) -> Result<(ReviewExplainerOutput, ReviewExplainerCallReceipt)> {
    let payload = serde_json::to_string(&serde_json::json!({
        "bundle": input, "previous": previous, "effort": effort,
    }))
    .map_err(|_| ReviewExplainerError::Invalid("input cannot be encoded"))?;
    let request = LlmRequest {
        model: route.model.clone(),
        envelope: CallEnvelope {
            scope: execution.scope.clone(),
            purpose: CallPurpose::Other {
                name: "review_bundle_explainer".into(),
            },
            class: CallClass::BestEffort,
            tier: route.tier.clone(),
            response_format: if route
                .backend
                .supports(&route.model, LlmCapability::JsonResponse)
            {
                ResponseFormat::Json {
                    schema: output_schema(),
                }
            } else {
                ResponseFormat::Text
            },
            locality: route.locality,
            seat_effort: Some(effort),
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: instructions.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: payload }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let request = vault
        .authorize_raw_inference(request, &route.inference)?
        .into_request();
    let lease = execution
        .guard
        .admit_for_request(&request)
        .inspect_err(|denied| {
            vault.budget_denied_hooks(denied, execution.guard, request.model.as_str(), None);
        })?
        .lease;
    let mut charge = CallCharge {
        guard: execution.guard,
        lease: &lease,
        settled: false,
    };
    let model = request.model.clone();
    let response = route.backend.generate(request, &lease).await?;
    execution.guard.settle_per_call(&lease, &response.usage)?;
    charge.settled = true;
    if response.finish_reason != FinishReason::Stop {
        return Err(ReviewExplainerError::Invalid("generation did not finish"));
    }
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let output: ReviewExplainerOutput = serde_json::from_str(&text)
        .map_err(|_| ReviewExplainerError::Invalid("generation is not a typed explainer"))?;
    output.validate(input)?;
    if let Some(previous) = previous {
        for prior in &previous.changes {
            let current = output
                .changes
                .iter()
                .find(|change| change.fork == prior.fork)
                .ok_or(ReviewExplainerError::Invalid(
                    "refinement lost a reviewed fork",
                ))?;
            if prior
                .removed_public_names
                .iter()
                .any(|name| !current.removed_public_names.contains(name))
            {
                return Err(ReviewExplainerError::Invalid(
                    "refinement hid a removed public name",
                ));
            }
        }
    }
    Ok((
        output,
        ReviewExplainerCallReceipt {
            model,
            effort,
            lease: lease.id().to_owned(),
            usage: response.usage,
        },
    ))
}

/// Cancellation and failed calls still charge their reservation; known usage settles once.
struct CallCharge<'a> {
    guard: &'a BudgetGuard,
    lease: &'a BudgetLease,
    settled: bool,
}
impl Drop for CallCharge<'_> {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.guard.settle_reserved(self.lease);
        }
    }
}

fn output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["summary", "changes", "diagram"],
        "properties": {
            "summary": {"type": "string", "minLength": 1},
            "changes": {
                "type": "array", "minItems": 1,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["fork", "line", "complexity", "removed_public_names"],
                    "properties": {
                        "fork": {"type": "string"}, "line": {"type": "string", "minLength": 1},
                        "complexity": {"enum": ["easy", "middling", "very_complex"]},
                        "removed_public_names": {"type": "array", "items": {"type": "string"}}
                    }
                }
            },
            "diagram": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["nodes", "edges"],
                        "properties": {
                            "nodes": {"type": "array", "minItems": 1, "items": {
                                "type": "object", "additionalProperties": false,
                                "required": ["id", "label", "forks"],
                                "properties": {
                                    "id": {"type": "string"}, "label": {"type": "string"},
                                    "forks": {"type": "array", "minItems": 1, "items": {"type": "string"}}
                                }
                            }},
                            "edges": {"type": "array", "items": {
                                "type": "object", "additionalProperties": false,
                                "required": ["from", "to", "label"],
                                "properties": {
                                    "from": {"type": "string"}, "to": {"type": "string"},
                                    "label": {"type": "string"}
                                }
                            }}
                        }
                    }
                ]
            }
        }
    })
}
