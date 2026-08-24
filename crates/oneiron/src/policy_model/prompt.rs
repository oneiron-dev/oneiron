//! The classify request, and how a safeguard model's answer is routed back to
//! a plane's rows.
//!
//! # The engine does not write the prompt
//!
//! The system message IS the substrate owner's policy document, sent verbatim.
//! The user message IS the candidate content, sent verbatim. The engine adds no
//! preamble, no taxonomy, no output instruction and no persona — those all live
//! inside the document, where their author can change them without an engine
//! release. What the engine contributes is the envelope: which binding to call,
//! which answer shape was declared, and the generation parameters the host
//! configured.
//!
//! # Writing the document (guidance, not machinery)
//!
//! Reasoning safeguard models respond to a policy laid out as INSTRUCTIONS,
//! DEFINITIONS, VIOLATES, SAFE, EXAMPLES — with the output instruction stated
//! at the TOP and repeated at the BOTTOM, because that is where these models
//! look for it. Roughly 400–600 tokens is the working optimum; ten thousand
//! still works and reasons more slowly. The engine checks none of this. It is
//! written down here because the person who writes the document is the person
//! whose classifier quality depends on it.

use std::collections::BTreeMap;

use serde_json::{Value as JsonValue, json};

use crate::error::{Error, Result};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DEFAULT_SAFEGUARD_MODEL_BINDING,
    DeterministicFallback, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelTierRef,
};

use super::contract::{PolicyModelAnswer, PolicyOutputContract, parse_model_answer};
use super::planes::{HostedLegalPolicy, PolicyPlane, PolicyRubricRow};
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{PolicyClassifyDecision, PolicyVerdictCategory};

/// A request to a safeguard model: the substrate owner's document, the
/// candidate, the rows an answer may resolve to, and the shape the document
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyPrompt {
    /// The policy document, verbatim.
    pub system: String,
    /// The candidate content, verbatim.
    pub user: String,
    pub rubric_rows: Vec<PolicyRubricRow>,
    pub output_contract: PolicyOutputContract,
}

impl PolicyClassifyPrompt {
    #[must_use]
    pub fn llm_request(&self, config: &PolicyModelConfig) -> LlmRequest {
        let selector = config.safeguard_binding.selector();
        let mut params = BTreeMap::new();
        params.insert(
            "temperature".to_owned(),
            json!(config.generation.temperature),
        );
        params.insert(
            "reasoning_effort".to_owned(),
            json!(config.generation.reasoning_effort.as_str()),
        );
        // No cap unless the host set one. A reasoning safeguard model spends
        // output tokens thinking before it answers, so a ceiling the engine
        // picked would truncate answers for a reason that was never about the
        // content.
        if let Some(max_output_tokens) = config.generation.max_output_tokens {
            params.insert("max_output_tokens".to_owned(), json!(max_output_tokens));
        }

        let mut provider_options = BTreeMap::new();
        provider_options.insert("safeguard_binding".to_owned(), json!(selector));
        provider_options.insert("factory_taxonomy".to_owned(), json!("suppressed"));

        LlmRequest {
            model: config.safeguard_binding.llm_model_id(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Other {
                    name: "policy_model_classify".to_owned(),
                },
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        // The only deterministic coverage left is what the
                        // substrate owner authored: `Decide` pattern rules.
                        name: "policy_model_decide_pattern_rules".to_owned(),
                        config: Some(json!({ "scope": "substrate_owner_patterns" })),
                    },
                },
                tier: crate::llm::TierPrecedence {
                    per_call: None,
                    vault_policy: Some(config.safeguard_binding.tier_ref()),
                    purpose_default: Some(ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned())),
                    global_default: ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned()),
                },
                response_format: self
                    .output_contract
                    .response_format(self.category_vocabulary()),
                locality: config.safeguard_binding.locality(),
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: self.system.clone(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: self.user.clone(),
                    }],
                },
            ],
            tools: Vec::new(),
            params,
            provider_options,
        }
    }

    /// The labels an answer may name, scoped to the plane whose rows are in
    /// this prompt. A plane never sees another plane's vocabulary.
    fn category_vocabulary(&self) -> Vec<JsonValue> {
        let mut labels: Vec<JsonValue> = vec![JsonValue::Null];
        for row in &self.rubric_rows {
            let label = match row.plane {
                // The owner plane's rows are free prose sharing one plane
                // label, so `row_ref` is the only vocabulary that tells two of
                // them apart.
                PolicyPlane::OwnerPolicy => JsonValue::from(row.row_ref.as_str()),
                PolicyPlane::HostedLegal => JsonValue::from(row.category.as_str()),
            };
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
        labels
    }
}

/// Builds the request for a plane: its document, the candidate, its rows.
pub(crate) fn render_classify_prompt(
    request: &PolicyClassifyRequest,
    policy_document: &str,
    rubric_rows: Vec<PolicyRubricRow>,
    output_contract: PolicyOutputContract,
) -> PolicyClassifyPrompt {
    PolicyClassifyPrompt {
        system: policy_document.to_owned(),
        user: request.content.clone(),
        rubric_rows,
        output_contract,
    }
}

/// Which plane's vocabulary an answer is read against. There is no third arm,
/// and no arm that means "either" — an answer belongs to exactly one plane.
pub(crate) enum AnswerPlane<'a> {
    Owner,
    Hosted(&'a HostedLegalPolicy),
}

/// A model answer resolved to a decision and the row it is attributed to.
pub(crate) struct ResolvedAnswer {
    pub(crate) decision: PolicyClassifyDecision,
    pub(crate) category: PolicyVerdictCategory,
    pub(crate) answer: PolicyModelAnswer,
}

/// Reads a safeguard-model response and routes it to a row of `plane`.
///
/// Every non-clean answer must land on a row the model was actually shown, and
/// the ROW decides the action — a model does not get to pick `Block` over a row
/// its plane wrote as `Warn`. An answer that names nothing the plane publishes
/// is unreadable, which is what keeps a hallucinated label from taking effect.
pub(crate) fn resolve_policy_model_response(
    response: &LlmResponse,
    prompt: &PolicyClassifyPrompt,
    plane: &AnswerPlane<'_>,
) -> Result<ResolvedAnswer> {
    let text = response_text(response).ok_or_else(|| {
        Error::InvalidConfig("policy model response contained no text part".to_owned())
    })?;
    let answer = parse_model_answer(prompt.output_contract, &text)?;
    if !answer.violation {
        return Ok(ResolvedAnswer {
            decision: PolicyClassifyDecision::Allow,
            category: PolicyVerdictCategory::None,
            answer,
        });
    }
    let (decision, category) = match plane {
        AnswerPlane::Owner => resolve_owner_violation(&answer, &prompt.rubric_rows)?,
        AnswerPlane::Hosted(policy) => resolve_hosted_violation(&answer, policy)?,
    };
    Ok(ResolvedAnswer {
        decision,
        category,
        answer,
    })
}

fn resolve_owner_violation(
    answer: &PolicyModelAnswer,
    rubric_rows: &[PolicyRubricRow],
) -> Result<(PolicyClassifyDecision, PolicyVerdictCategory)> {
    let owner_rows = || {
        rubric_rows
            .iter()
            .filter(|row| row.plane == PolicyPlane::OwnerPolicy)
    };
    let row = match answer.policy_category.as_deref() {
        // A categoryless contract resolves to the strictest row the owner
        // wrote, with manifest order breaking ties — the same rule that
        // governs when several of the owner's rows could apply.
        None => owner_rows().reduce(|governing, row| {
            if decision_severity(row.action) > decision_severity(governing.action) {
                row
            } else {
                governing
            }
        }),
        Some(row_ref) => owner_rows().find(|row| row.row_ref == row_ref),
    }
    .ok_or_else(|| {
        Error::InvalidConfig("policy model answer named no owner row the rubric carried".to_owned())
    })?;
    Ok((
        row.action,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: row.row_ref.clone(),
        },
    ))
}

fn resolve_hosted_violation(
    answer: &PolicyModelAnswer,
    policy: &HostedLegalPolicy,
) -> Result<(PolicyClassifyDecision, PolicyVerdictCategory)> {
    let row = match answer.policy_category.as_deref() {
        None => policy.strictest_row(),
        Some(label) => policy.row_for_category(label),
    }
    .ok_or_else(|| {
        Error::InvalidConfig(
            "policy model answer named no hosted row the policy carried".to_owned(),
        )
    })?;
    Ok((
        row.action.decision(),
        PolicyVerdictCategory::HostedLegal {
            category: row.category,
            jurisdiction: policy.jurisdiction.clone(),
            policy_version: policy.version.clone(),
            row_ref: row.row_ref.clone(),
        },
    ))
}

/// Ordering only — never stored, never emitted.
const fn decision_severity(decision: PolicyClassifyDecision) -> u8 {
    match decision {
        PolicyClassifyDecision::Allow => 0,
        PolicyClassifyDecision::Warn => 1,
        PolicyClassifyDecision::RouteToHelp => 2,
        PolicyClassifyDecision::Block => 3,
    }
}

/// The answer, as ONE string.
///
/// A provider may split a single answer across several text parts — a JSON
/// object arriving as `{"violation":` then `1}` is one answer in two pieces,
/// and reading only the first piece parses garbage. Garbage is an unreadable
/// answer, which fails the owner plane open and HALTS a hosted relay, so the
/// split has to be joined rather than picked from. Blank parts are dropped
/// because a provider's padding is not part of the answer; `None` when nothing
/// is left, which is the honest "the model said nothing".
fn response_text(response: &LlmResponse) -> Option<String> {
    let mut joined = String::new();
    for part in &response.message.content {
        if let ContentPart::Text { text } = part
            && !text.trim().is_empty()
        {
            joined.push_str(text);
        }
    }
    (!joined.trim().is_empty()).then_some(joined)
}
