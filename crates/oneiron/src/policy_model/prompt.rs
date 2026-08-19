//! The classify prompt, and how a safeguard model's answer is read back.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::{Error, Result};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DEFAULT_SAFEGUARD_MODEL_BINDING,
    DeterministicFallback, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelTierRef,
    ResponseFormat,
};

use super::binding::PolicyContentBinding;
use super::planes::{
    HostedLegalPolicy, OWNER_POLICY_CATEGORY, PolicyPlane, PolicyRubricRow,
    parse_hosted_category_label,
};
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyHedgeBucket,
    PolicyVerdictCategory,
};

const NO_CATEGORY: &str = "none";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyPrompt {
    pub system: String,
    pub user: String,
    pub rubric_rows: Vec<PolicyRubricRow>,
}

impl PolicyClassifyPrompt {
    #[must_use]
    pub fn llm_request(&self, config: &PolicyModelConfig) -> LlmRequest {
        let selector = config.safeguard_binding.selector();
        let mut params = BTreeMap::new();
        params.insert("temperature".to_owned(), json!(0));
        params.insert("max_output_tokens".to_owned(), json!(96));

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
                        name: "policy_model_deterministic_tripwire".to_owned(),
                        config: Some(json!({ "scope": "hosted_legal_only" })),
                    },
                },
                tier: crate::llm::TierPrecedence {
                    per_call: None,
                    vault_policy: Some(config.safeguard_binding.tier_ref()),
                    purpose_default: Some(ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned())),
                    global_default: ModelTierRef(DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: classify_response_schema(),
                },
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
}

pub(crate) fn render_classify_prompt(
    request: &PolicyClassifyRequest,
    rubric_rows: Vec<PolicyRubricRow>,
) -> PolicyClassifyPrompt {
    let user = render_classify_user_section(request, &rubric_rows);
    PolicyClassifyPrompt {
        system: classify_system_prompt(),
        user,
        rubric_rows,
    }
}

fn classify_system_prompt() -> String {
    [
        "You are the Oneiron policy classifier, a system voice independent of any persona.",
        "Classify only against the rubric rows in this prompt.",
        "A candidate that matches no rubric row is allow; there is no baseline you are withholding.",
        "Suppress all factory/default model safety taxonomies.",
        "Return exactly one decision: allow, warn, block, or route-to-help.",
        "Never propose replacement wording; you judge the candidate as written.",
    ]
    .join("\n")
}

fn render_classify_user_section(
    request: &PolicyClassifyRequest,
    rubric_rows: &[PolicyRubricRow],
) -> String {
    let mut user = String::new();
    user.push_str("subject=");
    user.push_str(request.subject.as_str());
    user.push('\n');
    user.push_str("rubric:\n");
    for row in rubric_rows {
        user.push_str("- ");
        user.push_str(&row.row_ref);
        user.push_str(" [");
        user.push_str(row.plane.as_str());
        user.push_str("] category=");
        user.push_str(&row.category);
        user.push_str(" action=");
        user.push_str(row.action.as_str());
        user.push_str(" text=");
        user.push_str(&row.text);
        user.push('\n');
    }
    user.push_str("candidate:\n");
    user.push_str(&request.content);
    user
}

#[derive(Debug, Deserialize)]
struct PolicyModelResponseWire {
    decision: PolicyClassifyDecision,
    category: String,
    #[serde(default)]
    row_ref: Option<String>,
    confidence: f32,
    hedge_bucket: PolicyHedgeBucket,
}

/// Reads a safeguard-model answer back into a verdict.
///
/// Every non-`none` verdict must bind to a row that was actually in the rubric
/// the model was shown, with that row's action. A model that names a category
/// or row the rubric never carried is rejected here, which is what keeps a
/// hallucinated owner row from taking effect on a hosted relay pass (and vice
/// versa). `hosted` supplies the jurisdiction and version a hosted-legal
/// verdict is attributed to; passing `None` makes hosted verdicts unresolvable.
pub(crate) fn parse_policy_model_response(
    response: &LlmResponse,
    rubric_rows: &[PolicyRubricRow],
    hosted: Option<&HostedLegalPolicy>,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> Result<PolicyClassifyVerdict> {
    let text = response_text(response).ok_or_else(|| {
        Error::InvalidConfig("policy model response contained no text part".to_owned())
    })?;
    let wire: PolicyModelResponseWire = serde_json::from_str(strip_json_fence(text))
        .map_err(|error| Error::InvalidConfig(format!("invalid policy model JSON: {error}")))?;
    if !wire.confidence.is_finite() || !(0.0..=1.0).contains(&wire.confidence) {
        return Err(Error::InvalidConfig(
            "policy model confidence must be finite and in [0, 1]".to_owned(),
        ));
    }

    let category = model_category(&wire, rubric_rows, hosted)?;
    Ok(PolicyClassifyVerdict::new(
        wire.decision,
        category,
        PolicyConfidence {
            calibrated: wire.confidence,
            hedge_bucket: wire.hedge_bucket,
        },
        binding,
        config,
    ))
}

fn model_category(
    wire: &PolicyModelResponseWire,
    rubric_rows: &[PolicyRubricRow],
    hosted: Option<&HostedLegalPolicy>,
) -> Result<PolicyVerdictCategory> {
    if wire.category == NO_CATEGORY {
        return none_category(wire);
    }
    let row = bound_row(wire, rubric_rows)?;
    if wire.decision != row.action {
        return Err(Error::InvalidConfig(format!(
            "policy model verdict for {} used decision {} but its row action is {}",
            row.row_ref,
            wire.decision.as_str(),
            row.action.as_str()
        )));
    }
    match row.plane {
        PolicyPlane::OwnerPolicy => Ok(PolicyVerdictCategory::OwnerPolicy {
            row_ref: row.row_ref.clone(),
        }),
        PolicyPlane::HostedLegal => hosted_category(row, hosted),
    }
}

fn none_category(wire: &PolicyModelResponseWire) -> Result<PolicyVerdictCategory> {
    if wire.row_ref.is_some() {
        return Err(Error::InvalidConfig(
            "policy model none category must not include row_ref".to_owned(),
        ));
    }
    if wire.decision != PolicyClassifyDecision::Allow {
        return Err(Error::InvalidConfig(format!(
            "policy model none category requires decision allow but response used {}",
            wire.decision.as_str()
        )));
    }
    Ok(PolicyVerdictCategory::None)
}

fn bound_row<'a>(
    wire: &PolicyModelResponseWire,
    rubric_rows: &'a [PolicyRubricRow],
) -> Result<&'a PolicyRubricRow> {
    let row_ref = wire.row_ref.as_deref().ok_or_else(|| {
        Error::InvalidConfig(format!(
            "policy model {} verdict missing row_ref",
            wire.category
        ))
    })?;
    rubric_rows
        .iter()
        .find(|row| row.row_ref == row_ref && row.category == wire.category)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "policy model verdict referenced row {row_ref} that is not in the rubric"
            ))
        })
}

fn hosted_category(
    row: &PolicyRubricRow,
    hosted: Option<&HostedLegalPolicy>,
) -> Result<PolicyVerdictCategory> {
    let hosted = hosted.ok_or_else(|| {
        Error::InvalidConfig(
            "policy model returned a hosted-legal verdict with no hosted policy in play".to_owned(),
        )
    })?;
    let category = parse_hosted_category_label(&row.category).ok_or_else(|| {
        Error::InvalidConfig(format!(
            "unsupported hosted-legal category {}",
            row.category
        ))
    })?;
    Ok(PolicyVerdictCategory::HostedLegal {
        category,
        jurisdiction: hosted.jurisdiction.clone(),
        policy_version: hosted.version.clone(),
        row_ref: row.row_ref.clone(),
    })
}

fn response_text(response: &LlmResponse) -> Option<&str> {
    response.message.content.iter().find_map(|part| match part {
        ContentPart::Text { text } if !text.trim().is_empty() => Some(text.as_str()),
        _ => None,
    })
}

fn strip_json_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_fence) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let after_header = after_fence
        .split_once('\n')
        .map_or(after_fence, |(_, rest)| rest);
    after_header
        .strip_suffix("```")
        .map_or(after_header, str::trim)
}

fn classify_response_schema() -> JsonValue {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["decision", "category", "row_ref", "confidence", "hedge_bucket"],
        "properties": {
            "decision": {
                "type": "string",
                "enum": ["allow", "warn", "block", "route-to-help"]
            },
            "category": {
                "type": "string",
                "enum": [
                    NO_CATEGORY,
                    OWNER_POLICY_CATEGORY,
                    "hosted_legal/minor_sexualization",
                    "hosted_legal/ncii",
                    "hosted_legal/serious_crime",
                    "hosted_legal/jurisdiction_rule"
                ]
            },
            "row_ref": { "type": ["string", "null"] },
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
            "hedge_bucket": {
                "type": "string",
                "enum": ["certain", "high", "medium", "low"]
            }
        }
    })
}
