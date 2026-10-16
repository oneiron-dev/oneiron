//! The audit notes a `rationale_json` pass carries beside its decided verdict.
//!
//! The safeguard read decides the verdict. The rule ids, confidence word and
//! rationale the contract promises the substrate owner come from one more
//! generation on the same model, on the same terms: the caller's lease, or its
//! own admission on the guard. Its request is the prompt's own, with a turn
//! naming the decided answer. The notes never change the verdict.

use serde_json::json;

use crate::error::Result;
use crate::llm::{ContentPart, FinishReason, LlmMessage, LlmMessageRole, LlmResponse};

use super::classifier_lease::ClassifierLease;
use super::contract::{parse_rationale_notes, rationale_notes_format};
use super::decide::{CLEAN, SafeguardModel};
use super::prompt::{PolicyClassifyPrompt, response_text, retain_resolvable_rule_ids};
use super::request::PolicyModelConfig;
use super::verdict::PolicyPassAudit;

/// Fills `audit`'s model fields with the notes on the decided answer:
/// `decided`, the vocabulary label of the row the read named, or none when it
/// found the content clean. The request is the prompt's own with one more turn
/// asking `wording` of that answer, and its reply holds the three fields alone.
/// A refused admission, a failed call or an unreadable reply leaves `audit` as
/// it was; the verdict stands.
pub(super) async fn rationale_notes(
    safeguard: SafeguardModel<'_>,
    prompt: &PolicyClassifyPrompt,
    config: &PolicyModelConfig,
    decided: Option<&str>,
    wording: &str,
    audit: &mut PolicyPassAudit,
) -> Result<()> {
    let mut request = prompt.llm_request(config);
    request.envelope.response_format = rationale_notes_format();
    request.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: json!({"question": wording, "answer": decided.unwrap_or(CLEAN)}).to_string(),
        }],
    });
    let admitted = match safeguard {
        SafeguardModel::Leased { .. } => None,
        // A refused admission is no notes, never a call on another lease.
        SafeguardModel::Budgeted { budget, .. } => match budget.admit_for_request(&request) {
            Ok(admission) => Some(ClassifierLease::new(budget, admission.lease)),
            Err(_) => return Ok(()),
        },
    };
    let (backend, lease) = match (safeguard, &admitted) {
        (SafeguardModel::Leased { backend, lease }, _) => (backend, lease),
        (SafeguardModel::Budgeted { backend, .. }, Some(admitted)) => (backend, admitted.lease()),
        (SafeguardModel::Budgeted { .. }, None) => return Ok(()),
    };
    let response = backend.generate(request, lease).await;
    if let Some(admitted) = &admitted {
        admitted.settle(&response)?;
    }
    let Some(mut notes) = response
        .ok()
        .and_then(|response| finished_text(&response))
        .and_then(|text| parse_rationale_notes(&text).ok())
    else {
        return Ok(());
    };
    audit.model_rule_ids_dropped = retain_resolvable_rule_ids(&mut notes, prompt);
    audit.model_rule_ids = notes.rule_ids;
    audit.model_confidence = notes.confidence;
    audit.model_rationale = notes.rationale;
    Ok(())
}

/// A finished reply's text. A cut, filtered, cancelled, paused or tool-pending
/// reply is partial, and this request declares no tools, so a tool call is no
/// answer either.
fn finished_text(response: &LlmResponse) -> Option<String> {
    if response.finish_reason != FinishReason::Stop
        || response
            .message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    {
        return None;
    }
    response_text(response)
}
