//! The conversation judge's protocol: the request the check sends for one
//! part (the host's rubric, the reply schema, the part's summary and the
//! text it was written from) and the reading of the judge's reply.

use super::{
    CompactionCheckModel, CompactionCheckVerdict, ConversationCheckDeclaration, Part, judge_call,
};
use crate::Result;
use oneiron_model::llm::{ContentPart, LlmRequest, LlmResponse};

/// The judge's call: the host's rubric, then the summary and the span it
/// was cut from, its conflicts citing turns by their place in the span.
pub(super) fn judge_request(
    model: &CompactionCheckModel<'_>,
    input: &serde_json::Value,
    locality: oneiron_model::llm::ModelLocality,
    keyless: bool,
    paid: bool,
) -> Result<LlmRequest> {
    let schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["verdict", "conflicts", "reason"],
        "properties": {
            "verdict": {"type": "string"},
            "conflicts": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["assertion", "turns"],
                "properties": {
                    "assertion": {"type": "integer"},
                    "turns": {"type": "array", "items": {"type": "integer"}}
                }
            }},
            "reason": {"type": "string"}
        }
    });
    judge_call(model, schema, input, locality, keyless, paid)
}

/// What the judge reads for `part`: the span's length in turns and, for a
/// piece summary, the bytes of the turn it covers; the summary; and the text
/// it was written from, whole.
pub(super) fn judge_input(
    declaration: &ConversationCheckDeclaration,
    part: &Part,
) -> serde_json::Value {
    let turns = declaration.turns.len();
    let span = match &part.piece {
        None => serde_json::json!({"turns": turns}),
        Some((bytes, total)) => {
            serde_json::json!({"turns": turns, "bytes": [bytes.start, bytes.end], "of": total})
        }
    };
    serde_json::json!({
        "span": span,
        "summary": part.summary,
        "evidence": part.evidence,
    })
}

/// The judge's verdict and its reason, each conflict citing the span's
/// turns by id; `None` for a reply that is not one. A conflict keeps only
/// turns of the checked span.
pub(super) struct Judged {
    pub(super) verdict: CompactionCheckVerdict,
    pub(super) conflicts: Vec<serde_json::Value>,
    pub(super) reason: String,
}

pub(super) fn judgment(
    response: &LlmResponse,
    declaration: &ConversationCheckDeclaration,
) -> Option<Judged> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let reply: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let verdict = match reply.get("verdict")?.as_str()? {
        "supported" => CompactionCheckVerdict::Supported,
        "mismatch" => CompactionCheckVerdict::Mismatch,
        _ => return None,
    };
    let mut conflicts = Vec::new();
    for conflict in reply.get("conflicts")?.as_array()? {
        let assertion = conflict.get("assertion")?.as_u64()?;
        let turns: Vec<String> = conflict
            .get("turns")?
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .filter_map(|at| usize::try_from(at).ok())
            .filter_map(|at| declaration.turns.get(at))
            .map(|span| span.turn.to_hex())
            .collect();
        conflicts.push(serde_json::json!({"assertion": assertion, "turns": turns}));
    }
    Some(Judged {
        verdict,
        conflicts,
        reason: reply.get("reason")?.as_str()?.to_owned(),
    })
}
