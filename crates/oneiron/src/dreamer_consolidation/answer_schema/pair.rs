//! One shadow pair of the nightly answer-schema check (HOUSE-SCHEMA-CHECK): the two arms
//! re-sent per drawn capture, the fault score per reply, and the judged quality score per pair.
//!
//! Arm S is the captured request with a pair seed; arm N is arm S without the schema field.
//! Both arms name the house model at the house locality: they are re-sent on the house rung,
//! whatever seat the night's own call took. A shadow reply is scored only, never decoded into
//! memory, never filed as a claim.

#[cfg(oneiron_test_support)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde_json::{Value as JsonValue, json};

use super::super::executor::extraction::{
    ANSWER_SCHEMA_PARAM, check_extraction_reply, extraction_reply,
};
use oneiron_model::llm::{
    CallClass, LlmMessageRole, LlmRequest, LlmResponse, ModelId, ModelLocality,
};

/// The seed param both arms of a pair carry: the pair's own seed, so the two arms differ only
/// by the schema.
const SEED_PARAM: &str = "seed";

/// Builds the pair's two arms from the captured request: arm S is the request with
/// `params["seed"] = seed`; arm N is arm S without [`ANSWER_SCHEMA_PARAM`] and without its
/// entry in the own-server-only list. Both arms name `model` at [`ModelLocality::OwnServer`]:
/// the check's calls go only to the house rung, and an own-server-only field survives the
/// wire only off a hosted locality. Both arms are [`CallClass::BestEffort`]: the captured TURN
/// call is Durable with a deterministic `json_rules_v1` fallback that answers a fatal failure
/// with an empty reply, which would pass a refused schema arm off as a whole one
/// (REVIEW-10538 round 2).
pub(crate) fn build_arms(
    captured: &LlmRequest,
    model: &ModelId,
    seed: u64,
) -> (LlmRequest, LlmRequest) {
    let mut schema = captured.clone();
    schema.model = model.clone();
    schema.envelope.locality = ModelLocality::OwnServer;
    schema.envelope.class = CallClass::BestEffort;
    schema.params.insert(SEED_PARAM.to_owned(), json!(seed));
    let mut shadow = schema.clone();
    shadow.params.remove(ANSWER_SCHEMA_PARAM);
    if let Some(JsonValue::Array(only)) = shadow
        .params
        .get_mut(oneiron_model::llm::OWN_SERVER_ONLY_PARAM)
    {
        only.retain(|name| name.as_str() != Some(ANSWER_SCHEMA_PARAM));
    }
    (schema, shadow)
}

/// The fault score of one arm's reply: whether it came back whole, and how many candidates
/// the contract decodes when it did, else none.
pub(crate) fn fault_scores(response: &LlmResponse) -> (bool, u32) {
    if check_extraction_reply(response).is_err() {
        return (false, 0);
    }
    let count = extraction_reply(response).map_or(0, |reply| reply.candidates.len());
    (true, count as u32)
}

/// The reply's candidates as the judge reads them, in order: each with its subject,
/// predicate, value and first quote. A reply that is not whole reads as no candidates.
pub(crate) fn candidates_of(response: &LlmResponse) -> Vec<JsonValue> {
    if check_extraction_reply(response).is_err() {
        return Vec::new();
    }
    match extraction_reply(response) {
        Ok(reply) => reply.candidates.iter().map(judge_candidate).collect(),
        Err(_) => Vec::new(),
    }
}

/// One candidate as the judge reads it: its subject, predicate, value and first quote.
fn judge_candidate(candidate: &JsonValue) -> JsonValue {
    let quote = candidate
        .get("evidence_refs")
        .and_then(JsonValue::as_array)
        .and_then(|refs| refs.first())
        .and_then(|cited| cited.get("quote"))
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    json!({
        "subject": candidate.get("subject").and_then(JsonValue::as_str).unwrap_or(""),
        "predicate": candidate.get("predicate").and_then(JsonValue::as_str).unwrap_or(""),
        "value": candidate.get("value").cloned().unwrap_or(JsonValue::Null),
        "quote": quote,
    })
}

/// The call's source text: the captured request's last user message, its text parts joined.
pub(crate) fn source_text(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .rev()
        .find(|message| message.role == LlmMessageRole::User)
        .map(|message| {
            message
                .content
                .iter()
                .filter_map(|part| match part {
                    oneiron_model::llm::ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// Which arm the judge reads as List 1 first: arm S on an even seed, arm N on an odd one.
/// The second call swaps the lists.
pub(crate) fn first_list_is_schema(seed: u64) -> bool {
    seed & 1 == 0
}

/// The judge's fixed instruction: prompt data for a fixed protocol, beside the engine's own
/// reply contract. The judge answers JSON only, one entry per candidate, in order.
const JUDGE_SYSTEM: &str = concat!(
    "You judge whether each extraction candidate is supported by the source turn it quotes. ",
    "Answer with JSON only: ",
    "{\"list1\":[true|false,...],\"list2\":[...]} ",
    "with one entry per candidate of List 1 and List 2, in order, ",
    "true when the turn supports the candidate.",
);

/// Renders one judge call's user turn: the source text and both candidate lists as JSON, no
/// arm names.
pub(crate) fn judge_user_text(source: &str, list1: &[JsonValue], list2: &[JsonValue]) -> String {
    format!(
        "Source turn:\n{source}\n\nList 1:\n{}\n\nList 2:\n{}",
        JsonValue::Array(list1.to_vec()),
        JsonValue::Array(list2.to_vec()),
    )
}

/// The judge's system turn.
pub(crate) fn judge_system_text() -> &'static str {
    JUDGE_SYSTEM
}

/// Reads one judge answer: the two boolean lists, which must match the presented lengths.
/// `None` for any other reply.
pub(crate) fn parse_judge_answer(
    text: &str,
    list1_len: usize,
    list2_len: usize,
) -> Option<(Vec<bool>, Vec<bool>)> {
    let reply: JsonValue = serde_json::from_str(text.trim()).ok()?;
    let list1 = reply.get("list1")?.as_array()?;
    let list2 = reply.get("list2")?.as_array()?;
    if list1.len() != list1_len || list2.len() != list2_len {
        return None;
    }
    let flags = |list: &[JsonValue]| {
        list.iter()
            .map(JsonValue::as_bool)
            .collect::<Option<Vec<bool>>>()
    };
    Some((flags(list1)?, flags(list2)?))
}

/// Which candidates of each arm both judge orders support: arm S's flags, then arm N's.
/// `first` is the first call's answer with arm S as List 1 on an even seed; `second` is the
/// swapped call's. A candidate counts only when both orders say so.
pub(crate) fn supported_flags(
    seed: u64,
    schema_len: usize,
    shadow_len: usize,
    first: (Vec<bool>, Vec<bool>),
    second: (Vec<bool>, Vec<bool>),
) -> (Vec<bool>, Vec<bool>) {
    let ((first1, first2), (second1, second2)) = (first, second);
    let (schema, shadow) = if first_list_is_schema(seed) {
        // First call: List 1 is arm S, List 2 is arm N; the second call swaps them.
        let schema = first1
            .into_iter()
            .zip(second2)
            .map(|(first, second)| first && second)
            .collect::<Vec<_>>();
        let shadow = first2
            .into_iter()
            .zip(second1)
            .map(|(first, second)| first && second)
            .collect::<Vec<_>>();
        (schema, shadow)
    } else {
        let shadow = first1
            .into_iter()
            .zip(second2)
            .map(|(first, second)| first && second)
            .collect::<Vec<_>>();
        let schema = first2
            .into_iter()
            .zip(second1)
            .map(|(first, second)| first && second)
            .collect::<Vec<_>>();
        (schema, shadow)
    };
    debug_assert_eq!(schema.len(), schema_len);
    debug_assert_eq!(shadow.len(), shadow_len);
    (schema, shadow)
}

/// One supported candidate's gold key: subject, predicate and value after trim and lowercase.
/// A value that is no string keys by its compact JSON.
pub(crate) fn candidate_key(candidate: &JsonValue) -> (String, String, String) {
    let word = |key: &str| {
        candidate
            .get(key)
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase()
    };
    let value = match candidate.get("value") {
        Some(JsonValue::String(text)) => text.trim().to_lowercase(),
        Some(value) => value.to_string(),
        None => String::new(),
    };
    (word("subject"), word("predicate"), value)
}

/// One candidate's gold key, as [`candidate_key`] spells it.
type GoldKey = (String, String, String);

/// Each arm's F1 against the pooled gold: the supported candidates of both arms, keyed by
/// [`candidate_key`]. An arm's precision is over every candidate it emitted, each counted, so
/// a claim the judge finds unsupported costs the arm that made it even when its key matches
/// a supported one's (REVIEW-10538 rounds 1 and 2); its hits are its distinct supported
/// keys, so a repeat earns nothing. `None` for both when the gold is empty: the pair has no quality and
/// stays out of the window.
pub(crate) fn f1_against_gold(
    schema: &[JsonValue],
    schema_supported: &[bool],
    shadow: &[JsonValue],
    shadow_supported: &[bool],
) -> (Option<f64>, Option<f64>) {
    let keys = |candidates: &[JsonValue], supported: &[bool]| {
        candidates
            .iter()
            .zip(supported.iter().copied())
            .filter(|(_, supported)| *supported)
            .map(|(candidate, _)| candidate_key(candidate))
            .collect::<BTreeSet<_>>()
    };
    let schema_keys = keys(schema, schema_supported);
    let shadow_keys = keys(shadow, shadow_supported);
    let gold = schema_keys
        .union(&shadow_keys)
        .cloned()
        .collect::<BTreeSet<_>>();
    if gold.is_empty() {
        return (None, None);
    }
    (
        Some(f1(&schema_keys, schema.len(), &gold)),
        Some(f1(&shadow_keys, shadow.len(), &gold)),
    )
}

/// The F1 of one arm against `gold`: `supported` are the gold keys of its candidates the
/// judge upheld, `emitted` how many candidates it gave. 0 when the arm holds nothing of the
/// gold.
fn f1(supported: &BTreeSet<GoldKey>, emitted: usize, gold: &BTreeSet<GoldKey>) -> f64 {
    let hit = supported.intersection(gold).count() as f64;
    let precision = if emitted == 0 {
        0.0
    } else {
        hit / emitted as f64
    };
    let recall = hit / gold.len() as f64;
    if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    }
}

/// The params both arms carry for `test_doors::dreamer_answer_schema`, without sending: the
/// schema arm's and the shadow arm's, from `captured` with `seed`.
#[cfg(oneiron_test_support)]
pub(crate) fn arm_params_for_test(
    captured: &LlmRequest,
    model: &ModelId,
    seed: u64,
) -> (BTreeMap<String, JsonValue>, BTreeMap<String, JsonValue>) {
    let (schema, shadow) = build_arms(captured, model, seed);
    (schema.params, shadow.params)
}
