//! Request hashing, memo keys, and provider wire calls.

use super::cli_and_pinned_config::PinnedAttestation;
use super::config_types::{
    ArmId, BROWSE_JUDGE_PROMPT_VERSION, BenchTask, CAMPAIGN_ID, ChatResponse, FixtureVault,
    GoldLabel, OPENROUTER_CHAT_COMPLETIONS, REQUEST_TEMPERATURE, RunSettings, SCORER_VERSION,
    TaskClass, WALL_CLOCK_CAP_S,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};
pub(super) fn request_nonce(task: &BenchTask, arm: ArmId, rep_index: u32) -> String {
    format!(
        "{CAMPAIGN_ID}:{}:{}:rep-{rep_index}",
        task.task_id,
        arm.as_str()
    )
}

fn judge_request_nonce(task: &BenchTask, rep_index: u32) -> String {
    format!(
        "{CAMPAIGN_ID}:{}:browse-judge:rep-{rep_index}",
        task.task_id
    )
}

pub(super) fn openrouter_request_body(
    messages: &[Value],
    max_tokens: u32,
    request_user: &str,
    settings: &RunSettings,
) -> Value {
    json!({
        "model": settings.model,
        "messages": messages,
        "temperature": REQUEST_TEMPERATURE,
        "max_tokens": max_tokens,
        "provider": settings.provider_lock(),
        "user": request_user
    })
}

/// The wire model id a built request body actually transmits.
fn transmitted_wire_model(request: &Value) -> Result<&str, String> {
    request
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "request body carries no transmitted model id".to_owned())
}

/// The pin THIS body transmits under, or `Ok(None)` for an unpinned run.
///
/// Fail-closed trust boundary (ONE-1344): when the run is pinned, the model the
/// body actually carries must resolve to a pinned revision. A body whose wire id
/// the pin file does not cover refuses — a pinned run never silently transmits
/// unpinned.
pub(super) fn pinned_transmit_attestation(
    settings: &RunSettings,
    request: &Value,
) -> Result<Option<PinnedAttestation>, String> {
    let Some(pinned) = settings.pinned.as_ref() else {
        return Ok(None);
    };
    let wire_id = transmitted_wire_model(request)?;
    pinned.attestation_for(wire_id).map(Some).ok_or_else(|| {
        format!(
            "--pinned-config does not cover transmitted model `{wire_id}`; \
             refusing to transmit unpinned"
        )
    })
}

/// The request hash a row is keyed and validated by.
///
/// An unpinned run hashes exactly the transmitted body, byte-identical to
/// pre-pin campaigns. A pinned run hashes the body TOGETHER with the pinned
/// revision and pin-file digest it transmits under, so a pinned run can never
/// key onto — and therefore never reuse — a row written by an unpinned run or
/// by a run pinned to a different revision.
pub(super) fn request_hash(request: &Value, pinned: Option<&PinnedAttestation>) -> String {
    match pinned {
        None => blake3_hex(request.to_string().as_bytes()),
        Some(pinned) => blake3_hex(
            json!({
                "body": request.to_string(),
                "pinnedModel": pinned.model,
                "pinnedConfigDigest": pinned.config_digest,
            })
            .to_string()
            .as_bytes(),
        ),
    }
}

pub(super) fn eval_memo_key(
    task: &BenchTask,
    arm: ArmId,
    rep_index: u32,
    request_nonce: &str,
    request_hash: &str,
    judge_cache_key: Option<&str>,
) -> String {
    let mut input = json!({
        "campaign": CAMPAIGN_ID,
        "callPurpose": "Eval",
        "scorerVersion": SCORER_VERSION,
        "taskId": task.task_id,
        "class": task.class.as_str(),
        "arm": arm.as_str(),
        "repIndex": rep_index,
        "requestNonce": request_nonce,
        "requestHash": request_hash,
    });
    if let Some(judge_cache_key) = judge_cache_key {
        input["judgeCacheKey"] = json!(judge_cache_key);
    }
    blake3_hex(input.to_string().as_bytes())
}

pub(super) fn judge_cache_key(task: &BenchTask) -> Option<String> {
    if task.class == TaskClass::BrowseThenAnswer {
        Some(BROWSE_JUDGE_PROMPT_VERSION.to_owned())
    } else {
        None
    }
}

pub(super) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub(super) fn call_openrouter(
    api_key: &str,
    messages: &[Value],
    max_tokens: u32,
    request_user: &str,
    settings: &RunSettings,
) -> Result<ChatResponse, String> {
    if api_key.contains(['\r', '\n']) {
        return Err("OPENROUTER_API_KEY contains unsupported newline characters".to_owned());
    }
    let request = openrouter_request_body(messages, max_tokens, request_user, settings);
    // The single transmit chokepoint (eval rows AND the browse judge): a pinned
    // run refuses here, before curl is spawned, unless the model this body
    // actually carries resolves to a pinned revision.
    pinned_transmit_attestation(settings, &request)?;
    let mut request_file =
        tempfile::NamedTempFile::new().map_err(|error| format!("create request body: {error}"))?;
    request_file
        .write_all(request.to_string().as_bytes())
        .map_err(|error| format!("write OpenRouter request body: {error}"))?;
    request_file
        .flush()
        .map_err(|error| format!("flush OpenRouter request body: {error}"))?;

    let curl_config = format!(
        "silent\n\
         show-error\n\
         fail-with-body\n\
         max-time = \"{}\"\n\
         header = \"Authorization: Bearer {}\"\n\
         header = \"Content-Type: application/json\"\n",
        WALL_CLOCK_CAP_S,
        curl_config_escape(api_key)
    );
    let mut child = Command::new("curl")
        .arg("--config")
        .arg("-")
        .arg("--data-binary")
        .arg(format!("@{}", request_file.path().display()))
        .arg(OPENROUTER_CHAT_COMPLETIONS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn curl for OpenRouter: {error}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "curl stdin was not available".to_owned())?;
        stdin
            .write_all(curl_config.as_bytes())
            .map_err(|error| format!("write curl config: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for OpenRouter response: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "OpenRouter provider-locked request failed: status={} stderr={} body={}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    let body: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse OpenRouter response JSON: {error}"))?;
    let content = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OpenRouter response missing assistant content: {body}"))?
        .to_owned();
    let tokens_total = body
        .get("usage")
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let generation_id = body
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(ChatResponse {
        content,
        tokens_total,
        generation_id,
    })
}

fn curl_config_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(super) fn chat_message(role: &str, content: String) -> Value {
    json!({
        "role": role,
        "content": content
    })
}

pub(super) fn score_task(task: &BenchTask, answer: &str) -> (f64, Value) {
    match &task.gold {
        GoldLabel::RetrievalQa { relevant_claim_ids } => {
            let cited = extract_claim_ids(answer);
            let gold = relevant_claim_ids.iter().cloned().collect::<BTreeSet<_>>();
            let f1 = set_f1(&cited, &gold);
            (
                f1,
                json!({"set_f1": f1, "cited": cited, "gold_count": gold.len()}),
            )
        }
        GoldLabel::MultiHop {
            exact_answer,
            supporting_ids,
        } => {
            let answer_hit = contains_case_insensitive(answer, exact_answer);
            let support_f1 = set_f1(
                &extract_claim_ids(answer),
                &supporting_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            let score = if answer_hit { 0.7 } else { 0.0 } + support_f1 * 0.3;
            (
                score,
                json!({"exact_answer": answer_hit, "supporting_ids_f1": support_f1}),
            )
        }
        GoldLabel::Provenance {
            field,
            value,
            supporting_ids,
        } => {
            let value_hit = contains_case_insensitive(answer, value);
            let support_f1 = set_f1(
                &extract_claim_ids(answer),
                &supporting_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            let score = if value_hit { 0.7 } else { 0.0 } + support_f1 * 0.3;
            (
                score,
                json!({"field": field, "field_match": value_hit, "supporting_ids_f1": support_f1}),
            )
        }
        GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } => {
            let citation_f1 = set_f1(
                &extract_claim_ids(answer),
                &required_claim_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            (
                citation_f1,
                json!({"citation_f1": citation_f1, "blind_judge": "pending"}),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn judge_browse_answer(
    api_key: &str,
    task: &BenchTask,
    fixture: &FixtureVault,
    answer: &str,
    citation_score: f64,
    citation_detail: Value,
    rep_index: u32,
    settings: &RunSettings,
) -> Result<(f64, Value, u32, Option<String>), String> {
    let GoldLabel::BrowseThenAnswer {
        topic,
        rubric,
        required_claim_ids,
    } = &task.gold
    else {
        return Ok((citation_score, citation_detail, 0, None));
    };
    let evidence = claim_evidence_block(fixture, required_claim_ids)?;
    let judge_answer = blind_judge_answer(answer);
    let judge_prompt = format!(
        "Grade this answer on a blind 1-5 rubric. The arm identity is hidden.\n\
         Task topic: {topic}\n\
         Required claim evidence:\n{evidence}\n\
         Rubric coverage: {}\n\
         Rubric faithfulness: {}\n\
         Rubric citation validity: {}\n\
         Return JSON only: {{\"coverage\":1-5,\"faithfulness\":1-5,\"citation_validity\":1-5,\"notes\":\"short\"}}\n\n\
         Answer:\n{judge_answer}",
        rubric.coverage, rubric.faithfulness, rubric.citation_validity
    );
    let request_user = judge_request_nonce(task, rep_index);
    let response = call_openrouter(
        api_key,
        &[
            chat_message(
                "system",
                "You are a blind evaluator. Return valid JSON only.".to_owned(),
            ),
            chat_message("user", judge_prompt),
        ],
        1_200,
        &request_user,
        settings,
    )?;
    let parsed = serde_json::from_str::<Value>(&response.content).unwrap_or_else(|_| {
        json!({
            "coverage": 1,
            "faithfulness": 1,
            "citation_validity": 1,
            "notes": "judge returned non-JSON"
        })
    });
    let coverage = rubric_score(&parsed, "coverage");
    let faithfulness = rubric_score(&parsed, "faithfulness");
    let citation_validity = rubric_score(&parsed, "citation_validity");
    let mean = (coverage + faithfulness + citation_validity) / 15.0;
    let final_accuracy = final_browse_accuracy(mean, citation_score);
    let generation_id = response.generation_id.clone();
    Ok((
        final_accuracy,
        json!({
            "browse_rubric": parsed,
            "rubric_normalized_score": mean,
            "citation_score": citation_score,
            "normalized_score": final_accuracy,
            "combiner": "min(rubric_normalized_score,citation_score)",
            "judge_tokens_total": response.tokens_total,
            "judge_generation_id": generation_id.as_deref(),
            "judge_prompt_version": BROWSE_JUDGE_PROMPT_VERSION,
            "citation_precheck": citation_detail
        }),
        response.tokens_total,
        generation_id,
    ))
}

pub(super) fn blind_judge_answer(answer: &str) -> String {
    let mut output = String::with_capacity(answer.len());
    let mut rest = answer;
    while let Some(start) = rest.find("/claims/") {
        output.push_str(&rest[..start]);
        let path_start = start + "/claims/".len();
        let after_prefix = &rest[path_start..];
        if let Some(suffix_start) = after_prefix.find(".txt") {
            let claim_id = &after_prefix[..suffix_start];
            if is_claim_path_id(claim_id) {
                output.push_str(claim_id);
                rest = &after_prefix[suffix_start + ".txt".len()..];
                continue;
            }
        }
        output.push_str("/claims/");
        rest = &rest[path_start..];
    }
    output.push_str(rest);
    output
}

fn is_claim_path_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn claim_evidence_block(fixture: &FixtureVault, claim_ids: &[String]) -> Result<String, String> {
    let by_id = fixture
        .claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    let mut evidence = String::new();
    for claim_id in claim_ids {
        let claim = by_id
            .get(claim_id.as_str())
            .ok_or_else(|| format!("missing fixture claim `{claim_id}`"))?;
        evidence.push_str(&format!("- {}: {}\n", claim.claim_id, claim.text));
    }
    Ok(evidence)
}

pub(super) fn final_browse_accuracy(rubric_mean: f64, citation_score: f64) -> f64 {
    rubric_mean
        .clamp(0.0, 1.0)
        .min(citation_score.clamp(0.0, 1.0))
}

fn rubric_score(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(1.0, 5.0)
}

fn extract_claim_ids(answer: &str) -> BTreeSet<String> {
    answer
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .filter(|token| token.starts_with("claim-") && token.len() == "claim-0000".len())
        .map(ToOwned::to_owned)
        .collect()
}

fn set_f1(actual: &BTreeSet<String>, expected: &BTreeSet<String>) -> f64 {
    if actual.is_empty() && expected.is_empty() {
        return 1.0;
    }
    if actual.is_empty() || expected.is_empty() {
        return 0.0;
    }
    let true_positive = actual.intersection(expected).count() as f64;
    if true_positive == 0.0 {
        return 0.0;
    }
    let precision = true_positive / actual.len() as f64;
    let recall = true_positive / expected.len() as f64;
    2.0 * precision * recall / (precision + recall)
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}
