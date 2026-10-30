//! Whether a recall finds what the cycle landed: the landed claim ids (the
//! stage lines' `landed_ids`, else the claims `vault.claims.list` shows
//! after the cycle and did not before the sitting ended), each claim read
//! back (`vault.claims.read_filtered`), and one light recall whose query is
//! that claim's own words.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

use super::super::client::Agent;
use super::cycle::recall;
use super::server_log::Scan;

/// The most rows `vault.claims.list` serves (`memory/caps.rs`).
const LIST_LIMIT: usize = 1000;
/// Landed claims read back, and how many of them get a recall.
const READ: usize = 20;
const TRIED: usize = 5;
/// Words in a proof query.
const QUERY_WORDS: usize = 16;

/// The claim ids `vault.claims.list` shows now, and whether the list was
/// cut at its limit (then a diff can miss rows).
pub(super) fn listed(agent: &Agent) -> Result<(BTreeSet<String>, bool), String> {
    let answer = agent
        .post("vault.claims.list", &json!({"limit": LIST_LIMIT}))
        .1
        .map_err(|e| format!("claims list: {e}"))?;
    let rows = answer["value"].as_array().cloned().unwrap_or_default();
    let ids = rows
        .iter()
        .filter_map(|row| row["claim_ref"].as_str().map(str::to_owned))
        .collect();
    Ok((ids, rows.len() >= LIST_LIMIT))
}

/// The `landed_ids` of every stage line read at or after `t0_ms`, in order,
/// without repeats.
pub(super) fn landed_from_stages(scan: &Scan, t0_ms: f64) -> Vec<String> {
    let mut ids = Vec::new();
    for seen in scan.stages.iter().filter(|s| s.at_ms >= t0_ms) {
        let joined = seen.fields.get("landed_ids").map_or("", String::as_str);
        for id in joined.split(',').map(str::trim).filter(|id| !id.is_empty()) {
            if !ids.iter().any(|known| known == id) {
                ids.push(id.to_owned());
            }
        }
    }
    ids
}

/// One landed claim's recall.
#[derive(Debug, Serialize)]
pub(super) struct Tried {
    pub(super) claim_ref: String,
    pub(super) subject_ref: Option<String>,
    pub(super) predicate: Option<String>,
    pub(super) approval: Option<String>,
    pub(super) lifecycle: Option<String>,
    pub(super) query: String,
    pub(super) found: bool,
    /// 1-based rank of the claim among the recall's items.
    pub(super) rank: Option<usize>,
    pub(super) ms: f64,
    pub(super) items: usize,
    pub(super) error: Option<String>,
}

/// One claim as `vault.claims.read_filtered` serves it to `agent`.
fn read(agent: &Agent, id: &str) -> Result<Value, String> {
    let answer = agent
        .post("vault.claims.read_filtered", &json!({"claim_ref": id}))
        .1?;
    match &answer["value"] {
        Value::Null => Err("not_readable".to_owned()),
        claim => Ok(claim.clone()),
    }
}

/// Every string and number under `value`, space-separated.
fn texts(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => {
            out.push(' ');
            out.push_str(text);
        }
        Value::Number(n) => {
            out.push(' ');
            out.push_str(&n.to_string());
        }
        Value::Array(items) => items.iter().for_each(|item| texts(item, out)),
        Value::Object(map) => map.values().for_each(|item| texts(item, out)),
        Value::Null | Value::Bool(_) => {}
    }
}

/// A query from the claim's own words: its value's, then its predicate's,
/// each word once, at most `QUERY_WORDS`.
fn query_of(claim: &Value) -> String {
    let mut text = String::new();
    texts(&claim["value"], &mut text);
    text.push(' ');
    text.push_str(claim["predicate"].as_str().unwrap_or(""));
    let mut seen = BTreeSet::new();
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty() && seen.insert(word.to_lowercase()))
        .take(QUERY_WORDS)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Where the claim `id` sits among a recall pack's items: its record id,
/// its short ref, or a revision its provenance names.
fn rank_of(pack: &Value, claim: &Value, id: &str) -> Option<usize> {
    let short = claim["short_ref"].as_str();
    let items = pack["items"].as_array()?;
    items
        .iter()
        .position(|item| {
            item["record"]["id"].as_str() == Some(id)
                || short.is_some_and(|short| item["short_id"].as_str() == Some(short))
                || item["provenance"]["source_revision_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|r| r.as_str() == Some(id)))
        })
        .map(|at| at + 1)
}

/// Whether recall may surface the claim: active, and approved or auto.
fn surfaceable(claim: &Value) -> bool {
    claim["lifecycle"].as_str() == Some("active")
        && matches!(claim["approval"].as_str(), Some("auto" | "approved"))
}

/// Reads up to `READ` landed claims, puts those recall may surface first,
/// and recalls each of the first `TRIED` by its own words.
pub(super) fn prove(agent: &Agent, landed: &[String]) -> Vec<Tried> {
    let mut read_back = landed
        .iter()
        .take(READ)
        .map(|id| (id.clone(), read(agent, id)))
        .collect::<Vec<_>>();
    read_back.sort_by_key(|(_, claim)| !claim.as_ref().is_ok_and(surfaceable));
    read_back
        .into_iter()
        .take(TRIED)
        .map(|(claim_ref, claim)| {
            let mut tried = Tried {
                claim_ref,
                subject_ref: None,
                predicate: None,
                approval: None,
                lifecycle: None,
                query: String::new(),
                found: false,
                rank: None,
                ms: 0.0,
                items: 0,
                error: None,
            };
            let claim = match claim {
                Ok(claim) => claim,
                Err(error) => {
                    tried.error = Some(format!("read {error}"));
                    return tried;
                }
            };
            let field = |key: &str| claim[key].as_str().map(str::to_owned);
            tried.subject_ref = field("subject_ref");
            tried.predicate = field("predicate");
            tried.approval = field("approval");
            tried.lifecycle = field("lifecycle");
            tried.query = query_of(&claim);
            if tried.query.is_empty() {
                tried.error = Some("no_words".to_owned());
                return tried;
            }
            let (ms, answer) = recall(agent, &tried.query);
            tried.ms = ms;
            match answer {
                Ok(pack) => {
                    tried.items = pack["items"].as_array().map_or(0, Vec::len);
                    tried.rank = rank_of(&pack, &claim, &tried.claim_ref);
                    tried.found = tried.rank.is_some();
                }
                Err(error) => tried.error = Some(format!("recall {error}")),
            }
            tried
        })
        .collect()
}
