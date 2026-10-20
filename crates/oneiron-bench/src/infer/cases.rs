//! Case packets, read at run time from a JSONL file outside the source tree.
//!
//! The bench embeds no case and has no fallback: a missing or unreadable file
//! fails the run. Errors name the line and the kind of fault, never the text
//! of the packet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::{ContentPart, LlmMessage, LlmMessageRole};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Which production contract a case's reply is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scorer {
    Claims,
    Decisions,
}

#[derive(Deserialize)]
struct CaseMessage {
    role: String,
    content: String,
}

/// One JSONL line. Fields this bench does not read are ignored.
#[derive(Deserialize)]
struct CaseLine {
    id: String,
    kind: String,
    scorer: Scorer,
    messages: Vec<CaseMessage>,
    max_tokens: u64,
    thinking: bool,
    #[serde(default)]
    gold: Option<BTreeMap<String, JsonValue>>,
    #[serde(default)]
    n_gold: Option<u64>,
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    approx_input_tokens: Option<u64>,
}

pub(super) struct Case {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) scorer: Scorer,
    pub(super) messages: Vec<LlmMessage>,
    pub(super) max_tokens: u64,
    pub(super) thinking: bool,
    /// Each gold id's expected action.
    pub(super) gold: Option<BTreeMap<String, String>>,
    pub(super) n_gold: Option<u64>,
    pub(super) prompt_tokens: Option<u64>,
    pub(super) approx_input_tokens: Option<u64>,
    /// BLAKE3 of the line's RFC 8785 canonical JSON.
    pub(super) digest: String,
}

pub(super) struct CaseFile {
    /// BLAKE3 of the file's bytes.
    pub(super) digest: String,
    pub(super) cases: Vec<Case>,
}

/// The source tree this binary was built from: the nearest ancestor of the
/// crate's manifest directory holding `.git`, else the workspace root two
/// levels up.
fn source_tree() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .or_else(|| manifest.ancestors().nth(2))
        .unwrap_or(manifest);
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// Refuses a `flag` path inside the source tree: cases, rows and outputs
/// stay outside the repo. A path that does not exist yet is judged by its
/// nearest existing ancestor.
pub(super) fn refuse_in_tree(flag: &str, path: &Path) -> Result<(), String> {
    let tree = source_tree();
    let existing = path
        .ancestors()
        .find_map(|dir| std::fs::canonicalize(dir).ok())
        .unwrap_or_else(|| path.to_path_buf());
    if existing.starts_with(&tree) {
        return Err(format!(
            "{flag} {} is inside the source tree {}; case packets and results stay outside the repo",
            path.display(),
            tree.display()
        ));
    }
    Ok(())
}

fn role(name: &str) -> Option<LlmMessageRole> {
    match name {
        "system" => Some(LlmMessageRole::System),
        "user" => Some(LlmMessageRole::User),
        "assistant" => Some(LlmMessageRole::Assistant),
        _ => None,
    }
}

/// A gold value's action: the string itself, or an object's `action`.
fn gold_action(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(action) => Some(action.clone()),
        JsonValue::Object(fields) => fields
            .get("action")
            .and_then(JsonValue::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

fn case(number: usize, value: JsonValue) -> Result<Case, String> {
    let at = |fault: &str| format!("cases line {number}: {fault}");
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| at("not canonical"))?;
    let line: CaseLine = serde_json::from_value(value).map_err(|e| {
        at(&format!(
            "not a case packet ({:?} fault in a field)",
            e.classify()
        ))
    })?;
    if line.id.trim().is_empty() {
        return Err(at("empty id"));
    }
    let messages = line
        .messages
        .into_iter()
        .map(|message| {
            Ok(LlmMessage {
                role: role(&message.role)
                    .ok_or_else(|| at("a message role is not system, user or assistant"))?,
                content: vec![ContentPart::Text {
                    text: message.content,
                }],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if messages.is_empty() {
        return Err(at("no messages"));
    }
    let gold = line
        .gold
        .map(|gold| {
            gold.into_iter()
                .map(|(id, value)| {
                    gold_action(&value)
                        .map(|action| (id, action))
                        .ok_or_else(|| at("a gold entry has no action string"))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()
        })
        .transpose()?;
    Ok(Case {
        id: line.id,
        kind: line.kind,
        scorer: line.scorer,
        messages,
        max_tokens: line.max_tokens,
        thinking: line.thinking,
        gold,
        n_gold: line.n_gold,
        prompt_tokens: line.prompt_tokens,
        approx_input_tokens: line.approx_input_tokens,
        digest: blake3::hash(&canonical).to_hex().to_string(),
    })
}

pub(super) fn load(path: &Path) -> Result<CaseFile, String> {
    refuse_in_tree("--cases", path)?;
    let bytes = std::fs::read(path).map_err(|e| format!("read --cases {}: {e}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("--cases {} is not UTF-8", path.display()))?;
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        let value: JsonValue = serde_json::from_str(line).map_err(|e| {
            format!(
                "cases line {number}: not JSON ({:?} at column {})",
                e.classify(),
                e.column()
            )
        })?;
        let case = case(number, value)?;
        if !ids.insert(case.id.clone()) {
            return Err(format!("cases line {number}: a case id repeats"));
        }
        cases.push(case);
    }
    if cases.is_empty() {
        return Err(format!("--cases {} holds no case", path.display()));
    }
    Ok(CaseFile {
        digest: blake3::hash(&bytes).to_hex().to_string(),
        cases,
    })
}
