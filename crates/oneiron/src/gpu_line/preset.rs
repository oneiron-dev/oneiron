//! Line presets (design pass 34, sections 3.2 and 3.3; row L1): a lane's line policy document,
//! carried by a pack in `knowledge/line-presets/<name>.json`. `vault.gpu.lines.set { preset }`
//! reads the document from the pack's Active install, lays the fields the owner states over it,
//! checks the whole as any policy, and stores the full values with the preset's reference. A
//! preset never applies itself, and a later version of its pack changes no line already set: the
//! line holds full values.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::fold::BudgetPolicy;
use super::store::gpu_seconds;
use super::wire::GpuLinePolicy;
use crate::llm::run_admission::LeaseUnit;

/// A line preset as `vault.gpu.lines.set` names it and a line keeps it: the pack, the preset's
/// name in it, and the content hash (hex) of its document, so the owner sets the line from the
/// exact bytes he read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinePresetRef {
    pub pack: String,
    pub name: String,
    pub digest: String,
}

/// A line policy document: the fields of a policy a lane's preset may carry. The wallet, the
/// period anchor, the offers, the machines and the role lists are the vault's own, so the owner
/// states them; a budget field the document leaves out takes the engine's neutral default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinePresetDocument {
    #[serde(default = "gpu_seconds")]
    pub unit: LeaseUnit,
    pub period_secs: u64,
    #[serde(default)]
    pub budget: BudgetPolicy,
}

/// The policy key whose object a stated policy lays over key by key.
const BUDGET: &str = "budget";

/// `stated` laid over `document`: each key the owner states replaces the document's, and inside
/// `budget` each budget key he states replaces the document's one.
#[must_use]
pub fn lay_over(document: &Map<String, Value>, stated: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = document.clone();
    for (key, value) in stated {
        match (merged.get_mut(key), value) {
            (Some(Value::Object(under)), Value::Object(over)) if key == BUDGET => {
                for (inner, value) in over {
                    under.insert(inner.clone(), value.clone());
                }
            }
            _ => {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    merged
}

/// The policy the fields `stated` give over the preset's `document`; with no preset, `stated`
/// alone, read as `vault.gpu.lines.set` always read its policy. The document is read as its
/// install checked it ([`check_document`]): a unit or budget it leaves out is the default, under
/// the fields the owner states.
///
/// # Errors
///
/// The decode's refusal, as text: a document that is not a line policy document, a field of
/// another shape, an unknown field, or one that neither the owner nor the document gives and that
/// has no default.
pub fn resolve_policy(
    document: Option<&Map<String, Value>>,
    stated: &Map<String, Value>,
) -> Result<GpuLinePolicy, String> {
    let merged = match document {
        Some(document) => lay_over(&decoded_document(document)?, stated),
        None => stated.clone(),
    };
    serde_json::from_value(Value::Object(merged)).map_err(|error| error.to_string())
}

/// `document` decoded as a [`LinePresetDocument`] and encoded again: each field it leaves out
/// holds its default.
///
/// # Errors
///
/// The decode's refusal, as text.
fn decoded_document(document: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let decoded = serde_json::from_value::<LinePresetDocument>(Value::Object(document.clone()))
        .map_err(|error| error.to_string())?;
    match serde_json::to_value(&decoded).map_err(|error| error.to_string())? {
        Value::Object(fields) => Ok(fields),
        other => Err(format!("a line policy document encodes as {other}")),
    }
}

/// Whether `document` is a line policy document ([`LinePresetDocument`]). Its bounds are the
/// policy's, checked when a line is set from it.
///
/// # Errors
///
/// The decode's refusal, as text.
pub fn check_document(document: &Map<String, Value>) -> Result<(), String> {
    decoded_document(document).map(|_| ())
}
