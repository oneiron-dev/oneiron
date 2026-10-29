//! Typed projections of retained result manifests and the existing reader.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::code_run::ResultFacet;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultRunRequest {
    pub run_id: EntityId,
}

/// An occurrence, never just a content digest. Equal bytes confer no access
/// to another occurrence, including another path in the same run.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultOccurrenceRequest {
    pub run_id: EntityId,
    pub occurrence: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultSliceRequest {
    pub run_id: EntityId,
    pub occurrence: EntityId,
    pub selection: ResultSliceSelection,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ResultSliceSelection {
    Bytes(ResultByteSelection),
    Lines(ResultLineSelection),
}

/// Half-open offsets, as [start] or [start, end]. The engine validates them.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultByteSelection {
    pub bytes: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultLineSelection {
    pub lines: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<ResultLineCursor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultLineCursor {
    pub offset: u64,
    pub line: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResultBodyKind {
    Text,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResultTaintState {
    Clean,
    TaintedLive,
    TaintedStale,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultTaint {
    pub state: ResultTaintState,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultTaintReference {
    pub secret_ref: String,
    pub generation: u32,
}

/// Provenance and read fence belong to this occurrence, not its shared bytes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultOccurrenceManifest {
    pub run_id: EntityId,
    pub occurrence: EntityId,
    pub path: String,
    pub handle: String,
    pub blake3: String,
    pub bytes: u64,
    pub kind: ResultBodyKind,
    pub lines: u64,
    pub complete: bool,
    pub taint: ResultTaint,
    pub taint_refs: Vec<ResultTaintReference>,
    /// None means unknown, never an empty/public source set.
    pub source_rows: Option<Vec<EntityId>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultCard {
    pub handle: String,
    pub bytes: u64,
    pub kind: ResultBodyKind,
    pub lines: u64,
    pub complete: bool,
    pub preview: String,
    pub name: Option<String>,
    pub taint: ResultTaint,
    pub more: Vec<ResultFacet>,
    /// The shape its head shows, when it is clean; none when tainted or withheld.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultReadRefusal {
    pub denied: String,
    #[serde(rename = "reasonCodes")]
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResultReadView {
    Available {
        manifest: ResultOccurrenceManifest,
        card: ResultCard,
    },
    Denied {
        refusal: ResultReadRefusal,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResultSliceView {
    Available {
        manifest: ResultOccurrenceManifest,
        page: ResultSlicePage,
    },
    Denied {
        refusal: ResultReadRefusal,
    },
}

/// The existing slice reader's bounded reply, including its scan continuation
/// or its content-free taint withholding. No opaque facet input or output.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ResultSlicePage {
    Withheld(ResultWithheld),
    Content(ResultSliceContent),
    Scanning(ResultSliceScanning),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultSliceContent {
    #[serde(rename = "ref")]
    pub reference: String,
    pub start: u64,
    pub end: u64,
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lossy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<ResultSliceSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultSliceScanning {
    #[serde(rename = "ref")]
    pub reference: String,
    pub done: bool,
    pub scanned: Vec<u64>,
    pub limit: String,
    pub next: ResultSliceSelection,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultWithheld {
    pub withheld: ResultTaintState,
    #[serde(rename = "ref")]
    pub reference: String,
    pub bytes: u64,
    pub lines: Option<u64>,
    pub kind: ResultBodyKind,
    pub taint: ResultTaint,
    pub reason: String,
}

/// A descriptor may precede a published handle. Incomplete with no retained
/// body is distinct from a complete empty result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultBodyStatus {
    pub occurrence: EntityId,
    pub complete: bool,
    pub retained: Option<ResultRetainedBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultRetainedBody {
    pub blake3: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultEffectRecord {
    pub seq: u64,
    pub effect: String,
    pub action_digest: Option<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

/// Recorded bridge entries are observations, not an assertion that every
/// entry succeeded or that an external effect committed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResultRunStatus {
    pub run_id: EntityId,
    pub replay_present: bool,
    pub checkpoint_count: usize,
    pub effects: Vec<ResultEffectRecord>,
    pub bodies: Vec<ResultBodyStatus>,
    pub occurrences: Vec<ResultOccurrenceManifest>,
}
