//! The inputs of the verb-table rows a code run answers itself
//! (`context: "run"` in `scripts/sdk/agent-verbs.json`).
//!
//! Each is the object code mode's `self.memory.<row>(input)` takes. The guest
//! bridge decodes it into the run's own typed `self.*` call, so a row keeps the
//! effect, gate and replay row it had as a hand-written import. Each input is
//! closed: a field it does not list is refused, as on every other row.
//!
//! The integer bounds are the ones the typed imports enforced: a time is a
//! JavaScript safe integer, since a guest number above it was already rounded,
//! and a search limit fits a `u32`.

/// The largest integer a JavaScript number carries exactly.
pub const JS_SAFE_INTEGER: u64 = (1 << 53) - 1;

use serde::Deserialize;

/// `self.memory.search`: a bounded text search over the run's storage route.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySearchInput {
    pub query: String,
    #[schemars(range(max = "u32::MAX"))]
    pub limit: Option<u32>,
}

/// `self.memory.put_claim`: one claim candidate through the run's gate.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryClaimInput {
    /// The claim's entity id, hex.
    pub id: String,
    pub predicate: String,
    /// The subject entity's id, hex.
    pub subject: String,
    pub value: serde_json::Value,
    /// An `f32`: a number past its range is refused, never rounded.
    #[schemars(range(min = "f32::MIN", max = "f32::MAX"))]
    pub confidence: Option<f64>,
    /// When the claim held, unix seconds; the run's clock when absent.
    pub occurred: Option<MemoryTimeRange>,
    /// When it was learned, unix seconds; the run's clock when absent.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub learned_at: Option<u64>,
}

/// A closed `[start, end]` span in unix seconds.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryTimeRange {
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub start: u64,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub end: u64,
}

/// `self.memory.supersede_claim`: closes `oldId` in favour of `newId`.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemorySupersedeInput {
    pub new_id: String,
    pub old_id: String,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub now: u64,
}

/// `self.memory.put_edge`: one typed edge through the run's edge gate.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryEdgeInput {
    pub src: String,
    /// The edge kind's snake_case name.
    pub kind: String,
    pub tgt: String,
    /// The kind's default weight when absent; an `f32`, as `confidence` is.
    #[schemars(range(min = "f32::MIN", max = "f32::MAX"))]
    pub weight: Option<f64>,
}
