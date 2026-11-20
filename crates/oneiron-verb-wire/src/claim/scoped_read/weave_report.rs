//! Moved from `crates/oneiron/src/claim/scoped_read/weave_report.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeKind;
use oneiron_contracts::register::Register;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("weave.section.kind")]
pub enum WeaveSectionKind {
    Changes,
    Projects,
    OpenAsks,
    Links,
    Conflicts,
    Exceptions,
    Admissions,
    Budgets,
    SieveScore,
    Digest,
}

/// A resident-authored recipe uses exact predicate names; no prose or
/// per-deployment ontology is compiled into the engine. Projects and budgets
/// read the typed project records and need no predicate list.
#[derive(Debug, Clone)]
pub struct WeaveSectionSpec {
    pub kind: WeaveSectionKind,
    pub predicates: Vec<String>,
    /// Direct graph kinds to project in a Links section. Empty for claim-only
    /// sections; the recipe, not the engine, decides which links belong here.
    pub edge_kinds: Vec<EdgeKind>,
}

impl WeaveSectionKind {
    pub fn policy_name(self) -> &'static str {
        self.as_str()
    }
}
