//! Moved from `crates/oneiron/src/claim/scoped_read/weave_report.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeKind;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
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
        match self {
            Self::Changes => "changes",
            Self::Projects => "projects",
            Self::OpenAsks => "open_asks",
            Self::Links => "links",
            Self::Conflicts => "conflicts",
            Self::Exceptions => "exceptions",
            Self::Admissions => "admissions",
            Self::Budgets => "budgets",
            Self::SieveScore => "sieve_score",
            Self::Digest => "digest",
        }
    }
}
