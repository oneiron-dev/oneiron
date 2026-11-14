//! Moved from `crates/oneiron/src/skill_optimize/eval_set/cut_audit.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::FamilyPurpose;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The method a cut was audited by, pinned on its row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditMethodPin {
    pub name: String,
    pub revision: u32,
    pub normalizer: String,
    pub shingle_size: u64,
    pub threshold: f64,
}

/// One case the audit read: its refs and purposes, never its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditCase {
    pub case: EntityId,
    pub family: EntityId,
    pub receipts: Vec<String>,
    pub parents: Vec<EntityId>,
    /// The purpose its family was assigned.
    pub assigned_purpose: FamilyPurpose,
    /// What it reads as now: a retired cohort's families are development.
    pub effective_purpose: FamilyPurpose,
}

/// A cut member and a case of another purpose whose texts overlap at or
/// above the threshold: flagged for review, never moved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NearCopyFlag {
    pub member_case: EntityId,
    pub other_case: EntityId,
    pub score: f64,
    pub intersection: u64,
    pub union: u64,
}

/// One comparison source the audit could not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub case: EntityId,
    /// The source whose text was missing; `None` when the case names no
    /// source with text at all.
    pub source: Option<String>,
}

/// Whether every audited case's text was read, and what was not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditCoverage {
    pub complete: bool,
    pub gaps: Vec<CoverageGap>,
}

/// The authenticated author of a sealed-cohort cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalCutAuthor {
    Skill {
        attempt: EntityId,
        skill: EntityId,
        revision: String,
    },
    Owner {
        person: EntityId,
    },
    /// The automated probe import, which authorizes nothing (FIX 10144).
    ProbeImport,
}
