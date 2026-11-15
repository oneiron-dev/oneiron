//! Moved from `crates/oneiron/src/edit_distance/attribution/triage.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Which worsening fired, with the numbers it fired on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorseningSignal {
    /// The `learning.edit_cost` cell's mean rose past the spread its earlier
    /// head held.
    #[serde(rename_all = "camelCase")]
    EditCostClimbing {
        /// The head the climb is measured from.
        previous_head: String,
        previous_mean: f64,
        previous_spread: f64,
        /// The head now.
        current_head: String,
        current_mean: f64,
        current_spread: f64,
    },
    /// The subject's newest outcomes in the scope were rejected `length`
    /// times in a row, the newest on receipt `newest`.
    #[serde(rename_all = "camelCase")]
    RejectionRun { length: u32, newest: String },
    /// The reliability floor contract's open quarantine proposal: the skill's
    /// posterior lower bound fell under the floor.
    #[serde(rename_all = "camelCase")]
    ReliabilityFloor {
        proposal: String,
        /// The executor whose cell crossed; `None` for the skill-wide check.
        executor: Option<String>,
        lower_bound: f32,
        floor: f32,
        crossed_at: u64,
    },
}

impl WorseningSignal {
    /// The signal's stable token, one part of its escalation's key.
    const fn token(&self) -> &'static str {
        match self {
            Self::EditCostClimbing { .. } => "edit_cost_climbing",
            Self::RejectionRun { .. } => "rejection_run",
            Self::ReliabilityFloor { .. } => "reliability_floor",
        }
    }

    /// What fired it: the head now, the newest rejected receipt, or the
    /// proposal. A re-trigger names another.
    fn trigger(&self) -> &str {
        match self {
            Self::EditCostClimbing { current_head, .. } => current_head.as_str(),
            Self::RejectionRun { newest, .. } => newest.as_str(),
            Self::ReliabilityFloor { proposal, .. } => proposal.as_str(),
        }
    }
}

/// What the subject of a packet is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageSubject {
    /// A SKILL a `skill_defect` share charged.
    Skill,
    /// An actor an `execution_lapse` share charged.
    Actor,
}

/// Who published the subject (ARCH-0056 r5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPublisher {
    /// Owner-authored, or made in the vault: the owner fixes it.
    Owner,
    /// A shipped or system artifact: an imported skill, or a seeded `sys.*`
    /// agent definition.
    Shipped,
}

/// One failing receipt, as refs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageReceipt {
    /// The judged receipt.
    pub receipt: String,
    /// The key of its Δ in the side-ledger
    /// (`amendment_delta`
    /// reads it); `None` when none is recorded, as for a rejection.
    pub delta_ref: Option<String>,
    pub rejected: bool,
    /// The judgment's edit mass.
    pub d_norm: f32,
    pub at: u64,
    /// The terminal pack receipt of the attempt the proposal came from.
    pub attempt: Option<String>,
    /// The drafting executor at revision; `None` when unknown.
    pub executor: Option<String>,
    /// The judge revision the judgment stands on; `None` for the rule tier.
    pub judge: Option<String>,
    /// The skill the run loaded, at version.
    pub skill: Option<SkillAtVersion>,
}

/// A skill at a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAtVersion {
    /// The SKILL entity.
    pub skill: String,
    /// Its stable name.
    pub skill_id: String,
    pub version: String,
    /// Whether the version was read through the attempt's pack receipt, its
    /// pinned revision where the manifest pinned one; `false` is the record
    /// as it stands now.
    pub via_attempt: bool,
}

/// An AgentDefinition behind the failing runs: the system-prompt ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDefinitionRef {
    /// The AGENT_DEF entity.
    pub definition: String,
    pub agent_id: String,
    /// The revision the failing runs were stamped with, where their pack
    /// receipts pin one (FIX 11637); else its version as it stands now, and
    /// the runs may have used an earlier one.
    pub version: String,
    /// The seeded `sys.*` id of a shipped definition.
    pub logical_id: Option<String>,
}

/// One value that changed between two failing receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentChange {
    /// The first receipt with the new value.
    pub receipt: String,
    pub before: String,
    pub after: String,
    pub at: u64,
}

/// What changed last across the failing receipts in the learning window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentChanges {
    /// Where the window starts: one learning half-life before the packet.
    pub window_from: u64,
    /// The last skill revision, as `skill_id@version`.
    pub skill_revision: Option<RecentChange>,
    /// The last executor change.
    pub executor: Option<RecentChange>,
}

/// The triage packet one worsening escalation carries (ARCH-0056 §5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriagePacket {
    /// The signal that fired and its numbers.
    pub signal: WorseningSignal,
    /// The skill or actor it is about.
    pub subject: String,
    pub subject_kind: TriageSubject,
    /// The consent scope the failing receipts share.
    pub scope: String,
    /// The project the failing runs counted in, as an entity id; `None` is
    /// the vault's (FIX 11627). A packet written before packets carried a
    /// project decodes as the vault's.
    #[serde(default)]
    pub project: Option<String>,
    pub publisher: ArtifactPublisher,
    /// The newest failing receipts, oldest first: the judged receipts in this
    /// scope that charge the subject or left an amended or rejected outcome
    /// on its cells.
    pub receipts: Vec<TriageReceipt>,
    pub agent_definitions: Vec<AgentDefinitionRef>,
    /// Each skill at each version the receipts name.
    pub skills: Vec<SkillAtVersion>,
    /// Each executor stamp the receipts name.
    pub executors: Vec<String>,
    pub recent_changes: RecentChanges,
    /// When the outcome that fired it landed.
    pub at: u64,
}
