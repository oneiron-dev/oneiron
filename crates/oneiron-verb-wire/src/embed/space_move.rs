//! Moved from `crates/oneiron/src/embed/space_move.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
use heed::RoTxn;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::embedding::KindSlotBindings;
use oneiron_store::embedding_vocabulary::InputKind;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Where a kind slot's vectors are searched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpaceRef {
    /// The vault's own text vector index: the unbound text slot.
    TextIndex,
    /// A declared space.
    Declared(String),
}

impl SpaceRef {
    /// Whether `kind`'s slot reads here under `bindings`.
    fn serves(&self, bindings: &KindSlotBindings, kind: InputKind) -> bool {
        match self {
            Self::TextIndex => kind == InputKind::Text && bindings.text.is_none(),
            Self::Declared(id) => bindings.space_for(kind) == Some(id.as_str()),
        }
    }

    fn declared(&self) -> Option<&str> {
        match self {
            Self::TextIndex => None,
            Self::Declared(id) => Some(id),
        }
    }
}

impl std::fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TextIndex => f.write_str("the vault's text index"),
            Self::Declared(id) => write!(f, "embedding space {id}"),
        }
    }
}

/// A paired comparison's reading (NOT-WORSE = A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotWorse {
    /// The interval's low end is at or above minus the tolerance.
    NotWorse,
    /// The whole interval is below minus the tolerance.
    Worse,
    /// Too few families, or the interval spans the tolerance.
    Unknown,
}

/// A family-grouped mean paired difference and its two-sided 95% interval.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PairedInterval {
    pub mean: f32,
    pub low: f32,
    pub high: f32,
}

/// One kind's paired probe run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KindProbeCheck {
    pub kind: InputKind,
    /// Probes that ran: those of this kind with a live target.
    pub probes: usize,
    /// The independent source families those probes come from.
    pub families: usize,
    /// Candidate minus incumbent, of each probe's reciprocal rank at [`SPACE_PROBE_DEPTH`],
    /// averaged per family; `None` under [`SPACE_PROBE_MIN_FAMILIES`].
    pub difference: Option<PairedInterval>,
    /// The incumbent's second run minus its first, likewise: its same-probe retest.
    pub retest: Option<PairedInterval>,
    /// What the difference's low end is held to: the retest interval's widest bound, or the
    /// owner's stricter margin.
    pub tolerance: Option<f32>,
    pub verdict: NotWorse,
    /// The unrewarded canary: candidate minus incumbent of whether each probe finds a target
    /// within [`SPACE_PROBE_DEPTH`] at all, grouped by family as the difference is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<PairedInterval>,
    /// The canary's reading, by the same rule against its own retest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_verdict: Option<NotWorse>,
    /// The version of the kind's probe set the runs read, 32 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_version: Option<String>,
    /// The version of its answer key and scoring the runs read, 32 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rubric: Option<String>,
    /// The sufficiency card the reading was read on as the move concluded (FIX 1638).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<SufficiencyCard>,
    /// The probes that ran from a cut cohort, as the check's cohort metadata held them (FIX
    /// 6744): an owner's later yes counts its swap on their cohorts (FIX 7040).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cohort_members: Vec<CohortProbe>,
}

/// One probe a check ran whose date window had ended: a member of a cut cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CohortProbe {
    /// 32 hex.
    pub probe: String,
    /// Its source document.
    pub source: EntityId,
    /// Its date window, vault seconds: `from` up to, not including, `until`.
    pub from: u64,
    pub until: u64,
}

/// One paired probe run over every kind a move carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpaceMoveCheck {
    /// Vault seconds.
    pub checked_at: u64,
    pub kinds: Vec<KindProbeCheck>,
    /// Not worse when every kind is; worse when any kind is; unknown otherwise.
    pub verdict: NotWorse,
    /// The token the check's probe cohorts counted it under (FIX 6744); `None` when it kept
    /// no cohort metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_check: Option<String>,
}

/// Where a move stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpaceMoveState {
    /// The candidate fills beside the incumbent, which serves.
    Open,
    /// The candidate serves; the incumbent stays declared for undo. `by_owner` is the owner's
    /// yes over a check that did not read not worse.
    SwappedIn { at: u64, by_owner: bool },
    /// The incumbent kept serving; the candidate's rows of the moved kinds went. `timed_out` is
    /// a move closed at [`SPACE_MOVE_FILL_DEADLINE_SECS`] with no check run, not a worse one.
    Kept { at: u64, timed_out: bool },
    /// An undo bound the incumbent again.
    Undone { at: u64 },
}

/// A kind slot version move: every kind slot the incumbent served, moving to the candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpaceMove {
    pub candidate: String,
    pub incumbent: SpaceRef,
    pub kinds: BTreeSet<InputKind>,
    /// The owner's margin, held only where it is stricter than the measured retest noise.
    pub margin: Option<f32>,
    /// Vault seconds.
    pub started_at: u64,
    pub state: SpaceMoveState,
    pub last_check: Option<SpaceMoveCheck>,
}
