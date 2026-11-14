//! The resume preflight a resumed pending step walks (L8-23): its re-entered program meets the
//! calls its pending step recorded, in the one real pass, and each meeting is replay free,
//! changed or unreached. A pure tail proceeds with the divergence recorded; a tail holding an
//! effect step turns dry and the entry holds with this report. Entry: `ResumePreflightReport`.
//! The walk itself runs in `engine_executor::host::deadline_replay`.

use crate::code_run::{SelfCall, SelfEffect};
use crate::entity_id::EntityId;
use crate::task_verb::sdk::AgentVerb;

/// Whether the verdict names a pure tail or one holding an effect step (L8-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeVerdict {
    /// No changed or unreached entry is an effect step: the step commits.
    Pure,
    /// An effect step would re-fire: the entry holds with the report.
    EffectTail,
}

/// One recorded call the re-entered program made with another request (L8-23).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChangedStep {
    /// The call's bridge position.
    pub seq: u64,
    /// The call's effect, recorded and re-entered alike.
    pub effect: SelfEffect,
    /// Lowercase hex BLAKE3 of the recorded canonical request value.
    pub recorded_request_digest: String,
    /// Lowercase hex BLAKE3 of the re-entered canonical request value.
    pub reentered_request_digest: String,
    /// Whether the entry counts as an effect step.
    pub effect_step: bool,
}

/// One recorded program call the re-entered program never reached (L8-23).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnreachedStep {
    /// The call's bridge position.
    pub seq: u64,
    /// The call's recorded effect.
    pub effect: SelfEffect,
    /// Whether the entry counts as an effect step.
    pub effect_step: bool,
}

/// What the walk met: which recorded calls replay free, which changed, which went unreached,
/// and whether the guest boundary or the preparation drifted (L8-23). It holds digests, never
/// request bodies. Seqs ascend in every list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResumePreflightReport {
    /// The run whose step resumed.
    pub run_id: EntityId,
    /// The resumed step's seq.
    pub step_seq: u64,
    /// The pending step's bridge frontier.
    pub frontier: u64,
    /// Seqs that met their rows, ascending.
    pub replay_free: Vec<u64>,
    /// Changed calls, ascending seq.
    pub changed: Vec<ChangedStep>,
    /// Unreached recorded calls, ascending seq.
    pub unreached: Vec<UnreachedStep>,
    /// The guest boundary changed since the step parked.
    pub boundary_changed: bool,
    /// The program prepares to other JavaScript than the parked one ran as.
    pub preparation_changed: bool,
    /// Changed plus unreached entries with `effect_step`.
    pub effect_steps_would_refire: u64,
    /// `EffectTail` when the count is above zero, else `Pure`.
    pub verdict: ResumeVerdict,
}

impl ResumePreflightReport {
    /// Whether the walk met no drift at all (L8-23): nothing changed, nothing unreached, and
    /// neither flag. A clean report records no output.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.changed.is_empty()
            && self.unreached.is_empty()
            && !self.boundary_changed
            && !self.preparation_changed
    }

    /// Lowercase hex BLAKE3 of the report's effect drift (L8-23): the run, the step, and the
    /// changed and unreached entries that are effect steps, in report order. Pure noise never makes
    /// a new ask.
    #[must_use]
    pub fn effect_digest(&self) -> String {
        #[derive(serde::Serialize)]
        struct EffectDrift<'a> {
            run_id: EntityId,
            step_seq: u64,
            changed: Vec<&'a ChangedStep>,
            unreached: Vec<&'a UnreachedStep>,
        }
        let drift = EffectDrift {
            run_id: self.run_id,
            step_seq: self.step_seq,
            changed: self
                .changed
                .iter()
                .filter(|step| step.effect_step)
                .collect(),
            unreached: self
                .unreached
                .iter()
                .filter(|step| step.effect_step)
                .collect(),
        };
        let bytes = serde_json::to_vec(&drift).unwrap_or_default();
        crate::entity_id::bytes_to_hex_lower(blake3::hash(&bytes).as_bytes())
    }
}

impl std::fmt::Display for ResumePreflightReport {
    /// Canon's line: the replay-free, changed and unreached seqs as ranges, the flags, and the
    /// count, joined by a spaced middle dot (L8-23).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if !self.replay_free.is_empty() {
            let ranges = collapse_ranges(self.replay_free.iter().copied());
            if self.replay_free.len() == 1 {
                parts.push(format!("step {ranges} replays free"));
            } else {
                parts.push(format!("steps {ranges} replay free"));
            }
        }
        if !self.changed.is_empty() {
            let ranges = collapse_ranges(self.changed.iter().map(|step| step.seq));
            if self.changed.len() == 1 {
                parts.push(format!("step {ranges} changed"));
            } else {
                parts.push(format!("steps {ranges} changed"));
            }
        }
        if !self.unreached.is_empty() {
            let ranges = collapse_ranges(self.unreached.iter().map(|step| step.seq));
            if self.unreached.len() == 1 {
                parts.push(format!("step {ranges} unreached"));
            } else {
                parts.push(format!("steps {ranges} unreached"));
            }
        }
        if self.boundary_changed {
            parts.push("guest boundary changed".to_owned());
        }
        if self.preparation_changed {
            parts.push("preparation changed".to_owned());
        }
        let effect_steps = self.effect_steps_would_refire;
        if effect_steps == 1 {
            parts.push("1 effect step would re-fire".to_owned());
        } else {
            parts.push(format!("{effect_steps} effect steps would re-fire"));
        }
        f.write_str(&parts.join(" \u{00b7} "))
    }
}

/// Ascending seqs collapsed into `a-b` ranges (or `a`), joined by `", "` (L8-23).
fn collapse_ranges(seqs: impl IntoIterator<Item = u64>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut start: Option<u64> = None;
    let mut end = 0_u64;
    for seq in seqs {
        if start.is_some() && seq == end.saturating_add(1) {
            end = seq;
        } else {
            if let Some(first) = start.take() {
                parts.push(range_part(first, end));
            }
            start = Some(seq);
            end = seq;
        }
    }
    if let Some(first) = start.take() {
        parts.push(range_part(first, end));
    }
    parts.join(", ")
}

/// One collapsed range: `a-b`, or `a` alone (L8-23).
fn range_part(first: u64, end: u64) -> String {
    if first == end {
        first.to_string()
    } else {
        format!("{first}-{end}")
    }
}

/// Whether a call with `effect` counts as an effect step (L8-23, ruling L8-23-EFFECT = A):
/// every call that is not a read. `verb` is the catalog verb name of an `AgentVerb` call, read
/// off the recorded row or the re-entered call; an unknown verb is an effect. The match is
/// exhaustive with no wildcard arm, so a new variant forces a choice.
pub(in crate::engine_executor) fn effect_step(effect: SelfEffect, verb: Option<&str>) -> bool {
    match effect {
        SelfEffect::MemorySearch
        | SelfEffect::Context
        | SelfEffect::InferenceDefaultsRead
        | SelfEffect::Leader
        | SelfEffect::RepoSnapshotsGet
        | SelfEffect::RepoSnapshotsRead
        | SelfEffect::RepoSymbolsDefinitions
        | SelfEffect::RepoSymbolsNeighbors
        | SelfEffect::RepoViewsGet
        | SelfEffect::RepoViewsRead
        | SelfEffect::RepoMergeQueueObserve
        | SelfEffect::RepoSymbolsObserve => false,
        SelfEffect::AgentVerb => verb
            .and_then(AgentVerb::from_name)
            .is_none_or(AgentVerb::writes),
        SelfEffect::AgentsSpawn
        | SelfEffect::TasksAsk
        | SelfEffect::TasksWait
        | SelfEffect::TasksRefuse
        | SelfEffect::ConsultResult
        | SelfEffect::SkillsCall
        | SelfEffect::MemoryWriteFixture
        | SelfEffect::MemoryPutClaim
        | SelfEffect::MemorySupersedeClaim
        | SelfEffect::MemoryPutEdge
        | SelfEffect::Ask
        | SelfEffect::DestructiveFixture
        | SelfEffect::OutboundFixture
        | SelfEffect::TaskDelegate
        | SelfEffect::Speak
        | SelfEffect::Think
        | SelfEffect::Express
        | SelfEffect::ReportBlocked
        | SelfEffect::AgentsPut
        | SelfEffect::InferenceDefaultsReplace
        | SelfEffect::WakePolicyWrite
        | SelfEffect::ConnectorAnswer
        | SelfEffect::WorldPrivacySet
        | SelfEffect::Fold
        | SelfEffect::ReaderSpawn
        | SelfEffect::ReaderReport
        | SelfEffect::TasksWaitSet
        | SelfEffect::Summarize
        | SelfEffect::LeaderSplit
        | SelfEffect::Team
        | SelfEffect::WorkflowDispatch
        | SelfEffect::RepoSnapshotsIngest
        | SelfEffect::RepoWorkOpen
        | SelfEffect::RepoSymbolsDeclare
        | SelfEffect::RepoSymbolsRenew
        | SelfEffect::RepoSymbolsRelease
        | SelfEffect::RepoProposalSubmit
        | SelfEffect::RepoProposalResolve
        | SelfEffect::RepoMergeQueueEnqueue
        | SelfEffect::RepoCheckoutBind
        | SelfEffect::RepoExport => true,
    }
}

/// The catalog verb name a re-entered call names, when it names one (L8-23).
pub(super) fn call_verb(call: &SelfCall) -> Option<&str> {
    if let SelfCall::AgentVerb(verb) = call {
        Some(verb.verb.as_str())
    } else {
        None
    }
}

/// Lowercase hex BLAKE3 of the MessagePack encoding of `request`, the canonical request value
/// the replay match compares (L8-23). The value is hashed, never kept.
pub(super) fn request_digest(request: &rmpv::Value) -> String {
    let mut encoded = Vec::new();
    if rmpv::encode::write_value(&mut encoded, request).is_err() {
        encoded.clear();
    }
    crate::entity_id::bytes_to_hex_lower(blake3::hash(&encoded).as_bytes())
}
