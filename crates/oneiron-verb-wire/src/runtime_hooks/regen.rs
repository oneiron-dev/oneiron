//! Moved from `crates/oneiron/src/runtime_hooks/regen.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::runtime_hooks::regen::enact::HookRegenCancel;
pub use crate::runtime_hooks::regen::history::HookRegenActor;
pub use crate::runtime_hooks::regen::history::HookRegenDecision;
pub use crate::runtime_hooks::regen::history::HookRegenEvent;
pub use crate::runtime_hooks::regen::history::HookRegenReceipt;
use crate::runtime_hooks::replay;
use crate::runtime_hooks::replay::HookReplayEntry;
use crate::runtime_hooks::replay::HookReplayResult;
use crate::store::pack_hook_proposal::HookSelector;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::skill_source::HubFile;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// What a hook body is written against: the verb table it calls and the
/// sandbox world it runs in. A change to either runs the intent again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookContractStamp {
    /// BLAKE3 of the verb table's declarations (`code-mode.d.ts`).
    pub verb_table: String,
    /// BLAKE3 of the hook world (`hook.wit`).
    pub sandbox: String,
}

impl HookContractStamp {
    /// This engine's contract.
    #[must_use]
    pub fn current() -> Self {
        Self {
            verb_table: blake3::hash(contract::VERB_TABLE.as_bytes())
                .to_hex()
                .to_string(),
            sandbox: blake3::hash(contract::HOOK_WORLD.as_bytes())
                .to_hex()
                .to_string(),
        }
    }
}

/// Where a regen stopped. Every phase keeps the last good body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookRegenFailurePhase {
    /// The hook kept no intent to run again.
    Intent,
    /// The regenerator could not write a body.
    Generate,
    /// The body it wrote is blank or not text.
    Validate,
    /// The golden set could not replay.
    GoldenReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenFailure {
    pub phase: HookRegenFailurePhase,
    pub message: String,
}

impl HookRegenFailure {
    #[must_use]
    pub fn new(phase: HookRegenFailurePhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
        }
    }
}

/// What one body returned on each golden run, by run key. A run the body ran
/// without failing records the BLAKE3 of its outcome token and JSON in
/// `cases`, whatever `compare` says against the live record: the compare
/// stands to the live run, not to a failure category. Two bodies returned
/// the same outcome on a run exactly when their `cases` entries match. A run
/// the body failed records its replay reason in `execution_failed`. A run the
/// current grant withholds records its key in `withheld`; a run whose inputs
/// are gone records its key in `missing_history`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookGoldenFingerprint {
    pub cases: BTreeMap<String, String>,
    pub execution_failed: BTreeMap<String, String>,
    pub withheld: BTreeSet<String>,
    pub missing_history: BTreeSet<String>,
}

/// One regen's golden manifest (ARCH-0080 §8, FIX 4691): the case vector it
/// replayed and both bodies' fingerprints over it. It rides the decision
/// while it waits and stays in the hook's regen history after, so a later
/// reader sees exactly which runs a decision stood on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookGoldenManifest {
    /// The saved runs replayed, by run key (64 hex), newest first.
    pub runs: Vec<String>,
    /// The last good body's pass over `runs`.
    pub last_good: HookGoldenFingerprint,
    /// The candidate's pass over `runs`.
    pub candidate: HookGoldenFingerprint,
}

impl HookGoldenFingerprint {
    /// One body's pass over the golden runs.
    fn of(entries: &[(String, HookReplayEntry)]) -> Self {
        let mut fingerprint = Self::default();
        for (run, entry) in entries {
            match &entry.result {
                HookReplayResult::Ran {
                    outcome,
                    outcome_json,
                    reason,
                    ..
                } if outcome.as_str() == "failed" => {
                    fingerprint.execution_failed.insert(
                        run.clone(),
                        reason
                            .clone()
                            .unwrap_or_else(|| "the body failed".to_owned()),
                    );
                }
                HookReplayResult::Ran {
                    outcome,
                    outcome_json,
                    ..
                } => {
                    let token = format!("{outcome}:{}", outcome_json.as_deref().unwrap_or(""));
                    fingerprint.cases.insert(run.clone(), body_hash(&token));
                }
                HookReplayResult::Withheld { .. } => {
                    fingerprint.withheld.insert(run.clone());
                }
                HookReplayResult::MissingHistory { .. } => {
                    fingerprint.missing_history.insert(run.clone());
                }
            }
        }
        fingerprint
    }
}

/// Where a candidate's golden replay parts from the last good body's. A golden
/// execution failure is execution-failed, not a valid difference: a
/// case-to-failure or case-to-history transition never lands in `changed`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookGoldenDiff {
    /// Every golden run compared: the union of all categories of both
    /// fingerprints.
    pub cases: usize,
    /// The run keys present in both `cases` maps whose successful outcome
    /// values differ.
    pub changed: Vec<String>,
    /// The run keys either fingerprint execution-failed, sorted.
    pub execution_failed: Vec<String>,
    /// The run keys either fingerprint withheld, sorted.
    pub withheld: Vec<String>,
    /// The run keys either fingerprint found without history, sorted.
    pub missing_history: Vec<String>,
}

impl HookGoldenDiff {
    fn between(last_good: &HookGoldenFingerprint, candidate: &HookGoldenFingerprint) -> Self {
        let runs: BTreeSet<&String> = last_good
            .cases
            .keys()
            .chain(last_good.execution_failed.keys())
            .chain(&last_good.withheld)
            .chain(&last_good.missing_history)
            .chain(candidate.cases.keys())
            .chain(candidate.execution_failed.keys())
            .chain(&candidate.withheld)
            .chain(&candidate.missing_history)
            .collect();
        let cases = runs.len();
        let changed: Vec<String> = runs
            .iter()
            .copied()
            .filter(
                |run| match (last_good.cases.get(*run), candidate.cases.get(*run)) {
                    (Some(before), Some(after)) => before != after,
                    _ => false,
                },
            )
            .cloned()
            .collect();
        let execution_failed: Vec<String> = runs
            .iter()
            .copied()
            .filter(|run| {
                last_good.execution_failed.contains_key(*run)
                    || candidate.execution_failed.contains_key(*run)
            })
            .cloned()
            .collect();
        let withheld: Vec<String> = runs
            .iter()
            .copied()
            .filter(|run| last_good.withheld.contains(*run) || candidate.withheld.contains(*run))
            .cloned()
            .collect();
        let missing_history: Vec<String> = runs
            .iter()
            .copied()
            .filter(|run| {
                last_good.missing_history.contains(*run) || candidate.missing_history.contains(*run)
            })
            .cloned()
            .collect();
        Self {
            cases,
            changed,
            execution_failed,
            withheld,
            missing_history,
        }
    }

    /// An empty golden set proves nothing, so it never adopts by itself. Any
    /// execution failure or history category also refuses adoption: only a
    /// nonempty set with no changed run and no diagnostic key is identical.
    #[must_use]
    pub fn identical(&self) -> bool {
        self.cases > 0
            && self.changed.is_empty()
            && self.execution_failed.is_empty()
            && self.withheld.is_empty()
            && self.missing_history.is_empty()
    }
}

/// A regen's decision, kept on the hook's record until it is enacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HookRegenOutcome {
    /// An identical fingerprint over successful runs: the candidate adopts
    /// without a question.
    AutoAdopt {
        candidate: String,
        target: HookContractStamp,
        diff: HookGoldenDiff,
        golden: HookGoldenManifest,
    },
    /// The golden replay differs, execution-failed, withheld, or lost history,
    /// or there is none: the owner stamps it.
    NeedsHumanStamp {
        candidate: String,
        target: HookContractStamp,
        diff: HookGoldenDiff,
        golden: HookGoldenManifest,
    },
    /// The last good body stands. `target` is the contract the regen ran
    /// against, so the engine's own pass tries each contract once.
    RolledBack {
        failure: HookRegenFailure,
        target: HookContractStamp,
    },
}

impl HookRegenOutcome {
    /// The candidate body's hash while one waits, as its binding records a
    /// body: the hash an adoption names, and the record's body hash once
    /// it is adopted. A rollback holds no candidate.
    #[must_use]
    pub fn candidate_hash(&self) -> Option<String> {
        match self {
            Self::AutoAdopt { candidate, .. } | Self::NeedsHumanStamp { candidate, .. } => {
                Some(body_hash(candidate))
            }
            Self::RolledBack { .. } => None,
        }
    }

    /// The contract this decision ran against.
    #[must_use]
    pub fn target(&self) -> &HookContractStamp {
        match self {
            Self::AutoAdopt { target, .. }
            | Self::NeedsHumanStamp { target, .. }
            | Self::RolledBack { target, .. } => target,
        }
    }
}

/// The body an adoption replaced, kept so the owner can roll the adoption
/// back (FIX 4690): its exact text, hash and the contract it passed under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenPrior {
    pub body: String,
    /// BLAKE3 of `body`, lowercase hex.
    pub body_hash: String,
    pub stamp: HookContractStamp,
}

/// One hook's regen record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenRecord {
    /// The last good body, as BLAKE3 hex.
    pub body_hash: String,
    /// The contract that body last passed under.
    pub stamp: HookContractStamp,
    /// The intent it came from, when the author kept one.
    pub intent: Option<String>,
    /// The last regen's decision, until it is enacted.
    pub pending: Option<HookRegenOutcome>,
    /// The body the last adoption replaced, until it is rolled back or
    /// another adoption replaces this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<HookRegenPrior>,
    /// The contract the owner declined a regen under, by a cancel or a
    /// rollback. The due list and the engine's own pass leave the hook on
    /// its body until the contract moves again; the owner may still run a
    /// regen by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declined: Option<HookContractStamp>,
}

impl HookRegenRecord {
    /// [`HookRegenOutcome::candidate_hash`] of the decision waiting here.
    #[must_use]
    pub fn candidate_hash(&self) -> Option<String> {
        self.pending
            .as_ref()
            .and_then(HookRegenOutcome::candidate_hash)
    }
}

/// A hook body's hash as its binding records it: BLAKE3, lowercase hex.
pub fn body_hash(body: &str) -> String {
    blake3::hash(body.as_bytes()).to_hex().to_string()
}
pub mod contract;
pub mod enact;
pub mod history;
