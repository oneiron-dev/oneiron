//! Hook regen (ARCH-0080 §8, slice 3): the shape of lens regen (OF-321),
//! with records typed for hooks. A hook keeps the intent its body came from.
//! When the verb table or the sandbox contract changes under it, the intent
//! runs again through an injected [`HookRegenerator`], and the hook's newest
//! saved runs, loaded once, replay as its golden set under the last good body
//! and under the candidate. Only an identical fingerprint over successful runs
//! adopts; a diff, an execution failure, a withheld run, or a run without
//! history waits for the owner's stamp; a failure rolls back, never to a blank body. Only a
//! vault's own packs regen: a hub pack's hooks change through their hub,
//! under the update rule.
//!
//! Every decision keeps its golden manifest (the case vector and both
//! bodies' fingerprints), and every decision and enactment lands one
//! regen receipt in the hook's history ([`history`]). The owner may
//! cancel a waiting decision or roll an adopted body back to the one it
//! replaced, and a hook an agent authored takes every new body through
//! that agent's own put ([`enact`]). The regenerator reads the contract as
//! text ([`contract`]), and the engine's own pass runs due regens after a
//! contract change ([`pass`]).

mod contract;
mod enact;
mod history;
mod pass;

pub use contract::{HookContractText, MAX_HOOK_CONTRACT_DECLARATIONS};
pub(crate) use enact::HookPut;
pub use enact::HookRegenCancel;
pub(crate) use history::hooks_regen_receipt_accepts_masked;
pub use history::{
    HookRegenActor, HookRegenDecision, HookRegenEvent, HookRegenReceipt, MAX_HOOK_REGEN_HISTORY,
};
pub use pass::HookRegenPassReport;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{
    HookSelector, PackHookBinding, PackInstallDisposition, PackSource,
};
use crate::{EntityId, Error, Result, Vault, WriteActor};

use super::body::HookBodyRuntime;
use super::replay::{self, HookReplayEntry, HookReplayResult};

/// One record per binding: the contract its last good body passed under.
const REGEN: SideTable<EntityId, HookRegenRecord, Named> = SideTable::new(&side_table::HOOKS_REGEN);
/// Whether a masked copy of a `HOOKS_REGEN` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn hooks_regen_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<HookRegenRecord, Named>(bytes)
}

/// The newest saved runs one regen replays as its golden set.
const GOLDEN_ENTRIES: usize = 256;
/// The `hub_ref` a vault's own pack records (`vault.packs.put`).
const OWN_PACK_REF: &str = "vault.packs.put";

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

/// The call purpose a served regenerator meters its model calls under.
pub const HOOK_REGEN_CALL_PURPOSE_NAME: &str = "coach_hook_regen";

/// One regen's ask: the hook, the live contract it targets, and the intent
/// read from the hook's own pack, never a cached prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegenRequest {
    pub binding: EntityId,
    pub pack: String,
    pub hook: String,
    pub selector: HookSelector,
    pub intent: String,
    pub target: HookContractStamp,
    /// The contract `target` hashes, as text: the hook world and the
    /// declarations of the verbs the selector names (FIX 4688).
    pub contract: HookContractText,
    /// The last good body, for the regenerator to read.
    pub last_good: String,
}

/// The injected seam that runs a hook's intent again. No model client,
/// router or worker enters this module.
pub trait HookRegenerator {
    /// Writes a body for `request.intent` against `request.target`. Every
    /// failure is a typed phase; a blank body is never an answer.
    fn regenerate(
        &self,
        request: &HookRegenRequest,
    ) -> std::result::Result<String, HookRegenFailure>;
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
fn body_hash(body: &str) -> String {
    blake3::hash(body.as_bytes()).to_hex().to_string()
}

/// `source`'s files with `hook`'s `body.js` set to `body`, and the body it
/// held there.
fn files_with_hook_body(
    source: &PackSource,
    hook: &str,
    body: &[u8],
) -> (Vec<HubFile>, Option<Vec<u8>>) {
    let body_path = format!("hooks/{hook}/body.js");
    let mut replaced = None;
    let files = source
        .files()
        .iter()
        .map(|file| {
            if file.path == body_path {
                replaced = Some(file.content.clone());
                HubFile::new(file.path.clone(), body.to_vec())
            } else {
                file.clone()
            }
        })
        .collect();
    (files, replaced)
}

/// The CALL behind the candidate-hash fence (DOOR-077): the candidate a
/// pending regen enacts, and the contract it targets, only when the
/// decision waiting on `record` is the one `candidate_hash` names. An
/// adoption never enacts a candidate its caller did not read, so a regen
/// that replaced the decision since is refused, never adopted under a stamp
/// given for the older one. An AutoAdopt needs no question; a
/// NeedsHumanStamp enacts only with `stamped`, the owner's stamp.
fn pending_candidate(
    record: Option<&HookRegenRecord>,
    candidate_hash: &str,
    stamped: bool,
) -> Result<(String, HookContractStamp)> {
    let (candidate, target, asks) = match record.and_then(|record| record.pending.as_ref()) {
        Some(HookRegenOutcome::AutoAdopt {
            candidate, target, ..
        }) => (candidate, target, false),
        Some(HookRegenOutcome::NeedsHumanStamp {
            candidate, target, ..
        }) => (candidate, target, true),
        Some(HookRegenOutcome::RolledBack { .. }) | None => {
            return Err(Error::InvalidConfig("no regen is pending".to_owned()));
        }
    };
    if body_hash(candidate) != candidate_hash {
        return Err(Error::InvalidConfig(
            "the pending regen is not the candidate named: read the record again".to_owned(),
        ));
    }
    if asks && !stamped {
        return Err(Error::InvalidConfig(
            "this regen changes what the hook does: it needs the owner's stamp".to_owned(),
        ));
    }
    Ok((candidate.clone(), target.clone()))
}

/// A binding's body passed under this engine's contract when it was bound.
pub(crate) fn note_bound_hook_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: EntityId,
    body_hash: &str,
    intent: Option<&str>,
) -> Result<()> {
    if REGEN
        .get(&vault.store, txn, &binding)?
        .is_some_and(|record| record.body_hash == body_hash)
    {
        return Ok(());
    }
    REGEN.put(
        vault,
        txn,
        &binding,
        &HookRegenRecord {
            body_hash: body_hash.to_owned(),
            stamp: HookContractStamp::current(),
            intent: intent.map(str::to_owned),
            pending: None,
            previous: None,
            declined: None,
        },
    )
}

impl Vault {
    /// Each binding of a vault's own pack whose last good body passed under
    /// another contract than this engine's, and has no regen waiting. A hook
    /// whose owner declined a regen under this contract is not due.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn hooks_due_for_regen(&self) -> Result<Vec<EntityId>> {
        let current = HookContractStamp::current();
        let mut due = Vec::new();
        for (id, binding) in self.pack_hook_bindings()? {
            if !binding.enabled || !self.own_pack(&binding.pack)? {
                continue;
            }
            if self.hook_regen_record(id)?.is_some_and(|record| {
                record.stamp != current
                    && record.declined.as_ref() != Some(&current)
                    && !matches!(
                        &record.pending,
                        Some(
                            HookRegenOutcome::AutoAdopt { target, .. }
                                | HookRegenOutcome::NeedsHumanStamp { target, .. }
                        ) if *target == current
                    )
            }) {
                due.push(id);
            }
        }
        Ok(due)
    }

    /// The regen record of `binding`, if it was bound under a record.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn hook_regen_record(&self, binding: EntityId) -> Result<Option<HookRegenRecord>> {
        let rtxn = self.store.env.read_txn()?;
        REGEN.get(&self.store, &rtxn, &binding)
    }

    /// Runs `binding`'s intent again against this engine's contract and
    /// decides (ARCH-0080 §8): the golden set replays under the last good
    /// body and the candidate. The decision lands on the hook's record and
    /// enacts nothing; [`Self::adopt_hook_regen`] enacts it.
    ///
    /// # Errors
    ///
    /// Storage errors, and a binding that is not a vault's own pack's.
    pub fn regenerate_hook(
        &self,
        runtime: &dyn HookBodyRuntime,
        regenerator: &dyn HookRegenerator,
        binding: EntityId,
    ) -> Result<HookRegenOutcome> {
        self.regenerate_hook_as(runtime, regenerator, binding, &HookRegenActor::Engine)
    }

    /// [`Self::regenerate_hook`], with the regen receipt naming `actor` as
    /// the one who ran it: the owner's or an agent's own run, or the
    /// engine's pass after a contract change.
    ///
    /// # Errors
    ///
    /// As [`Self::regenerate_hook`].
    pub fn regenerate_hook_as(
        &self,
        runtime: &dyn HookBodyRuntime,
        regenerator: &dyn HookRegenerator,
        binding: EntityId,
        actor: &HookRegenActor,
    ) -> Result<HookRegenOutcome> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        if !self.own_pack(&row.pack)? {
            return Err(Error::InvalidConfig(
                "a hub pack's hooks change through their hub, not regen".to_owned(),
            ));
        }
        let mut record = self.hook_regen_record(binding)?.unwrap_or(HookRegenRecord {
            body_hash: row.body_hash.clone(),
            stamp: HookContractStamp::current(),
            intent: None,
            pending: None,
            previous: None,
            declined: None,
        });
        let intent = match self.get_pack_source(&row.source)? {
            Some(source) => source
                .hooks()
                .iter()
                .find(|hook| hook.name == row.hook)
                .and_then(|hook| hook.intent.clone()),
            None => None,
        }
        .or_else(|| record.intent.clone());
        let outcome =
            self.decide_hook_regen(runtime, regenerator, binding, &row, intent.clone())?;
        record.intent = intent;
        record.pending = Some(outcome.clone());
        let event = HookRegenEvent::decided(&outcome);
        self.with_write_txn_grouped(|txn| {
            REGEN.put(self, txn, &binding, &record)?;
            history::append_in_txn(self, txn, binding, &row, &record.body_hash, actor, event)
        })?;
        Ok(outcome)
    }

    fn decide_hook_regen(
        &self,
        runtime: &dyn HookBodyRuntime,
        regenerator: &dyn HookRegenerator,
        binding: EntityId,
        row: &PackHookBinding,
        intent: Option<String>,
    ) -> Result<HookRegenOutcome> {
        let target = HookContractStamp::current();
        let rolled_back = |phase, message: &str| HookRegenOutcome::RolledBack {
            failure: HookRegenFailure::new(phase, message),
            target: target.clone(),
        };
        let Some(intent) = intent.filter(|intent| !intent.trim().is_empty()) else {
            return Ok(rolled_back(
                HookRegenFailurePhase::Intent,
                "the hook kept no intent to run again",
            ));
        };
        let last_good = match String::from_utf8(self.pack_hook_body(row)?) {
            Ok(body) => body,
            Err(_) => {
                return Ok(rolled_back(
                    HookRegenFailurePhase::Validate,
                    "the last good body is not text",
                ));
            }
        };
        let request = HookRegenRequest {
            binding,
            pack: row.pack.clone(),
            hook: row.hook.clone(),
            selector: row.selector.clone(),
            intent,
            target: target.clone(),
            contract: HookContractText::for_selector(&row.selector),
            last_good,
        };
        let candidate = match regenerator.regenerate(&request) {
            Ok(candidate) if candidate.trim().is_empty() => {
                return Ok(rolled_back(
                    HookRegenFailurePhase::Validate,
                    "the regenerated body is blank",
                ));
            }
            Ok(candidate) => candidate,
            Err(failure) => {
                return Ok(HookRegenOutcome::RolledBack {
                    failure,
                    target: target.clone(),
                });
            }
        };
        // One case vector, the hook's newest saved runs, for both bodies.
        let golden = replay::saved_runs(self, binding, GOLDEN_ENTRIES).and_then(|runs| {
            let pass = |body: &str| {
                self.hooks_replay_runs(runtime, binding, row, body, &runs)
                    .map(|entries| {
                        let keys: Vec<String> =
                            entries.iter().map(|(run, _)| run.clone()).collect();
                        (keys, HookGoldenFingerprint::of(&entries))
                    })
            };
            let (keys, last_good) = pass(request.last_good.as_str())?;
            let (_, next) = pass(candidate.as_str())?;
            Ok(HookGoldenManifest {
                runs: keys,
                last_good,
                candidate: next,
            })
        });
        let golden = match golden {
            Ok(golden) => golden,
            Err(error) => {
                return Ok(rolled_back(
                    HookRegenFailurePhase::GoldenReplay,
                    &error.to_string(),
                ));
            }
        };
        let diff = HookGoldenDiff::between(&golden.last_good, &golden.candidate);
        Ok(if diff.identical() {
            HookRegenOutcome::AutoAdopt {
                candidate,
                target,
                diff,
                golden,
            }
        } else {
            HookRegenOutcome::NeedsHumanStamp {
                candidate,
                target,
                diff,
                golden,
            }
        })
    }

    /// Enacts `binding`'s pending regen as the owner: the candidate replaces
    /// the hook's body in its pack, through the owner's own put, or, for a
    /// hook an agent authored, through that agent's own put of the `local`
    /// pack, so the hook stays the agent's, at its ceiling, its grant carried
    /// (FIX 4692). `candidate_hash` names the candidate its caller read
    /// ([`HookRegenRecord::candidate_hash`]); only that pending candidate
    /// enacts. An AutoAdopt needs no question; a NeedsHumanStamp adopts only
    /// with `stamped`, the owner's stamp. Only a put that installs the
    /// candidate advances the record, to the new body under the target
    /// contract. A Candidate or Blocked put leaves the last good body and the
    /// pending decision as they were, and is answered as it is.
    ///
    /// # Errors
    ///
    /// No regen is pending, it is not the candidate named, or it needs a
    /// stamp it lacks; and the put's own refusals.
    pub fn adopt_hook_regen(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        candidate_hash: &str,
        stamped: bool,
    ) -> Result<PackInstallDisposition> {
        let actor = owner.revalidate(self)?;
        self.enact_hook_regen(
            HookPut::Owner(owner),
            &HookRegenActor::Owner { actor },
            binding,
            candidate_hash,
            stamped,
        )
    }

    /// Enacts the regen pending on a hook `agent` authored, as that agent,
    /// through its own put of the `local` pack (FIX 4692): the hook stays the
    /// agent's, at its ceiling, its grant carried. An agent carries no
    /// owner's stamp, so only an AutoAdopt enacts; a candidate whose golden
    /// replay differs waits for the owner.
    ///
    /// # Errors
    ///
    /// A hook the agent did not author, no AutoAdopt pending or not the one
    /// named, and the put's own refusals.
    pub fn adopt_hook_regen_as_agent(
        &self,
        agent: &WriteActor,
        binding: EntityId,
        candidate_hash: &str,
    ) -> Result<PackInstallDisposition> {
        self.enact_hook_regen(
            HookPut::Agent {
                agent: *agent,
                owner: None,
            },
            &HookRegenActor::Agent {
                agent: agent.entity_ref(),
            },
            binding,
            candidate_hash,
            false,
        )
    }

    /// Whether `pack` is installed as a vault's own pack.
    fn own_pack(&self, pack: &str) -> Result<bool> {
        Ok(self
            .installed_pack(pack)?
            .is_some_and(|receipt| receipt.hub_ref == OWN_PACK_REF))
    }
}
