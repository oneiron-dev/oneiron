//! Hook regen (ARCH-0080 §8, slice 3): the shape of lens regen (OF-321),
//! with records typed for hooks. A hook keeps the intent its body came from.
//! When the verb table or the sandbox contract changes under it, the intent
//! runs again through an injected [`HookRegenerator`], and the hook's newest
//! saved runs, loaded once, replay as its golden set under the last good body
//! and under the candidate. Only a complete, identical fingerprint adopts; a
//! diff, or a run either body could not replay on its record, waits for the
//! owner's stamp; a failure rolls back, never to a blank body. Only a
//! vault's own packs regen: a hub pack's hooks change through their hub,
//! under the update rule.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{HookSelector, PackInstallDisposition};
use crate::{EntityId, Error, Result, Vault};

use super::body::HookBodyRuntime;
use super::replay::{self, HookReplayCompare, HookReplayEntry, HookReplayResult};

/// One record per binding: the contract its last good body passed under.
const REGEN: SideTable<EntityId, HookRegenRecord, Named> = SideTable::new(&side_table::HOOKS_REGEN);
/// The newest saved runs one regen replays as its golden set.
const GOLDEN_ENTRIES: usize = 256;
/// The `hub_ref` a vault's own pack records (`vault.packs.put`).
const OWN_PACK_REF: &str = "vault.packs.put";

/// What a hook body is written against: the verb table it calls and the
/// sandbox world it runs in. A change to either runs the intent again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            verb_table: blake3::hash(include_bytes!("../task_verb/code-mode.d.ts"))
                .to_hex()
                .to_string(),
            sandbox: blake3::hash(include_bytes!("../../wit/hook/hook.wit"))
                .to_hex()
                .to_string(),
        }
    }
}

/// Where a regen stopped. Every phase keeps the last good body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// What one body returned on each golden run, by run key: the outcome token
/// and its JSON. A run whose replay did not give back what it recorded (its
/// history gone, a failed body, another outcome) is incomplete instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookGoldenFingerprint {
    pub cases: BTreeMap<String, String>,
    pub incomplete: BTreeSet<String>,
}

impl HookGoldenFingerprint {
    /// One body's pass over the golden runs.
    fn of(entries: &[(String, HookReplayEntry)]) -> Self {
        let mut fingerprint = Self::default();
        for (run, entry) in entries {
            match &entry.result {
                HookReplayResult::Ran {
                    compare: HookReplayCompare::Same,
                    outcome,
                    outcome_json,
                    ..
                } => {
                    fingerprint.cases.insert(
                        run.clone(),
                        format!("{outcome}:{}", outcome_json.as_deref().unwrap_or("")),
                    );
                }
                _ => {
                    fingerprint.incomplete.insert(run.clone());
                }
            }
        }
        fingerprint
    }
}

/// Where a candidate's golden replay parts from the last good body's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookGoldenDiff {
    /// The golden runs compared.
    pub cases: usize,
    /// The run keys whose outcome changed, or that either body could not
    /// replay on its record.
    pub changed: Vec<String>,
}

impl HookGoldenDiff {
    fn between(last_good: &HookGoldenFingerprint, candidate: &HookGoldenFingerprint) -> Self {
        let runs: BTreeSet<&String> = last_good
            .cases
            .keys()
            .chain(&last_good.incomplete)
            .chain(candidate.cases.keys())
            .chain(&candidate.incomplete)
            .collect();
        let cases = runs.len();
        let changed = runs
            .into_iter()
            .filter(|run| {
                last_good.incomplete.contains(*run)
                    || candidate.incomplete.contains(*run)
                    || last_good.cases.get(*run) != candidate.cases.get(*run)
            })
            .cloned()
            .collect();
        Self { cases, changed }
    }

    /// An empty golden set proves nothing, so it never adopts by itself.
    #[must_use]
    pub fn identical(&self) -> bool {
        self.cases > 0 && self.changed.is_empty()
    }
}

/// A regen's decision, kept on the hook's record until it is enacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HookRegenOutcome {
    /// An identical fingerprint: the candidate adopts without a question.
    AutoAdopt {
        candidate: String,
        target: HookContractStamp,
        diff: HookGoldenDiff,
    },
    /// The golden replay differs, is incomplete, or there is none: the owner
    /// stamps it.
    NeedsHumanStamp {
        candidate: String,
        target: HookContractStamp,
        diff: HookGoldenDiff,
    },
    /// The last good body stands.
    RolledBack { failure: HookRegenFailure },
}

/// One hook's regen record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRegenRecord {
    /// The last good body, as BLAKE3 hex.
    pub body_hash: String,
    /// The contract that body last passed under.
    pub stamp: HookContractStamp,
    /// The intent it came from, when the author kept one.
    pub intent: Option<String>,
    /// The last regen's decision, until it is enacted.
    pub pending: Option<HookRegenOutcome>,
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
        },
    )
}

impl Vault {
    /// Each binding of a vault's own pack whose last good body passed under
    /// another contract than this engine's, and has no regen waiting.
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
        self.with_write_txn_grouped(|txn| REGEN.put(self, txn, &binding, &record))?;
        Ok(outcome)
    }

    fn decide_hook_regen(
        &self,
        runtime: &dyn HookBodyRuntime,
        regenerator: &dyn HookRegenerator,
        binding: EntityId,
        row: &crate::skill_hub::pack_catalog::PackHookBinding,
        intent: Option<String>,
    ) -> Result<HookRegenOutcome> {
        let rolled_back = |phase, message: &str| HookRegenOutcome::RolledBack {
            failure: HookRegenFailure::new(phase, message),
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
        let target = HookContractStamp::current();
        let request = HookRegenRequest {
            binding,
            pack: row.pack.clone(),
            hook: row.hook.clone(),
            selector: row.selector.clone(),
            intent,
            target: target.clone(),
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
            Err(failure) => return Ok(HookRegenOutcome::RolledBack { failure }),
        };
        // One case vector, the hook's newest saved runs, for both bodies.
        let golden = replay::saved_runs(self, binding, GOLDEN_ENTRIES).and_then(|runs| {
            let pass = |body: &str| {
                self.hooks_replay_runs(runtime, binding, row, body, &runs)
                    .map(|entries| HookGoldenFingerprint::of(&entries))
            };
            Ok((pass(request.last_good.as_str())?, pass(candidate.as_str())?))
        });
        let (old, new) = match golden {
            Ok(golden) => golden,
            Err(error) => {
                return Ok(rolled_back(
                    HookRegenFailurePhase::GoldenReplay,
                    &error.to_string(),
                ));
            }
        };
        let diff = HookGoldenDiff::between(&old, &new);
        Ok(if diff.identical() {
            HookRegenOutcome::AutoAdopt {
                candidate,
                target,
                diff,
            }
        } else {
            HookRegenOutcome::NeedsHumanStamp {
                candidate,
                target,
                diff,
            }
        })
    }

    /// Enacts `binding`'s pending regen: the candidate replaces the hook's
    /// body in its pack, through the owner's own put. An AutoAdopt needs no
    /// question; a NeedsHumanStamp adopts only with `stamped`, the owner's
    /// stamp. The record then names the new body under the target contract.
    ///
    /// # Errors
    ///
    /// No regen is pending, or it needs a stamp it lacks; and the put's own
    /// refusals.
    pub fn adopt_hook_regen(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        stamped: bool,
    ) -> Result<PackInstallDisposition> {
        let (_, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        let mut record = self
            .hook_regen_record(binding)?
            .ok_or_else(|| Error::InvalidConfig("no regen is pending".to_owned()))?;
        let (candidate, target) = match &record.pending {
            Some(HookRegenOutcome::AutoAdopt {
                candidate, target, ..
            }) => (candidate.clone(), target.clone()),
            Some(HookRegenOutcome::NeedsHumanStamp {
                candidate, target, ..
            }) if stamped => (candidate.clone(), target.clone()),
            Some(HookRegenOutcome::NeedsHumanStamp { .. }) => {
                return Err(Error::InvalidConfig(
                    "this regen changes what the hook does: it needs the owner's stamp".to_owned(),
                ));
            }
            _ => return Err(Error::InvalidConfig("no regen is pending".to_owned())),
        };
        let source = self
            .get_pack_source(&row.source)?
            .ok_or(Error::EntityNotFound)?;
        let body_path = format!("hooks/{}/body.js", row.hook);
        let files = source
            .files()
            .iter()
            .map(|file| {
                if file.path == body_path {
                    HubFile::new(file.path.clone(), candidate.as_bytes().to_vec())
                } else {
                    file.clone()
                }
            })
            .collect();
        let disposition = self.put_pack(owner, files)?;
        let body_hash = blake3::hash(candidate.as_bytes()).to_hex().to_string();
        // The new body binds under a new id; the old binding stops.
        let rebound = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(_, bound)| {
                bound.pack == row.pack && bound.hook == row.hook && bound.body_hash == body_hash
            })
            .map(|(id, _)| id);
        record.body_hash = body_hash;
        record.stamp = target;
        record.pending = None;
        self.with_write_txn_grouped(|txn| {
            for id in std::iter::once(binding).chain(rebound) {
                REGEN.put(self, txn, &id, &record)?;
            }
            Ok(())
        })?;
        Ok(disposition)
    }

    /// Whether `pack` is installed as a vault's own pack.
    fn own_pack(&self, pack: &str) -> Result<bool> {
        Ok(self
            .installed_pack(pack)?
            .is_some_and(|receipt| receipt.hub_ref == OWN_PACK_REF))
    }
}
