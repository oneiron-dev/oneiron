//! A linked repair becomes a sealed eval seed (census L1-20; ARCH-0053
//! `#eval-repair-seed`, owner 2026-10-15; ruling L1-20-SEEDER = A).
//!
//! "The case's source family gets its split before anything is derived from
//! it": proposing a seed compiles the capture's task and assigns its family
//! root to a sealed-confirmation family in the same write, before any case
//! exists. "The old skill must fail the case and the candidate must pass it":
//! the gate grades both arms' answers itself, against the app's observed
//! outcome ("never the candidate skill's own text"), and only then records one
//! `Repair` case and its `WorldOutcome` label. A refused seed records no case,
//! so nothing is ever derived from it.
//!
//! "The app's observed outcome, or an adjudicated label, is the check": when
//! the outcome is no usable answer, the task's contract names the
//! adjudicated-response grader. Its seed awaits an adjudicated audit label
//! ([`Memory::label_eval_repair_seed`]), held only as the BLAKE3 of the
//! answer, and the gate grades against that and records an `AdjudicatedAudit`
//! label in place of the `WorldOutcome` one.
//!
//! The skill decides which repair to seed; fixed code compiles, seals and
//! grades. Nothing here runs a model: the measuring host answers each arm and
//! hands the answers to [`Memory::settle_eval_repair_seed`], as it hands leg
//! results to the measurement doors. No verb reaches these doors.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    DerivationKind, EvalArmPin, EvalCaseDraft, EvalLabel, EvalLabelKind, EvalRepairTask,
    EvalRepairTaskSource, EvalRepairToolCall, FamilyPurpose, MAX_LABEL_VALUE_BYTES, MAX_REF_BYTES,
    append_label_in_txn, assign_family_in_txn, bounded_ref, invalid, record_case_in_txn,
};
use crate::Vault;
use crate::claim::ScopedReadReceipt;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, Named, SideTable};

/// One seed per task source, keyed by the BLAKE3 of the source's identity.
const SEEDS: SideTable<[u8; 32], EvalRepairSeed, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_EVAL_REPAIR_SEED);
/// The seed key's domain.
const SEED_DOMAIN: &[u8] = b"skill_optimize:eval_repair_seed:v1\0";

/// What the eval-authoring skill proposes: a linked repair's task, and the
/// old and candidate skill arms the gate compares on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairSeedRequest {
    pub source: EvalRepairTaskSource,
    /// The skill the person's repair corrected; it must fail the task.
    pub old: EvalArmPin,
    /// The skill proposed in its place; it must pass the task.
    pub candidate: EvalArmPin,
}

/// Why the gate refused a seed. A refused seed has no case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairSeedRefusal {
    /// The old skill's answer already met the observed outcome.
    OldPassed,
    /// The candidate skill's answer did not meet the observed outcome.
    CandidateFailed,
    /// The capture's task no longer compiles to the task the seed was
    /// proposed with.
    TaskMoved,
}

/// Where a seed stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairSeedState {
    /// Proposed and sealed; the gate has not graded it yet.
    Pending,
    /// Proposed and sealed, with an adjudicated-response task: the gate
    /// grades nothing until its adjudicated audit label lands, which makes
    /// it `Pending`.
    AwaitingLabel,
    /// The old arm failed and the candidate passed: `case` holds it.
    Confirmed {
        case: EntityId,
        /// The receipt of the old arm's leg, as the measuring host named it.
        old_receipt: String,
        /// The receipt of the candidate arm's leg.
        candidate_receipt: String,
        at: u64,
    },
    Refused {
        reason: EvalRepairSeedRefusal,
        at: u64,
    },
}

/// The adjudicated audit label an adjudicated-response seed is graded
/// against. The answer is held only as the BLAKE3 of its bytes, never as text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairAdjudication {
    /// BLAKE3 of the adjudicated answer's bytes.
    pub answer_digest: [u8; 32],
    /// The audit the label came from.
    pub reference: String,
    pub weight: f64,
    /// When the label was given.
    pub at: u64,
}

/// A sealed eval seed from one linked repair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairSeed {
    pub source: EvalRepairTaskSource,
    /// The sealed-confirmation family the capture's root was assigned to
    /// when the seed was proposed.
    pub family: EntityId,
    /// The compiled task's hash when the seed was proposed.
    pub task_hash: [u8; 32],
    pub old: EvalArmPin,
    pub candidate: EvalArmPin,
    /// The rows the task was compiled from: the capture claim.
    pub source_rows: Vec<EntityId>,
    /// When the seed was proposed; its case's `source_at`.
    pub proposed_at: u64,
    /// An adjudicated-response task's label, once it lands; set once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjudication: Option<EvalRepairAdjudication>,
    pub state: EvalRepairSeedState,
}

/// A seed door's answer. `seed` is `None` when the scoped reader withholds
/// the capture; `receipt` is that read's receipt.
#[derive(Debug, Clone)]
pub struct EvalRepairSeedRead {
    pub seed: Option<EvalRepairSeed>,
    pub receipt: ScopedReadReceipt,
}

/// One arm's answer to the task, as the measuring host received it: a text
/// response for a text-response world, tool calls for a JSON-state-tools
/// world. An answer of the other kind fails the task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairLegAnswer {
    Response(String),
    ToolCalls(Vec<EvalRepairToolCall>),
}

/// The receipts of the two legs whose answers the gate grades.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairSeedLegs {
    pub old_receipt: String,
    pub candidate_receipt: String,
}

fn seed_key(source: &EvalRepairTaskSource) -> Result<[u8; 32]> {
    let seat = source.seat.token()?;
    let ordinal = source.outcome_ordinal.to_string();
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEED_DOMAIN);
    for part in [
        seat.as_str(),
        source.claim_ref.as_str(),
        source.source_hash.as_str(),
        ordinal.as_str(),
        source.task_pointer.as_str(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn bounded_arm(arm: &EvalArmPin) -> Result<()> {
    bounded_ref(&arm.model)?;
    bounded_ref(&arm.revision)?;
    match &arm.skill_digest {
        Some(digest) if !digest.trim().is_empty() && digest.len() <= MAX_REF_BYTES => Ok(()),
        _ => Err(invalid("a repair seed's arm pins a bounded skill digest")),
    }
}

fn grade(task: &EvalRepairTask, answer: &EvalRepairLegAnswer) -> bool {
    match answer {
        EvalRepairLegAnswer::Response(text) => task.grade_response(text),
        EvalRepairLegAnswer::ToolCalls(calls) => task.grade_tool_calls(calls),
    }
}

impl Memory<'_> {
    /// Propose a sealed eval seed from a linked repair: compile its task
    /// (refusals as [`Self::read_eval_repair_task`]: a contract that does not
    /// fit its world, a failing precondition, a leaked answer), then, in one
    /// write, assign the capture's family root to a sealed-confirmation
    /// family and record the seed `Pending`. A capture the scoped reader
    /// withholds returns no seed and the read receipt. A replay over the same
    /// source returns the seed already proposed, unchanged.
    ///
    /// # Errors
    ///
    /// An arm that pins no bounded skill digest, two equal arms, a task the
    /// capture does not compile to, a root that already belongs to a family
    /// of another purpose, or storage errors.
    pub fn propose_eval_repair_seed(
        &self,
        request: &EvalRepairSeedRequest,
        at: u64,
    ) -> MemoryResult<EvalRepairSeedRead> {
        bounded_arm(&request.old)?;
        bounded_arm(&request.candidate)?;
        if request.old == request.candidate {
            return Err(invalid("a repair seed compares two different arms").into());
        }
        let read = self.read_eval_repair_task(&request.source)?;
        let Some(task) = read.task else {
            return Ok(EvalRepairSeedRead {
                seed: None,
                receipt: read.receipt,
            });
        };
        let vault = self.vault();
        let seed = vault.with_write_txn_grouped(|txn| {
            let key = seed_key(&task.source)?;
            if let Some(existing) = SEEDS.get(&vault.store, txn, &key)? {
                return Ok(existing);
            }
            // The split comes first: no case can derive from the root until
            // it has its sealed family.
            let family = assign_family_in_txn(
                vault,
                txn,
                &task.source.seat,
                &BTreeSet::from([task.family_root()]),
                FamilyPurpose::SealedConfirmation,
                at,
            )?;
            let seed = EvalRepairSeed {
                source: task.source.clone(),
                family: family.id,
                task_hash: task.task_hash,
                old: request.old.clone(),
                candidate: request.candidate.clone(),
                source_rows: task.source_rows.clone(),
                proposed_at: at,
                adjudication: None,
                state: if task.awaits_adjudication() {
                    EvalRepairSeedState::AwaitingLabel
                } else {
                    EvalRepairSeedState::Pending
                },
            };
            SEEDS.put(&vault.store, txn, &key, &seed)?;
            Ok(seed)
        })?;
        Ok(EvalRepairSeedRead {
            seed: Some(seed),
            receipt: read.receipt,
        })
    }

    /// The gate for a pending seed: recompile its task from the capture,
    /// grade both arms' answers by the task's own grader, and settle the
    /// seed. The old answer must fail and the candidate's must pass; then one
    /// `Repair` case is recorded in the seed's sealed family, reading the
    /// capture's root, with a `WorldOutcome` label whose value is the
    /// observed outcome's BLAKE3 hex (the answer stays out of the case), or,
    /// for an adjudicated-response task, an `AdjudicatedAudit` label whose
    /// value is the adjudicated answer's BLAKE3 hex, and the seed is
    /// `Confirmed`. Otherwise it is `Refused` with its reason and no case is
    /// recorded. A task that no longer compiles to the seed's hash refuses as
    /// `TaskMoved`. A seed already settled is returned as it stands. The
    /// caller is the measuring host, trusted to name the legs that produced
    /// the answers, as the measurement doors trust it.
    ///
    /// # Errors
    ///
    /// A seed that awaits its adjudicated label (it stays as it is), no seed
    /// for `source`, unbounded or equal leg receipts, a capture that
    /// no longer compiles, or storage errors.
    pub fn settle_eval_repair_seed(
        &self,
        source: &EvalRepairTaskSource,
        old: &EvalRepairLegAnswer,
        candidate: &EvalRepairLegAnswer,
        legs: &EvalRepairSeedLegs,
        at: u64,
    ) -> MemoryResult<EvalRepairSeedRead> {
        bounded_ref(&legs.old_receipt)?;
        bounded_ref(&legs.candidate_receipt)?;
        if legs.old_receipt == legs.candidate_receipt {
            return Err(invalid("a repair seed's two legs have their own receipts").into());
        }
        let vault = self.vault();
        let key = seed_key(source)?;
        let stored = vault
            .eval_repair_seed(source)?
            .ok_or(invalid("no repair seed was proposed for this source"))?;
        let read = self.read_eval_repair_task(&stored.source)?;
        let Some(mut task) = read.task else {
            return Ok(EvalRepairSeedRead {
                seed: None,
                receipt: read.receipt,
            });
        };
        if let Some(adjudication) = &stored.adjudication {
            task.adjudicate(adjudication.answer_digest);
        }
        // Until its label lands an adjudicated seed is not graded; a task
        // that moved meanwhile is still refused, so the seed never waits on.
        if task.task_hash == stored.task_hash && task.awaits_adjudication() {
            return Err(invalid("an adjudicated repair seed waits for its label").into());
        }
        let verdict = if task.task_hash != stored.task_hash {
            Err(EvalRepairSeedRefusal::TaskMoved)
        } else if grade(&task, old) {
            Err(EvalRepairSeedRefusal::OldPassed)
        } else if !grade(&task, candidate) {
            Err(EvalRepairSeedRefusal::CandidateFailed)
        } else {
            Ok(())
        };
        let seed = vault.with_write_txn_grouped(|txn| {
            let Some(mut seed) = SEEDS.get(&vault.store, txn, &key)? else {
                return Err(invalid("no repair seed was proposed for this source"));
            };
            if !matches!(
                seed.state,
                EvalRepairSeedState::Pending | EvalRepairSeedState::AwaitingLabel
            ) {
                return Ok(seed);
            }
            seed.state = match verdict {
                Err(reason) => EvalRepairSeedState::Refused { reason, at },
                Ok(()) => {
                    let root = task.family_root();
                    let draft = EvalCaseDraft {
                        seat: seed.source.seat.clone(),
                        kind: DerivationKind::Repair,
                        receipts: vec![root],
                        parents: Vec::new(),
                        stratum: None,
                        draw_probability: None,
                        source_at: seed.proposed_at,
                    };
                    let case = record_case_in_txn(
                        vault,
                        txn,
                        &draft,
                        Some(task.source_rows.as_slice()),
                        at,
                    )?;
                    let value = task
                        .outcome_digest()
                        .ok_or(invalid("an adjudicated repair seed waits for its label"))?;
                    // The check the gate graded against: the app's observed
                    // outcome, or the adjudicated audit.
                    let label = match &stored.adjudication {
                        Some(adjudication) => EvalLabel {
                            kind: EvalLabelKind::AdjudicatedAudit,
                            value,
                            reference: adjudication.reference.clone(),
                            weight: adjudication.weight,
                            at: adjudication.at,
                            source_rows: Some(task.source_rows.clone()),
                        },
                        None => EvalLabel {
                            kind: EvalLabelKind::WorldOutcome,
                            value,
                            reference: format!(
                                "ag_ui:{}:{}#outcome/{}",
                                task.source.claim_ref,
                                task.source.source_hash,
                                task.source.outcome_ordinal
                            ),
                            weight: 1.0,
                            at,
                            source_rows: Some(task.source_rows.clone()),
                        },
                    };
                    append_label_in_txn(vault, txn, &case.id, label)?;
                    EvalRepairSeedState::Confirmed {
                        case: case.id,
                        old_receipt: legs.old_receipt.clone(),
                        candidate_receipt: legs.candidate_receipt.clone(),
                        at,
                    }
                }
            };
            SEEDS.put(&vault.store, txn, &key, &seed)?;
            Ok(seed)
        })?;
        Ok(EvalRepairSeedRead {
            seed: Some(seed),
            receipt: read.receipt,
        })
    }

    /// Land the adjudicated audit label an adjudicated-response seed awaits,
    /// which makes it `Pending` for the gate. The label's value is the
    /// adjudicated answer: bounded (at most 512 bytes; a longer one is
    /// refused, never cut), checked against the task's workspace and history
    /// as a compiled answer is, and held only as the BLAKE3 of its bytes. An
    /// owner's pick arrives through its ask and a judge's verdict is never a
    /// check, so only an adjudicated audit is taken. The label is set once:
    /// the same answer and reference again return the seed unchanged.
    ///
    /// # Errors
    ///
    /// A label of another kind, an unbounded value or reference, a weight
    /// outside 0..=1, no seed for `source`, a task that is not an adjudicated
    /// response or that moved since the seed was proposed, a leaked answer,
    /// another label already set, a seed that does not await a label, or
    /// storage errors.
    pub fn label_eval_repair_seed(
        &self,
        source: &EvalRepairTaskSource,
        label: &EvalLabel,
    ) -> MemoryResult<EvalRepairSeedRead> {
        match label.kind {
            EvalLabelKind::AdjudicatedAudit => {}
            EvalLabelKind::OwnerPick => {
                return Err(invalid("an owner's pick is recorded through its ask").into());
            }
            EvalLabelKind::WorldOutcome | EvalLabelKind::JudgeVerdict => {
                return Err(invalid("a repair seed takes only an adjudicated audit label").into());
            }
        }
        if label.value.trim().is_empty()
            || label.value.len() > MAX_LABEL_VALUE_BYTES
            || !label.weight.is_finite()
            || !(0.0..=1.0).contains(&label.weight)
        {
            return Err(invalid("an eval label needs a bounded value and a 0..=1 weight").into());
        }
        bounded_ref(&label.reference)?;
        let vault = self.vault();
        let key = seed_key(source)?;
        let stored = vault
            .eval_repair_seed(source)?
            .ok_or(invalid("no repair seed was proposed for this source"))?;
        let read = self.read_eval_repair_task(&stored.source)?;
        let Some(task) = read.task else {
            return Ok(EvalRepairSeedRead {
                seed: None,
                receipt: read.receipt,
            });
        };
        if task.task_hash != stored.task_hash {
            return Err(invalid("the capture's task moved since its seed was proposed").into());
        }
        let adjudication = EvalRepairAdjudication {
            answer_digest: task.adjudicated_answer_digest(&label.value)?,
            reference: label.reference.clone(),
            weight: label.weight,
            at: label.at,
        };
        let seed = vault.with_write_txn_grouped(|txn| {
            let Some(mut seed) = SEEDS.get(&vault.store, txn, &key)? else {
                return Err(invalid("no repair seed was proposed for this source"));
            };
            let replay = seed.adjudication.as_ref().map(|existing| {
                existing.answer_digest == adjudication.answer_digest
                    && existing.reference == adjudication.reference
            });
            match replay {
                Some(true) => return Ok(seed),
                Some(false) => {
                    return Err(invalid("a repair seed's adjudicated label is set once"));
                }
                None if seed.state != EvalRepairSeedState::AwaitingLabel => {
                    return Err(invalid("this repair seed does not await a label"));
                }
                None => {}
            }
            seed.adjudication = Some(adjudication);
            seed.state = EvalRepairSeedState::Pending;
            SEEDS.put(&vault.store, txn, &key, &seed)?;
            Ok(seed)
        })?;
        Ok(EvalRepairSeedRead {
            seed: Some(seed),
            receipt: read.receipt,
        })
    }
}

impl Vault {
    /// The seed proposed for `source`, if one was.
    ///
    /// # Errors
    ///
    /// An invalid seat, an unreadable row, or storage errors.
    pub fn eval_repair_seed(
        &self,
        source: &EvalRepairTaskSource,
    ) -> Result<Option<EvalRepairSeed>> {
        let txn = self.store.env.read_txn()?;
        SEEDS.get(&self.store, &txn, &seed_key(source)?)
    }

    /// Every seed the gate has not graded yet, for the measuring host.
    ///
    /// # Errors
    ///
    /// An unreadable row, or storage errors.
    pub fn pending_eval_repair_seeds(&self) -> Result<Vec<EvalRepairSeed>> {
        let txn = self.store.env.read_txn()?;
        Ok(SEEDS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, seed)| seed)
            .filter(|seed| seed.state == EvalRepairSeedState::Pending)
            .collect())
    }

    /// The ledger row of eval case `id`, for the test doors: a sealed case
    /// has no read outside its cohort.
    #[cfg(oneiron_test_support)]
    pub(crate) fn eval_case_for_test_doors(
        &self,
        id: &EntityId,
    ) -> Result<Option<super::EvalCase>> {
        let txn = self.store.env.read_txn()?;
        super::case_in_txn(self, &txn, id)
    }
}

/// An erased capture takes its seeds with it: a pending seed is never
/// graded, and a settled one keeps no reference to the capture. A confirmed
/// seed's case stays, and the case erase hook drops the capture from its
/// source rows. Registered on the seed table's declaration.
///
/// # Errors
///
/// Storage errors, or a stored seed that does not decode.
pub(crate) fn erase_eval_repair_seeds_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let named: Vec<[u8; 32]> = SEEDS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, seed)| seed.source_rows.contains(id))
        .map(|(key, _)| key)
        .collect();
    for key in named {
        SEEDS.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}
