//! Experiment arms of the lane economy (design pass 32 section 3.3): one arm
//! is a promise whose contract was frozen before the work. The lane lead
//! admits it into one family of a GPU line; from that moment it holds its
//! first allowance (one rung-1 cap) in the period it was admitted, so no
//! other arm can take that room. Its rungs then run units, take the lead's
//! verdict and, for a promote, an independent review that opens the next
//! rung.
//!
//! The record is one side-table row per arm. The engine stamps every time,
//! id and hold; no caller supplies a measured number or a clock. A
//! correction is a new arm that supersedes the old one: a closed rung is
//! never rewritten.
//!
//! The doors are public verbs behind a Grant (`vault.arms.*`, proof
//! `verb_grant_caller`): the owner, or an agent whose live owner Grant lists
//! the verb and reaches the arm's line
//! ([`crate::memory::Memory::verb_grant_caller_admits_over_in_txn`]). A
//! reader sees only arms of lines its Grant reaches.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::gpu_line::{AllowanceHold, Track};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod read;
pub(crate) mod tables;
mod wire;

pub use read::{ARMS_GET_VERB, ARMS_LIST_VERB, arm_get_as, arm_list_as};
pub use wire::{ArmList, ArmListRequest, ArmRef, ArmView};

const EXPERIMENT_ARMS: SideTable<EntityId, ExperimentArm, Named> =
    SideTable::new(&side_table::EXPERIMENT_ARM);

/// The longest arm title, in bytes.
pub const ARM_TITLE_MAX_BYTES: usize = 200;
/// The most numbers one verdict carries.
pub const VERDICT_NUMBERS_MAX: usize = 32;
/// The longest verdict text, in bytes.
pub const VERDICT_TEXT_MAX_BYTES: usize = 2_000;

/// One experiment arm. Key: id16 (arm).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExperimentArm {
    pub id: EntityId,
    /// The GPU line: the lane project's id.
    pub line: EntityId,
    /// The family: a child project seated on the line.
    pub family: EntityId,
    /// The family seat's track, as it stood at admission.
    pub track: Track,
    /// The task type the arm was placed in once (the root when unsure).
    pub type_ref: TypeRef,
    /// At most [`ARM_TITLE_MAX_BYTES`].
    pub title: String,
    pub contract: ContractPin,
    pub runner: RunnerRef,
    /// The arm this one corrects, in the same family.
    pub supersedes: Option<EntityId>,
    /// The hold made at admission; `None` only on an arm admitted with no
    /// period open.
    pub first_allowance: Option<AllowanceHold>,
    /// `rungs[0]` is rung 1.
    pub rungs: Vec<ArmRung>,
    /// The lab ledger lines that mirror this arm, by handle only.
    pub ledger_rows: Vec<LedgerRowRef>,
    /// Who admitted it; `None` after their erase.
    pub admitted_by: Option<EntityId>,
    pub admitted_at_ms: u64,
    pub revision: u64,
}

/// The frozen contract an arm is judged against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContractPin {
    /// The contract file's path in the lane's tree.
    pub path: String,
    /// SHA-256 of the contract text, lower hex.
    pub sha256: String,
    /// The sealed NOTE's `sealed_at` when `note` names one, else the
    /// admission time; the engine stamps it either way.
    pub frozen_at_ms: u64,
    /// The sealed NOTE that mirrors the contract text.
    pub note: Option<EntityId>,
}

/// Who runs the arm's units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerRef {
    /// The runner's model, with its revision (e.g. `muse-spark-1.3`).
    pub model: String,
    /// The runner's actor, when it has one; `None` after its erase.
    pub actor: Option<EntityId>,
}

/// A lab ledger line, by handle: its id and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LedgerRowRef {
    pub id: String,
    pub sha256: String,
}

/// One rung of an arm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmRung {
    /// 1 is the first rung.
    pub rung: u8,
    /// How many holds the lead gave it (at most one).
    pub holds: u8,
    /// The engine-minted promotion that opened this rung; `None` on rung 1.
    pub promotion: Option<ArmPromotion>,
    pub verdict: Option<ArmVerdict>,
    pub review: Option<ArmReview>,
    /// The team receipt's `team_ref` (`arm:<arm hex>:r<rung>`) once the rung
    /// closed measurable.
    pub receipt: Option<String>,
}

impl ArmRung {
    /// A fresh rung `rung`, opened by `promotion` (none on rung 1).
    #[must_use]
    pub fn open(rung: u8, promotion: Option<ArmPromotion>) -> Self {
        Self {
            rung,
            holds: 0,
            promotion,
            verdict: None,
            review: None,
            receipt: None,
        }
    }

    /// Whether this rung closed the arm: a kill or an invalid verdict, or a
    /// review that changed a promote to either.
    #[must_use]
    pub fn closes_arm(&self) -> bool {
        let closing = |decision: &ArmDecision| {
            matches!(decision, ArmDecision::Kill | ArmDecision::Invalid { .. })
        };
        match (&self.verdict, &self.review) {
            (
                _,
                Some(ArmReview {
                    verdict: ArmReviewVerdict::Changed { to },
                    ..
                }),
            ) => closing(to),
            (Some(verdict), _) => closing(&verdict.decision),
            (None, _) => false,
        }
    }
}

/// The engine's promotion record that opens a rung after an independent
/// `confirmed` review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmPromotion {
    pub review_at_ms: u64,
    /// The reviewer; `None` after their erase.
    pub reviewer: Option<EntityId>,
}

/// The lead's verdict on a rung, against the frozen contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmVerdict {
    pub decision: ArmDecision,
    /// At most [`VERDICT_NUMBERS_MAX`] entries.
    pub numbers: BTreeMap<String, f64>,
    /// At most [`VERDICT_TEXT_MAX_BYTES`].
    pub text: String,
    pub evidence: Vec<ArmEvidenceDigest>,
    pub contract_sha256: String,
    /// Who gave it; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
}

/// A rung's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArmDecision {
    Promote,
    Hold,
    Kill,
    Invalid { reason: ArmInvalidReason },
}

/// Why a rung is invalid: never a loss, never a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArmInvalidReason {
    BoxLost,
    CouldNotMeasure,
    ContractChanged,
    TimedOut,
    Other(String),
}

/// A piece of evidence, by hash: never its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmEvidenceDigest {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub rows: Option<u64>,
}

/// An independent reviewer's verdict on a promote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmReview {
    pub verdict: ArmReviewVerdict,
    pub contract_sha256: String,
    pub evidence: Vec<ArmEvidenceDigest>,
    /// The review text (REVIEW.md), by hash.
    pub review_ref: ArmEvidenceDigest,
    /// The reviewer's model, with its revision.
    pub model: String,
    /// The reviewer; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
}

/// A review's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArmReviewVerdict {
    Confirmed,
    Changed { to: ArmDecision },
    Unresolved,
}

impl ExperimentArm {
    /// Whether the arm is still open: no rung closed it.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.rungs.iter().any(ArmRung::closes_arm)
    }

    /// The rung the arm stands at: its last opened one.
    #[must_use]
    pub fn current_rung(&self) -> u8 {
        self.rungs.last().map_or(1, |rung| rung.rung)
    }
}

impl Vault {
    /// The arm `id`, if one is stored.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn experiment_arm(&self, id: &EntityId) -> crate::Result<Option<ExperimentArm>> {
        EXPERIMENT_ARMS.get(&self.store, &self.store.env.read_txn()?, id)
    }

    pub(crate) fn experiment_arm_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> crate::Result<Option<ExperimentArm>> {
        EXPERIMENT_ARMS.get(&self.store, txn, id)
    }

    /// Every stored arm, in id order (admission order).
    pub(crate) fn experiment_arms_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Vec<ExperimentArm>> {
        Ok(EXPERIMENT_ARMS
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(_, arm)| arm)
            .collect())
    }
}

/// Takes the erased actor out of every arm (the side table's actor scrub):
/// as admitter, runner, verdict giver or reviewer, its id is forgotten and
/// the rest of the record stays. The scrub bumps the arm's revision.
pub(crate) fn erase_arm_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    let forget = |slot: &mut Option<EntityId>| {
        let named = *slot == Some(*actor);
        if named {
            *slot = None;
        }
        named
    };
    for (id, mut arm) in EXPERIMENT_ARMS.scan(&vault.store, wtxn)? {
        let mut changed = forget(&mut arm.admitted_by);
        changed |= forget(&mut arm.runner.actor);
        for rung in &mut arm.rungs {
            if let Some(promotion) = &mut rung.promotion {
                changed |= forget(&mut promotion.reviewer);
            }
            if let Some(verdict) = &mut rung.verdict {
                changed |= forget(&mut verdict.by);
            }
            if let Some(review) = &mut rung.review {
                changed |= forget(&mut review.by);
            }
        }
        if changed {
            arm.revision += 1;
            EXPERIMENT_ARMS.put(&vault.store, wtxn, &id, &arm)?;
        }
    }
    Ok(())
}
