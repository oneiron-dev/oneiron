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
//! the verb, reaches the arm's line
//! ([`crate::memory::Memory::verb_grant_caller_admits_over_in_txn`]) and
//! holds a role on it (design r2 section 5.1: the lead for the admit, the
//! forecast and the verdict, a reviewer for the review, any role for the
//! reads). A reader sees only arms of lines it holds a role on.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::claim::learning_evidence::Anchor;
use crate::gpu_line::{AllowanceHold, RuleRef, Track};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod admit;
mod forecast;
mod outcome;
mod read;
mod reserve;
mod review;
mod score;
pub(crate) mod tables;
mod unit_cancel;
mod unit_view;
mod verdict;
mod wire;

pub use admit::{ARMS_ADMIT_VERB, ArmAdmitRequest, ArmContractAsk, arm_admit_as};
pub use forecast::{ARMS_FORECAST_VERB, ArmForecastRequest, PASS_PER_MILLE_MAX, arm_forecast_as};
pub use outcome::rung_receipt_ref;
pub use read::{ARMS_GET_VERB, ARMS_LIST_VERB, arm_get_as, arm_list_as};
pub use reserve::{ARMS_UNITS_RESERVE_VERB, UnitReserveRequest, unit_reserve_as};
pub use review::{ARMS_REVIEW_VERB, ArmReviewRequest, arm_review_as};
pub use score::{
    CALIBRATION_BINS, CalibrationBin, ForecastScore, ForecastScoreRow, forecast_scores,
};
pub use unit_cancel::{
    ARMS_UNITS_CANCEL_VERB, StartedUnitCancel, UnitCancel, UnitCancelRequest, unit_cancel_as,
};
pub use unit_view::UnitView;
pub use verdict::{ARMS_VERDICT_VERB, ArmVerdictRequest, EVIDENCE_NAME_MAX_BYTES, arm_verdict_as};
pub use wire::{ArmList, ArmListRequest, ArmRef, ArmView};

const EXPERIMENT_ARMS: SideTable<EntityId, ExperimentArm, Named> =
    SideTable::new(&side_table::EXPERIMENT_ARM);

/// The longest arm title, in bytes.
pub const ARM_TITLE_MAX_BYTES: usize = 200;
/// The most numbers one verdict carries.
pub const VERDICT_NUMBERS_MAX: usize = 32;
/// The longest verdict text, in bytes.
pub const VERDICT_TEXT_MAX_BYTES: usize = 2_000;
/// The most evidence digests one verdict or review lists.
pub const ARM_EVIDENCE_MAX: usize = 32;

/// One experiment arm. Key: id16 (arm).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExperimentArm {
    pub id: EntityId,
    /// The GPU line: the lane project's id.
    pub line: EntityId,
    /// The family: a child project seated on the line.
    pub family: EntityId,
    /// The seat the arm was admitted under (`FamilySeat::seat`).
    pub seat: EntityId,
    /// The seat's kind at admission. Draws read the seat's kind now.
    pub track: Track,
    /// The task type the arm was placed in once (the root when unsure).
    pub type_ref: TypeRef,
    /// At most [`ARM_TITLE_MAX_BYTES`].
    pub title: String,
    pub contract: ContractPin,
    pub runner: RunnerRef,
    /// The closed arm of the same family this one re-runs or corrects; one
    /// successor per arm.
    pub supersedes: Option<EntityId>,
    /// The comparison half (section 4.4), fixed at admission for life;
    /// `None` while one rule is in force and on a new-idea arm.
    pub cohort: Option<RuleRef>,
    /// The arm's (period, position) in the period's assignment order.
    pub cohort_block: Option<(u32, u32)>,
    /// The digest of the planner card the lead read before admitting.
    pub card_digest: Option<String>,
    /// The rung-1 earmark made at admission (section 4.2); `None` on a
    /// re-run of an experiment, which gets no hold.
    pub first_allowance: Option<AllowanceHold>,
    /// How the hold ended by a write (rung 1 left `Open`, or the arm was
    /// withdrawn); `None` while no write ended it. A hold also ends at its
    /// period's end and when it lies dormant
    /// ([`ExperimentArm::hold_ended_at`]); those ends are read, not stored.
    pub hold_end: Option<HoldEnd>,
    /// `rungs[0]` is rung 1.
    pub rungs: Vec<ArmRung>,
    pub state: ArmState,
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
    /// SHA-256 of the contract text, lower hex: within a family, the
    /// experiment's key.
    pub sha256: String,
    /// The engine's clock at admission, always.
    pub pinned_at_ms: u64,
    /// The lane's own freeze time, shown as its claim.
    pub claimed_frozen_at_ms: Option<u64>,
    /// A sealed NOTE whose sealed bytes hash to `sha256`.
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
    pub state: RungState,
    /// How many holds the lead gave it (at most one).
    pub holds: u8,
    /// The designated runner's one forecast, written before the rung's
    /// first claim.
    pub forecast: Option<RunnerForecast>,
    /// The engine-minted promotion that opened this rung; `None` on rung 1.
    pub promotion: Option<ArmPromotion>,
    pub verdict: Option<ArmVerdict>,
    pub review: Option<ArmReview>,
    /// The scored fact, written once.
    pub outcome: Option<ArmOutcome>,
    /// The last settlement at this rung, fixed when the rung leaves `Open`.
    pub work_done_at_ms: Option<u64>,
    /// The team receipt's `team_ref` (`arm:<arm hex>:r<rung>`) once its
    /// projection is written.
    pub receipt: Option<String>,
}

impl ArmRung {
    /// A fresh rung `rung`, opened by `promotion` (none on rung 1).
    #[must_use]
    pub fn open(rung: u8, promotion: Option<ArmPromotion>) -> Self {
        Self {
            rung,
            state: RungState::Open,
            holds: 0,
            forecast: None,
            promotion,
            verdict: None,
            review: None,
            outcome: None,
            work_done_at_ms: None,
            receipt: None,
        }
    }
}

/// Where a rung stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RungState {
    Open,
    /// A promote verdict waits for its independent review.
    AwaitingReview,
    Closed {
        end: RungEnd,
    },
}

/// How a rung closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum RungEnd {
    Promoted,
    Killed,
    Invalid { reason: ArmInvalidReason },
}

/// Where an arm stands.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ArmState {
    #[default]
    Open,
    /// Its last rung was promoted.
    Succeeded,
    Killed,
    Invalid,
    Withdrawn,
}

/// The designated runner's forecast for a rung (section 4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerForecast {
    /// The chance the rung passes, in thousandths.
    pub pass_per_mille: u16,
    pub runner: RunnerRef,
    pub contract_sha256: String,
    /// Who wrote it; `None` after their erase.
    pub written_by: Option<EntityId>,
    pub written_at_ms: u64,
}

/// A rung's scored fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmOutcome {
    pub success: bool,
    pub anchor: Anchor,
    pub at_ms: u64,
}

/// How a first-allowance hold ended by a write (section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HoldEnd {
    pub at_ms: u64,
    pub cause: HoldEndCause,
}

/// Why a first-allowance hold ended. The first two are written; the last
/// two are read from the clock ([`ExperimentArm::hold_ended_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HoldEndCause {
    /// Rung 1 left `Open`.
    RungClosed,
    /// The arm was withdrawn.
    Withdrawn,
    /// The hold's period ended.
    PeriodEnded,
    /// The period policy's `hold_ttl_secs` passed with no claim ever made.
    Dormant,
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
    /// The claims this verdict rests on.
    pub units: Vec<EntityId>,
    /// Required for promote and kill: an output digest of `units`.
    pub result: Option<ArmEvidenceDigest>,
    /// At most [`VERDICT_NUMBERS_MAX`] entries.
    pub numbers: BTreeMap<String, f64>,
    /// At most [`VERDICT_TEXT_MAX_BYTES`].
    pub text: String,
    pub evidence: Vec<ArmEvidenceDigest>,
    pub ledger_row: Option<LedgerRowRef>,
    pub contract_sha256: String,
    /// Who gave it; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
    /// The arm revision the verdict was written at.
    pub arm_revision: u64,
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
    CouldNotMeasure,
    ContractChanged,
    TimedOut,
    Withdrawn,
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
    /// The verdict revision this review read.
    pub of_arm_revision: u64,
    /// The verdict's result digest, read again.
    pub result: ArmEvidenceDigest,
    pub evidence: Vec<ArmEvidenceDigest>,
    /// The review text (REVIEW.md), by hash.
    pub review_ref: ArmEvidenceDigest,
    pub ledger_row: Option<LedgerRowRef>,
    /// The reviewer's model, with its revision, shown as a claim.
    pub model: String,
    /// The reviewer; `None` after their erase.
    pub by: Option<EntityId>,
    /// The Grant the reviewer held the reviewer role under; `None` when the
    /// vault owner reviewed under their own proof.
    pub grant: Option<EntityId>,
    pub at_ms: u64,
}

/// A review's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArmReviewVerdict {
    Confirmed,
    Changed { to: ArmChangedTo },
    Unresolved,
}

/// What a review may change a promote to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArmChangedTo {
    Kill,
    Invalid { reason: ArmInvalidReason },
}

impl ExperimentArm {
    /// Whether the arm is still open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state == ArmState::Open
    }

    /// When and why the first-allowance hold ended, as of `now_ms`: the
    /// written end; else the end of the hold's period (`period_end_ms`);
    /// else, with no claim ever made on it (`claimed` false), the moment
    /// `hold_ttl_secs` passed after admission. `None` while the hold lives
    /// or when the arm has none.
    #[must_use]
    pub fn hold_ended_at(
        &self,
        now_ms: u64,
        period_end_ms: u64,
        hold_ttl_secs: u64,
        claimed: bool,
    ) -> Option<HoldEnd> {
        self.first_allowance.as_ref()?;
        if let Some(end) = self.hold_end {
            return Some(end);
        }
        let dormant_at = (!claimed).then(|| {
            self.admitted_at_ms
                .saturating_add(hold_ttl_secs.saturating_mul(1_000))
        });
        let (at_ms, cause) = match dormant_at {
            Some(at) if at < period_end_ms => (at, HoldEndCause::Dormant),
            _ => (period_end_ms, HoldEndCause::PeriodEnded),
        };
        (now_ms >= at_ms).then_some(HoldEnd { at_ms, cause })
    }

    /// Ends the first-allowance hold by a write at `at_ms` (rung 1 left
    /// `Open`, or the arm was withdrawn): its undrawn part goes back to its
    /// pools once, as the fold reads it. The verdict and withdrawal writes
    /// (row M2-E) call it on the arm they put, beside their revision bump.
    /// `false`, and nothing changes, when the arm holds none or its hold
    /// already ended by a write.
    pub fn end_hold(&mut self, at_ms: u64, cause: HoldEndCause) -> bool {
        if self.first_allowance.is_none() || self.hold_end.is_some() {
            return false;
        }
        self.hold_end = Some(HoldEnd { at_ms, cause });
        true
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

/// Puts `arm` as given (TEST-ONLY, `test_doors::experiment_arm_rows`): a
/// test stands an arm in a state whose writer is a later row (a closed
/// rung 1, a withdrawal: row M2-E's verdict writes).
#[cfg(oneiron_test_support)]
pub(crate) fn put_arm_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    arm: &ExperimentArm,
) -> crate::Result<()> {
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &arm.id, arm)
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
            if let Some(forecast) = &mut rung.forecast {
                changed |= forget(&mut forecast.written_by);
                changed |= forget(&mut forecast.runner.actor);
            }
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
