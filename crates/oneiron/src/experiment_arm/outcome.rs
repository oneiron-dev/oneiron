//! A rung's scored outcome (design pass 32 r2, sections 3.6, 4.5 and 4.6):
//! what a verdict or a review rests on, read from the rung's claims, and the
//! write that scores the rung once. The verdict (`vault.arms.verdict`) and
//! the review (`vault.arms.review`) call these in their own write, so the
//! outcome, the rung's new state and the receipt projection land together.
use std::collections::{BTreeMap, BTreeSet};

use crate::claim::learning_evidence::Anchor;
use crate::gpu_line::{
    BudgetPolicy, ClaimState, GpuLine, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal,
    claims_at_rung_in_txn, stored_period_in_txn,
};
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::team::pattern::{TeamAxis, TeamPattern};
use crate::team::receipt::{
    ARM_RECEIPT_PREFIX, DecidedBy, TeamOutcome, TeamReceipt, TeamShape, record_arm_receipt_in_txn,
};
use crate::{EntityId, Vault};

use super::{ArmEvidenceDigest, ArmInvalidReason, ArmOutcome, ExperimentArm, RungEnd, RungState};

/// The claims made at one rung of one arm, as a verdict or a review reads
/// them in its write.
pub(super) struct RungClaims {
    claims: Vec<UnitClaim>,
}

impl RungClaims {
    /// Every claim at `rung` of `arm`, over every attempt and period.
    pub(super) fn read_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        arm: &ExperimentArm,
        rung: u8,
    ) -> crate::Result<Self> {
        let claims = claims_at_rung_in_txn(vault, txn, &arm.id, rung)?
            .into_iter()
            .filter(|claim| claim.arm == arm.id && claim.rung == rung)
            .collect();
        Ok(Self { claims })
    }

    /// Whether a claim at the rung has not ended: an unconfirmed unit is not
    /// zero, so no verdict is given over it (`units_live`).
    pub(super) fn any_live(&self) -> bool {
        self.claims.iter().any(UnitClaim::is_open)
    }

    /// The first of `units` that is no claim at this rung.
    pub(super) fn first_foreign(&self, units: &[EntityId]) -> Option<EntityId> {
        units
            .iter()
            .copied()
            .find(|unit| !self.claims.iter().any(|claim| claim.id == *unit))
    }

    /// The work claims among `units` that measured the arm's contract: ended
    /// `Settled` with charged seconds, under the arm's contract sha256 (the
    /// workload pin carried it at the reserve). A review check, a released,
    /// box-lost or written-off attempt measures nothing.
    fn measured<'a>(
        &'a self,
        units: &'a [EntityId],
        contract_sha256: &'a str,
    ) -> impl Iterator<Item = &'a UnitTerminal> + 'a {
        self.claims
            .iter()
            .filter(move |claim| {
                units.contains(&claim.id)
                    && claim.purpose == UnitPurpose::Work
                    && claim.contract_sha256 == contract_sha256
            })
            .filter_map(|claim| match &claim.state {
                ClaimState::Ended(terminal)
                    if terminal.end == UnitEnd::Settled && terminal.charged_secs > 0 =>
                {
                    Some(terminal)
                }
                _ => None,
            })
    }

    /// The checks of a measurable verdict (section 4.6): `units` holds a
    /// measured unit, and `result` is one of its output digests, which the
    /// machine hashed itself.
    ///
    /// # Errors
    ///
    /// `invalid_state`: `no_measured_unit`, `result_not_an_output`.
    pub(super) fn check_result(
        &self,
        units: &[EntityId],
        contract_sha256: &str,
        result: &ArmEvidenceDigest,
    ) -> MemoryResult<()> {
        let mut measured = self.measured(units, contract_sha256).peekable();
        if measured.peek().is_none() {
            return Err(invalid_state(
                "no_measured_unit: promote and kill rest on a named work claim of this rung that settled with charged seconds under the arm's contract",
            ));
        }
        if !measured.any(|terminal| {
            terminal
                .outputs
                .iter()
                .any(|output| output.sha256 == result.sha256)
        }) {
            return Err(invalid_state(
                "result_not_an_output: the result digest is no output digest of the named measured claims",
            ));
        }
        Ok(())
    }

    /// Whether the rows support invalid `reason` (section 4.5), given the
    /// verdict's `text` and `evidence`.
    pub(super) fn supports_invalid(
        &self,
        reason: &ArmInvalidReason,
        text: &str,
        evidence: &[ArmEvidenceDigest],
    ) -> bool {
        let ended = || {
            self.claims.iter().filter_map(|claim| match &claim.state {
                ClaimState::Ended(terminal) => Some(terminal),
                _ => None,
            })
        };
        match reason {
            ArmInvalidReason::ContractChanged => ended().any(|terminal| {
                let refused = match &terminal.end {
                    UnitEnd::Released(why) => why.contains("contract_changed"),
                    _ => false,
                };
                refused
                    || terminal
                        .node_end
                        .as_deref()
                        .is_some_and(|end| end.contains("contract_changed"))
            }),
            ArmInvalidReason::TimedOut => ended().any(|terminal| {
                terminal.end == UnitEnd::Settled
                    && terminal.node_end.as_deref() == Some("time_limit")
            }),
            ArmInvalidReason::Withdrawn => self.charged_secs() == 0,
            ArmInvalidReason::CouldNotMeasure | ArmInvalidReason::Other(_) => {
                !text.trim().is_empty() && !evidence.is_empty()
            }
        }
    }

    /// The seconds charged to the rung's work claims: what the rung cost.
    fn charged_secs(&self) -> u64 {
        self.work_terminals()
            .map(|terminal| terminal.charged_secs)
            .sum()
    }

    /// The last settlement at the rung: the rung's `work_done_at_ms` once it
    /// leaves `Open`.
    pub(super) fn work_done_at_ms(&self) -> Option<u64> {
        self.work_terminals()
            .map(|terminal| terminal.ended_at_ms)
            .max()
    }

    /// The actors who reserved a claim at the rung, a review check's
    /// reserver among them.
    pub(super) fn reservers(&self) -> BTreeSet<EntityId> {
        self.claims
            .iter()
            .filter_map(|claim| claim.reserved_by)
            .collect()
    }

    fn work_terminals(&self) -> impl Iterator<Item = &UnitTerminal> {
        self.claims
            .iter()
            .filter(|claim| claim.purpose == UnitPurpose::Work)
            .filter_map(|claim| match &claim.state {
                ClaimState::Ended(terminal) => Some(terminal),
                _ => None,
            })
    }

    /// The period whose policy the rung's work ran under: that of its last
    /// settled work claim's reservation. `None` before any work settled.
    fn work_period(&self) -> Option<u32> {
        self.claims
            .iter()
            .filter(|claim| claim.purpose == UnitPurpose::Work)
            .filter_map(|claim| match &claim.state {
                ClaimState::Ended(terminal) if terminal.end == UnitEnd::Settled => {
                    Some((terminal.ended_at_ms, claim.period))
                }
                _ => None,
            })
            .max()
            .map(|(_, period)| period)
    }

    /// The budget policy the rung is judged under: the minted policy of the
    /// period its work ran in (a period record never changes), else the
    /// line's own policy.
    pub(super) fn policy_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        line: &GpuLine,
        arm: &ExperimentArm,
    ) -> crate::Result<BudgetPolicy> {
        if let Some(index) = self.work_period()
            && let Some(period) = stored_period_in_txn(vault, txn, &arm.line, index)?
        {
            return Ok(period.policy);
        }
        Ok(line.budget.clone())
    }
}

/// The team reference of rung `rung`'s receipt: `arm:<arm hex>:r<rung>`.
#[must_use]
pub fn rung_receipt_ref(arm: &EntityId, rung: u8) -> String {
    format!("{ARM_RECEIPT_PREFIX}{}:r{rung}", arm.to_hex())
}

/// Whether `result` already backs a scored rung of another arm or rung on
/// `arm`'s line (section 4.6: a result backs one outcome). Read again in the
/// write that would score, so two pending promotes cannot both score it.
///
/// # Errors
///
/// A store read failure.
pub(super) fn result_scored_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &ExperimentArm,
    rung: u8,
    result: &ArmEvidenceDigest,
) -> crate::Result<bool> {
    Ok(vault
        .experiment_arms_in_txn(txn)?
        .iter()
        .filter(|other| other.line == arm.line)
        .flat_map(|other| {
            other
                .rungs
                .iter()
                .map(move |other_rung| (other.id, other_rung))
        })
        .any(|(id, other_rung)| {
            (id, other_rung.rung) != (arm.id, rung)
                && other_rung.outcome.is_some()
                && other_rung
                    .verdict
                    .as_ref()
                    .and_then(|verdict| verdict.result.as_ref())
                    .is_some_and(|scored| scored.sha256 == result.sha256)
        }))
}

/// Whether an arm that `arm` supersedes, directly or through its own
/// predecessors, was promoted at `rung`: an experiment wins a rung once
/// (section 3.3).
///
/// # Errors
///
/// A store read failure.
pub(super) fn rung_won_before_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &ExperimentArm,
    rung: u8,
) -> crate::Result<bool> {
    let mut seen = BTreeSet::from([arm.id]);
    let mut next = arm.supersedes;
    while let Some(id) = next {
        if !seen.insert(id) {
            break;
        }
        let Some(before) = vault.experiment_arm_in_txn(txn, &id)? else {
            break;
        };
        let won = before.rungs.iter().any(|before_rung| {
            before_rung.rung == rung
                && before_rung.state
                    == (RungState::Closed {
                        end: RungEnd::Promoted,
                    })
        });
        if won {
            return Ok(true);
        }
        next = before.supersedes;
    }
    Ok(false)
}

/// Scores rung `index` of `arm` with `outcome` and writes its receipt
/// projection in the same write (sections 3.6 and 4.5): the rung's outcome
/// is the scored fact, written once; the receipt is its copy for the generic
/// payoff view. `claims` are the rung's and `cap_secs` its rung cap.
///
/// # Errors
///
/// `invalid_state` for a rung already scored; the receipt writer's
/// refusals (a receipt already written); a store failure.
pub(super) fn score_rung_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    arm: &mut ExperimentArm,
    index: usize,
    outcome: ArmOutcome,
    claims: &RungClaims,
    cap_secs: Option<u64>,
) -> MemoryResult<()> {
    let rung = &arm.rungs[index];
    if rung.outcome.is_some() || rung.receipt.is_some() {
        return Err(invalid_state(
            "rung_closed: the rung's outcome is written once",
        ));
    }
    let team_ref = rung_receipt_ref(&arm.id, rung.rung);
    let opened_at_ms = rung
        .promotion
        .as_ref()
        .map_or(arm.admitted_at_ms, |promotion| promotion.review_at_ms);
    let elapsed_secs = rung
        .work_done_at_ms
        .map_or(0, |done| done.saturating_sub(opened_at_ms) / 1_000);
    // A model id the receipt cannot carry is recorded as unknown, never cut.
    let model = &arm.runner.model;
    let models = if model.is_empty() || model.len() > 256 || model.contains('\0') {
        Vec::new()
    } else {
        vec![model.clone()]
    };
    let receipt = TeamReceipt {
        team_ref: team_ref.clone(),
        project: Some(arm.family),
        type_ref: arm.type_ref.clone(),
        pattern: TeamPattern::Market,
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models,
        shape: TeamShape {
            width: 1,
            roles: BTreeMap::from([("runner".to_owned(), 1)]),
        },
        decided_by: DecidedBy::Referee {
            rule: arm.contract.sha256.clone(),
            signed_at: arm.contract.pinned_at_ms / 1_000,
        },
        coverage: None,
        confessions: None,
        spend: Some(secs_f64(claims.charged_secs())),
        spend_cap: cap_secs.map(secs_f64),
        elapsed_secs,
        calls: None,
        outcome: Some(TeamOutcome {
            receipt: team_ref.clone(),
            anchor: outcome.anchor,
            success: outcome.success,
            at: outcome.at_ms / 1_000,
            critics: None,
        }),
        at: outcome.at_ms / 1_000,
    };
    record_arm_receipt_in_txn(vault, wtxn, &receipt)?;
    let rung = &mut arm.rungs[index];
    rung.outcome = Some(outcome);
    rung.receipt = Some(team_ref);
    Ok(())
}

/// Seconds as the receipt's spend unit. A rung's seconds stay far below
/// `u32::MAX` (136 years), so the conversion is exact.
fn secs_f64(secs: u64) -> f64 {
    f64::from(u32::try_from(secs).unwrap_or(u32::MAX))
}

/// The outcome of a lead's kill: scored at once against the held-out
/// contract.
pub(super) const fn kill_outcome(at_ms: u64) -> ArmOutcome {
    ArmOutcome {
        success: false,
        anchor: Anchor::HeldOut,
        at_ms,
    }
}

/// The outcome of an independent review: an audit of the one verdict it
/// read.
pub(super) const fn audited_outcome(success: bool, at_ms: u64) -> ArmOutcome {
    ArmOutcome {
        success,
        anchor: Anchor::Audit { rate: 1.0 },
        at_ms,
    }
}

pub(super) fn invalid_state(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        why,
        &["Read the arm with vault.arms.get."],
    )
}
