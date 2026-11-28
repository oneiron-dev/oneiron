//! The planner card's `lane_arms` part (design pass 32 r2, section 5.4):
//! what the family's own arms on its GPU line did, read from the line's own
//! rows and nothing else. An arm of the family on another line, and an arm
//! of another family on this line, never appear (T57). Then the family's
//! room in the period that holds now, its refusals in that period and the
//! forecast scores of its arms.
//!
//! The room is the reserve door's own fold ([`PeriodRoom::fold`] over the
//! period's holds and claims), so the card shows what the next draw would
//! see. Every number is the line's: the period record, its policy and
//! `forecast_score_after`.
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::experiment_arm::{
    ArmDecision, ArmState, ExperimentArm, ForecastScoreRow, RunnerRef, forecast_scores,
};
use crate::gpu_line::{
    Bucket, ClaimState, GpuLine, LineRefusal, PeriodRoom, RuleRef, Track, claims_at_rung_in_txn,
    line_refusals_in_txn, period_view_in_txn,
};
use crate::{EntityId, Vault};

/// The most arms one card page lists.
pub const PLANNER_CARD_ARMS_PAGE: usize = 50;

/// The card's `lane_arms` part.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardLaneArms {
    /// The line: the lane project's id, hex.
    pub line: String,
    /// The kind of the family's seat: its live one, else its newest.
    pub track: Track,
    /// Whether that seat is live.
    pub seated: bool,
    /// The family's arms on this line, newest first: one page of at most
    /// [`PLANNER_CARD_ARMS_PAGE`].
    pub arms: Vec<PlannerCardArm>,
    /// The `cursor` that reads the next page; `None` on the last one.
    pub next_cursor: Option<String>,
    /// The family's room in the period that holds now; `None` before
    /// period 0, or when the line's clock or the mint's preview refuses.
    pub room: Option<PlannerCardRoom>,
    /// The family's unmet asks in that period, in the order written.
    pub refusals: Vec<LineRefusal>,
    /// How each declared runner model's forecasts on the family's arms came
    /// true (section 4.7), over every arm of the family on this line.
    pub forecast_scores: Vec<ForecastScoreRow>,
}

/// One arm on the card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardArm {
    pub arm: String,
    pub title: String,
    pub state: ArmState,
    /// The rung the arm stands at.
    pub rung: u8,
    /// The newest verdict's decision; `None` before any verdict.
    pub decision: Option<ArmDecision>,
    /// The newest verdict's text.
    pub reason: Option<String>,
    /// The machine's device time over every ended claim of the arm, at every
    /// rung and attempt.
    pub measured_secs: u64,
    /// What the pools paid for those claims.
    pub charged_secs: u64,
    pub runner: RunnerRef,
    /// The current rung's forecast, in thousandths.
    pub forecast_per_mille: Option<u16>,
    /// The comparison half fixed at admission.
    pub cohort: Option<RuleRef>,
    pub admitted_at_ms: u64,
}

/// The family's room in one period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerCardRoom {
    pub period: u32,
    /// `false` while the period is unminted: the room is the mint's preview,
    /// the record the next write door mints.
    pub minted: bool,
    /// Each bucket the family can draw: its floor, the pinned pool when its
    /// track is the pinned one, each market ceiling in force (none for a new
    /// idea), and each live first-allowance hold of its arms.
    pub buckets: Vec<PlannerCardBucket>,
}

/// One bucket's room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerCardBucket {
    pub bucket: Bucket,
    pub capacity: u64,
    pub used: u64,
    pub left: u64,
}

/// The `lane_arms` part of `family` on `line` at `now_ms`, the page after
/// `cursor`, read in `txn`.
///
/// # Errors
///
/// A cursor the card did not answer; a family `line` does not seat; storage
/// errors.
pub(super) fn lane_arms_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
    family: EntityId,
    cursor: Option<&str>,
    now_ms: u64,
) -> Result<PlannerCardLaneArms> {
    let after = cursor.map(parse_cursor).transpose()?;
    let seated = line.seat(&family);
    let track = seated
        .or_else(|| line.last_seat(&family))
        .map(|seat| seat.track)
        .ok_or(Error::InvalidClaimBody(
            "the planner card's lane part reads a family its line seats",
        ))?;
    let mut arms: Vec<ExperimentArm> = vault
        .experiment_arms_in_txn(txn)?
        .into_iter()
        .filter(|arm| arm.line == line.project && arm.family == family)
        .collect();
    arms.sort_by(|a, b| (b.admitted_at_ms, b.id).cmp(&(a.admitted_at_ms, a.id)));
    let forecast_scores = forecast_scores(line.project, &arms, line.budget.forecast_score_after);
    let room = room_in_txn(vault, txn, line, family, track, &arms, now_ms)?;
    let refusals = match &room {
        Some(room) => line_refusals_in_txn(vault, txn, &line.project, room.period)?
            .into_iter()
            .map(|(_, refusal)| refusal)
            .filter(|refusal| refusal.family == family)
            .collect(),
        None => Vec::new(),
    };
    let mut rest = arms
        .iter()
        .filter(|arm| after.is_none_or(|key| (arm.admitted_at_ms, arm.id) < key));
    let mut page = Vec::new();
    for arm in rest.by_ref().take(PLANNER_CARD_ARMS_PAGE) {
        page.push(arm_on_card_in_txn(vault, txn, arm)?);
    }
    let next_cursor = match (rest.next(), page.last()) {
        (Some(_), Some(last)) => Some(format!("{}:{}", last.admitted_at_ms, last.arm)),
        _ => None,
    };
    Ok(PlannerCardLaneArms {
        line: line.project.to_hex(),
        track,
        seated: seated.is_some(),
        arms: page,
        next_cursor,
        room,
        refusals,
        forecast_scores,
    })
}

/// `cursor` as the arm key it names: `<admitted_at_ms>:<arm hex>`.
fn parse_cursor(cursor: &str) -> Result<(u64, EntityId)> {
    let bad = || Error::InvalidClaimBody("the planner card's cursor is a next_cursor it answered");
    let (at_ms, arm) = cursor.split_once(':').ok_or_else(bad)?;
    let at_ms = at_ms.parse::<u64>().map_err(|_| bad())?;
    let arm = EntityId::from_hex(arm).map_err(|_| bad())?;
    Ok((at_ms, arm))
}

/// `arm` as the card shows it, with the seconds of its ended claims.
fn arm_on_card_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &ExperimentArm,
) -> Result<PlannerCardArm> {
    let (mut measured_secs, mut charged_secs) = (0u64, 0u64);
    for rung in &arm.rungs {
        for claim in claims_at_rung_in_txn(vault, txn, &arm.id, rung.rung)? {
            if claim.arm != arm.id || claim.rung != rung.rung {
                continue;
            }
            if let ClaimState::Ended(terminal) = &claim.state {
                measured_secs = measured_secs.saturating_add(terminal.measured_secs);
                charged_secs = charged_secs.saturating_add(terminal.charged_secs);
            }
        }
    }
    let verdict = arm
        .rungs
        .iter()
        .rev()
        .find_map(|rung| rung.verdict.as_ref());
    Ok(PlannerCardArm {
        arm: arm.id.to_hex(),
        title: arm.title.clone(),
        state: arm.state,
        rung: arm.current_rung(),
        decision: verdict.map(|verdict| verdict.decision.clone()),
        reason: verdict.map(|verdict| verdict.text.clone()),
        measured_secs,
        charged_secs,
        runner: arm.runner.clone(),
        forecast_per_mille: arm
            .rungs
            .last()
            .and_then(|rung| rung.forecast.as_ref())
            .map(|forecast| forecast.pass_per_mille),
        cohort: arm.cohort,
        admitted_at_ms: arm.admitted_at_ms,
    })
}

/// The family's room in the period of `line` that holds `now_ms`, over the
/// family's `arms` on the line.
fn room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
    family: EntityId,
    track: Track,
    arms: &[ExperimentArm],
    now_ms: u64,
) -> Result<Option<PlannerCardRoom>> {
    let Ok(Some((period, preview))) = period_view_in_txn(vault, txn, line, now_ms)? else {
        return Ok(None);
    };
    let rows = vault.spend_rows_in_txn(txn, &line.project, &period, now_ms)?;
    let room = PeriodRoom::fold(&period, &line.families, &rows);
    let mut buckets = vec![Bucket::Floor { family }];
    if track == period.policy.pinned_track {
        buckets.push(Bucket::Pinned);
    }
    if track != Track::NewIdea {
        buckets.extend(period.tables.iter().map(|table| Bucket::Market {
            family,
            rule: table.rule,
        }));
    }
    buckets.extend(
        arms.iter()
            .map(|arm| Bucket::FirstAllowance { arm: arm.id })
            .filter(|bucket| room.capacity(*bucket) > 0),
    );
    Ok(Some(PlannerCardRoom {
        period: period.index,
        minted: !preview,
        buckets: buckets
            .into_iter()
            .map(|bucket| PlannerCardBucket {
                bucket,
                capacity: room.capacity(bucket),
                used: room.used(bucket),
                left: room.left(bucket),
            })
            .collect(),
    }))
}
