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
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::experiment_arm::{
    ArmDecision, ArmState, ExperimentArm, ForecastScoreRow, RunnerRef, forecast_scores,
};
use crate::gpu_line::{
    Bucket, ClaimState, FamilySeat, GpuLine, LineRefusal, PeriodRoom, RuleRef, SpendRow, Track,
    claims_at_rung_in_txn, line_in_txn, line_refusals_in_txn, period_view_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Every stored GPU line, by its project, read in the card's own snapshot. A
/// line's row outlives its project's: a lane project deleted after its
/// families moved away keeps its `GPU_LINE` row and the seats on it.
const LINES: SideTable<EntityId, GpuLine, Named> = SideTable::new(&side_table::GPU_LINE);

/// The most arms one card page lists.
pub const PLANNER_CARD_ARMS_PAGE: usize = 50;

/// The card's `lane_arms` part.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannerCardLaneArms {
    /// The line: the lane project's id, hex.
    pub line: String,
    /// The kind of the family's seat: its live one, else its newest.
    pub track: Track,
    /// Whether that seat is live now: as the period's mint marked it, and
    /// while that period is unminted, as its mint will mark it (a new idea it
    /// no longer funds is not, though its row is not yet marked).
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
    /// idea), and each live first-allowance hold of its arms, a spent one
    /// (no room left) too.
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

/// The line that seats `family` (section 5.1: family -> line), from the
/// lines' stored seats: the one where its seat stands at `now_ms`
/// ([`standing_seat_in_txn`]), else the one holding its newest seat by
/// admission time. A family is seated as a child project of its lane
/// (`vault.gpu.lines.families.admit` refuses any other), so the lines on the
/// projects it descends from over the stored parents
/// ([`Vault::project_lines_in_txn`]) are read first. A family moved under
/// another parent since keeps its seat, and its former lane may since be
/// deleted with its line row kept, so every other stored line
/// ([`LINES`]) is read after them. `None` when no line ever seated it.
///
/// # Errors
///
/// A stored parent that is not an id; a store read failure.
pub(super) fn family_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    family: EntityId,
    now_ms: u64,
) -> Result<Option<GpuLine>> {
    let mut lines = Vec::new();
    for project in vault.project_lines_in_txn(txn, family)? {
        if let Some(line) = line_in_txn(vault, txn, &project)? {
            lines.push(line);
        }
    }
    for (project, line) in LINES.scan(&vault.store, txn)? {
        if !lines.iter().any(|seen| seen.project == project) {
            lines.push(line);
        }
    }
    let mut newest: Option<(u64, GpuLine)> = None;
    for line in lines {
        if standing_seat_in_txn(vault, txn, &line, &family, now_ms)?.is_some() {
            return Ok(Some(line));
        }
        let Some(at_ms) = line.last_seat(&family).map(|seat| seat.admitted_at_ms) else {
            continue;
        };
        if newest
            .as_ref()
            .is_none_or(|(newest_ms, _)| at_ms > *newest_ms)
        {
            newest = Some((at_ms, line));
        }
    }
    Ok(newest.map(|(_, line)| line))
}

/// The live seat of `family` on `line` as it stands at `now_ms`, read in
/// `txn`. A minted period's seats are as its mint marked them, so while the
/// period that holds now is minted the stored row decides, whatever the
/// policy says since (a later edit of `new_idea_periods` moves no seat the
/// mint already judged). While it is unminted, the card shows the mint's
/// preview, and that mint will lapse a new idea from the period its funded
/// periods end under the policy as it stands then (LE-6,
/// [`FamilySeat::lapses_from`]): the same rule is applied here.
fn standing_seat_in_txn<'l>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &'l GpuLine,
    family: &EntityId,
    now_ms: u64,
) -> Result<Option<&'l FamilySeat>> {
    let Some(seat) = line.seat(family) else {
        return Ok(None);
    };
    let Ok(Some((period, true))) = period_view_in_txn(vault, txn, line, now_ms)? else {
        return Ok(Some(seat));
    };
    Ok(match seat.lapses_from(line.budget.new_idea_periods) {
        Some(lapse) if lapse <= period.index => None,
        _ => Some(seat),
    })
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
    let seated = standing_seat_in_txn(vault, txn, line, &family, now_ms)?;
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
    // Each live hold the period's rows carry, a spent one too: its room is 0.
    // A hold whose arm is no longer open (its unclaimed hold ran out) is a
    // row of the period, not a bucket the family can draw.
    let held: BTreeSet<EntityId> = rows
        .iter()
        .filter_map(|row| match row {
            SpendRow::Hold {
                arm,
                family: of,
                arm_open: true,
                ..
            } if *of == family => Some(*arm),
            _ => None,
        })
        .collect();
    buckets.extend(
        arms.iter()
            .map(|arm| Bucket::FirstAllowance { arm: arm.id })
            .filter(|bucket| match bucket {
                Bucket::FirstAllowance { arm } => held.contains(arm) || room.capacity(*bucket) > 0,
                _ => false,
            }),
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
