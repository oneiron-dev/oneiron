//! `vault.jobs.history` is a view over rows the vault already keeps, not a second ledger
//! (design pass 34 sections 5 and 10, row Q2). For one line and one period, the seconds the
//! history totals as charged are the seconds the line's own period fold charges the period's
//! buckets for the same ended claims: a settled run at its billed seconds, a run billed past its
//! reservation at the reservation, a refusal before anything ran and a lost machine at zero,
//! and a closed arm's first-allowance hold at what its unit took from it. An open claim is not
//! history, and a claim of another period counts in that period only. An agent reads only the
//! attempts it reserved, and totals over those. A line unit shows the meter the issuer's
//! observation of its key holds, and keeps its claim's terminal for the rest.
//!
//! The projection is pure, so these run without a vault. Fleet command:
//! `cargo test --locked -p oneiron --all-features --test job_history`.
use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_job::{GpuJobEnd, GpuJobTerminal, MeterVerdict};
use oneiron::gpu_line::{
    AllowanceHold, Bucket, BudgetPolicy, ClaimState, Draw, DrawSource, FamilySeat, GpuLine,
    GpuLinePeriod, PeriodRoom, PinnedMode, RuleRef, SpendRow, Track, UnitClaim, UnitEndReport,
    UnitPurpose, gpu_seconds, mint_period,
};
use oneiron::job_dispatch::JobObservation;
use oneiron::job_history::{HistoryInputs, HistoryViewer, JobHistoryRequest, project};
use oneiron::llm::run_admission::AllocationRef;

const RESERVED: u64 = 1_800;
const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x03;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn lane() -> EntityId {
    id(1)
}
fn demand() -> EntityId {
    id(10)
}
fn interest() -> EntityId {
    id(20)
}
fn lead() -> EntityId {
    id(40)
}
fn other_agent() -> EntityId {
    id(41)
}
fn machine() -> EntityId {
    id(50)
}

fn seat(family: EntityId, track: Track) -> FamilySeat {
    let mut seat_id = *family.as_bytes();
    seat_id[0] = 0x04;
    FamilySeat {
        seat: EntityId::from_bytes_unchecked(seat_id),
        project: family,
        track,
        replaces: None,
        graduated: None,
        lapsed_from_period: None,
        effective_from_period: 0,
        late_floor: None,
        admitted_by: None,
        admitted_at_ms: 0,
    }
}

/// A line of one demand and one interest family, under a lane's own budget (the open-models
/// preset's figures, pass 34 section 3.3), so the mint funds floors, a pinned pool and a market.
fn line() -> GpuLine {
    GpuLine {
        project: lane(),
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: Vec::new(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: 345_600,
            pinned_parts: (1, 3),
            floor_arms: 2,
            rung_caps_secs: vec![1_800, 10_800, 172_800],
            seat_cap: 6,
            seat_reserve_floors: 1,
            new_idea_slots_per_period: 4,
            review_check_secs: 600,
            max_running_per_family: 1,
            forecast_required: true,
            window_periods: 3,
            pinned_mode: PinnedMode::FloorPlusMarket,
            ..BudgetPolicy::default()
        },
        families: vec![
            seat(demand(), Track::Demand),
            seat(interest(), Track::Interest),
        ],
        set_by: None,
        set_at_ms: 0,
        revision: 1,
        preset: None,
    }
}

fn minted(line: &GpuLine, index: u32) -> GpuLinePeriod {
    mint_period(
        line,
        index,
        &BTreeMap::new(),
        ANCHOR_MS + u64::from(index) * PERIOD_MS,
    )
    .expect("the mint funds the line")
}

fn market() -> DrawSource {
    DrawSource::Market {
        rule: RuleRef::PAYOFF_SHARE_1,
    }
}

fn draw(source: DrawSource, units: u64) -> Draw {
    Draw { source, units }
}

/// One claim of the line, reserved by `by` at `RESERVED` seconds over `draws`.
fn claim(
    job: u8,
    arm: EntityId,
    family: EntityId,
    period: u32,
    by: EntityId,
    draws: Vec<Draw>,
    state: ClaimState,
) -> UnitClaim {
    UnitClaim {
        id: id(job),
        arm,
        rung: 1,
        unit_key: format!("unit-{job}"),
        attempt: 1,
        line: lane(),
        family,
        period,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        reserved_secs: RESERVED,
        draws,
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-0".to_owned(),
            generation: 0,
        },
        grant: Some(id(60)),
        reserved_by: Some(by),
        reserved_at_ms: ANCHOR_MS + u64::from(period) * PERIOD_MS + 60_000,
        ask_digest: "ad".repeat(32),
        state,
        revision: 1,
    }
}

fn machine_end(end: GpuJobEnd, measured: Option<u64>, billed: u64) -> UnitEndReport {
    UnitEndReport::Machine(GpuJobTerminal {
        end,
        measured_secs: measured,
        billed_secs: billed,
        meter: MeterVerdict::Agreed,
        machine: Some(machine()),
        device_id: Some("GPU-1f2e3d4c".to_owned()),
        outputs: Vec::new(),
    })
}

/// `claim` ended by `report` at `at_ms`.
fn ended(claim: &UnitClaim, report: &UnitEndReport, at_ms: u64) -> UnitClaim {
    claim
        .ended_by(report, at_ms)
        .expect("the claim may end so")
        .expect("the claim was open")
}

/// Every bucket of the line's two families.
fn buckets() -> Vec<Bucket> {
    let mut buckets = vec![Bucket::Pinned];
    for family in [demand(), interest()] {
        buckets.push(Bucket::Floor { family });
        buckets.push(Bucket::Market {
            family,
            rule: RuleRef::PAYOFF_SHARE_1,
        });
    }
    buckets
}

/// The fixture: five claims of period 0 (one still open) and one of period 1, all on `lane()`.
struct Fixture {
    line: GpuLine,
    periods: Vec<GpuLinePeriod>,
    claims: Vec<UnitClaim>,
    /// The first-allowance hold of the closed arm `id(31)` in period 0.
    hold: SpendRow,
}

fn fixture() -> Fixture {
    let line = line();
    let periods = vec![minted(&line, 0), minted(&line, 1)];
    let in_period_0 = ANCHOR_MS + 3_600_000;
    let started = ClaimState::Started;
    // A closed arm's unit drew its first allowance and ran 700 of its 1,800 seconds.
    let settled_short = ended(
        &claim(
            1,
            id(31),
            demand(),
            0,
            lead(),
            vec![draw(DrawSource::FirstAllowance, RESERVED)],
            started.clone(),
        ),
        &machine_end(GpuJobEnd::Exited { code: 0 }, Some(700), 700),
        in_period_0,
    );
    // A unit billed past its reservation pays the reservation, floor first.
    let settled_over = ended(
        &claim(
            2,
            id(32),
            demand(),
            0,
            lead(),
            vec![draw(DrawSource::Floor, 1_000), draw(market(), 800)],
            started.clone(),
        ),
        &machine_end(GpuJobEnd::TimeLimit, Some(RESERVED), 2_500),
        in_period_0 + 1,
    );
    // Refused before anything ran: zero.
    let released = ended(
        &claim(
            3,
            id(32),
            demand(),
            0,
            other_agent(),
            vec![draw(DrawSource::Floor, RESERVED)],
            ClaimState::Claimed,
        ),
        &UnitEndReport::Refused {
            reason: "period_ended".to_owned(),
        },
        in_period_0 + 2,
    );
    // The machine attests the loss after 300 seconds seen: zero, and 300 lost.
    let lost = ended(
        &claim(
            4,
            id(33),
            interest(),
            0,
            other_agent(),
            vec![draw(DrawSource::Pinned, RESERVED)],
            started.clone(),
        ),
        &machine_end(
            GpuJobEnd::Lost {
                reason: "host_reset".to_owned(),
                last_seen_secs: 300,
            },
            None,
            0,
        ),
        in_period_0 + 3,
    );
    // Still running: no end, so no history.
    let open = claim(
        5,
        id(34),
        interest(),
        0,
        lead(),
        vec![draw(market(), RESERVED)],
        started.clone(),
    );
    // The next period's unit.
    let next = ended(
        &claim(
            6,
            id(32),
            demand(),
            1,
            lead(),
            vec![draw(DrawSource::Floor, RESERVED)],
            started,
        ),
        &machine_end(GpuJobEnd::Exited { code: 0 }, Some(500), 500),
        ANCHOR_MS + PERIOD_MS + 3_600_000,
    );
    let hold = SpendRow::Hold {
        arm: id(31),
        family: demand(),
        hold: AllowanceHold {
            period: 0,
            units: RESERVED,
            draws: vec![draw(DrawSource::Floor, RESERVED)],
        },
        arm_open: false,
    };
    Fixture {
        line,
        periods,
        claims: vec![settled_short, settled_over, released, lost, open, next],
        hold,
    }
}

/// What the line's own fold charges period `index` for the ended claims of `fixture`: the sum of
/// every bucket's spend.
fn fold_charged(fixture: &Fixture, index: u32) -> u64 {
    let period = &fixture.periods[usize::try_from(index).expect("a small index")];
    let mut rows = vec![fixture.hold.clone()];
    rows.extend(
        fixture
            .claims
            .iter()
            .filter(|claim| !claim.is_open())
            .map(UnitClaim::spend_row),
    );
    let room = PeriodRoom::fold(period, &fixture.line.families, &rows);
    buckets().into_iter().map(|bucket| room.used(bucket)).sum()
}

fn request() -> JobHistoryRequest {
    JobHistoryRequest {
        line: Some(lane().to_hex()),
        ..JobHistoryRequest::default()
    }
}

#[test]
fn history_totals_equal_the_settled_holds_of_the_same_period() {
    let fixture = fixture();
    let inputs = HistoryInputs {
        jobs: &[],
        claims: &fixture.claims,
        periods: &fixture.periods,
        orders: &[],
        observations: &[],
        unattributed: &[],
    };
    let filter = request().filter().expect("a valid request");
    let history = project(&inputs, &filter, HistoryViewer::Owner);

    // Five ended attempts; the open claim is not history.
    assert_eq!(history.attempts.len(), 5);
    assert!(
        history
            .attempts
            .iter()
            .all(|attempt| attempt.job != id(5).to_hex()),
        "an open claim is not an ended attempt"
    );

    let period = |index: u32| {
        history
            .totals
            .by_period
            .iter()
            .find(|row| row.line == lane().to_hex() && row.period == index)
            .unwrap_or_else(|| panic!("period {index} has a total"))
    };
    // The ledger's own fold charges period 0 exactly what history totals for it: 700 for the
    // short run (through the closed arm's hold), 1,800 for the run billed past its reservation,
    // nothing for the refusal and the lost machine.
    assert_eq!(fold_charged(&fixture, 0), 700 + RESERVED);
    assert_eq!(period(0).sum.charged_secs, fold_charged(&fixture, 0));
    assert_eq!(period(0).sum.attempts, 4);
    assert_eq!(period(0).sum.lost_secs, 300);
    assert_eq!(period(0).sum.returned_secs, 4 * RESERVED - 700 - RESERVED);
    assert_eq!(period(0).start_ms, Some(fixture.periods[0].start_ms));
    assert_eq!(period(0).end_ms, Some(fixture.periods[0].end_ms));
    // The next period's unit counts there, and only there.
    assert_eq!(period(1).sum.charged_secs, fold_charged(&fixture, 1));
    assert_eq!(period(1).sum.charged_secs, 500);
    assert_eq!(history.totals.all.charged_secs, 700 + RESERVED + 500);

    // The other cuts of the same attempts add up to the same seconds.
    let by_family: u64 = history
        .totals
        .by_family
        .iter()
        .map(|row| row.sum.charged_secs)
        .sum();
    let by_machine: u64 = history
        .totals
        .by_machine
        .iter()
        .map(|row| row.sum.charged_secs)
        .sum();
    assert_eq!(by_family, history.totals.all.charged_secs);
    assert_eq!(by_machine, history.totals.all.charged_secs);
    // A lost machine's occupancy is unknown, never zero.
    let lost = history
        .attempts
        .iter()
        .find(|attempt| attempt.job == id(4).to_hex())
        .expect("the lost unit is history");
    assert_eq!(lost.occupied_secs, None);
    assert_eq!(lost.end, "box_lost");
    assert_eq!(history.totals.all.occupied_unknown, 1);
}

#[test]
fn an_agent_reads_only_the_attempts_it_reserved_and_their_totals() {
    let fixture = fixture();
    let inputs = HistoryInputs {
        jobs: &[],
        claims: &fixture.claims,
        periods: &fixture.periods,
        orders: &[],
        observations: &[],
        unattributed: &[],
    };
    let filter = request().filter().expect("a valid request");
    let own = project(&inputs, &filter, HistoryViewer::Requester(other_agent()));
    let jobs: Vec<&str> = own
        .attempts
        .iter()
        .map(|attempt| attempt.job.as_str())
        .collect();
    assert_eq!(jobs.len(), 2);
    assert!(jobs.contains(&id(3).to_hex().as_str()));
    assert!(jobs.contains(&id(4).to_hex().as_str()));
    assert_eq!(own.totals.all.attempts, 2);
    assert_eq!(own.totals.all.charged_secs, 0);
    assert_eq!(own.totals.all.lost_secs, 300);

    // A page of two, then the rest from its cursor: nothing twice, nothing left out.
    let owner_all = project(&inputs, &filter, HistoryViewer::Owner);
    let mut paged = JobHistoryRequest {
        limit: Some(2),
        ..request()
    };
    let mut seen = Vec::new();
    loop {
        let page = project(
            &inputs,
            &paged.filter().expect("a valid request"),
            HistoryViewer::Owner,
        );
        assert!(page.attempts.len() <= 2);
        assert_eq!(
            page.totals, owner_all.totals,
            "totals cover every attempt, not the page"
        );
        seen.extend(page.attempts.into_iter().map(|attempt| attempt.key));
        match page.next {
            Some(next) => paged.after = Some(next),
            None => break,
        }
    }
    let all: Vec<String> = owner_all
        .attempts
        .into_iter()
        .map(|attempt| attempt.key)
        .collect();
    assert_eq!(seen, all);
}

#[test]
fn a_line_unit_shows_the_meter_its_issuer_judged_and_keeps_its_claim_terminal() {
    let fixture = fixture();
    // The issuer's observation of the first settled unit's key: the same end the claim's
    // terminal took, with the issuer's meter verdict.
    let settled = &fixture.claims[0];
    let end = GpuJobTerminal {
        end: GpuJobEnd::Exited { code: 0 },
        measured_secs: Some(700),
        billed_secs: 700,
        meter: MeterVerdict::Agreed,
        machine: Some(machine()),
        device_id: Some("GPU-1f2e3d4c".to_owned()),
        outputs: Vec::new(),
    };
    let observations = [JobObservation {
        key: format!("{}:0", settled.id.to_hex()),
        machine: machine(),
        device_id: Some("GPU-1f2e3d4c".to_owned()),
        receipt: Vec::new(),
        epoch: "epoch-1".to_owned(),
        seq: 12,
        last_measured_secs: Some(700),
        observed_at_ms: ANCHOR_MS + 3_600_000,
        end_seen: None,
        meter: Some(MeterVerdict::Agreed),
        terminal: Some(end),
        started: true,
    }];
    let inputs = HistoryInputs {
        jobs: &[],
        claims: &fixture.claims,
        periods: &fixture.periods,
        orders: &[],
        observations: &observations,
        unattributed: &[],
    };
    let filter = request().filter().expect("a valid request");
    let history = project(&inputs, &filter, HistoryViewer::Owner);
    let unit = history
        .attempts
        .iter()
        .find(|attempt| attempt.job == settled.id.to_hex())
        .expect("the settled unit is history");
    assert_eq!(unit.meter.as_deref(), Some("agreed"));
    // The claim's terminal stays the record of the rest, as the line's fold charged it.
    assert_eq!(unit.occupied_secs, Some(700));
    assert_eq!(unit.charged_secs, Some(700));
    assert_eq!(unit.node_end.as_deref(), Some("exited(0)"));
    let metered = history
        .attempts
        .iter()
        .filter(|attempt| attempt.meter.is_some())
        .count();
    assert_eq!(metered, 1, "only the observed key has a meter");
}
