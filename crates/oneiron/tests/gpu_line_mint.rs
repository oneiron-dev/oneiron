//! The lane economy's mint (design pass 32 r2, sections 3.1, 3.2 and 4.1 to
//! 4.3; LE-1 = B, LE-5 = A, LE-6): one period record from the line as it
//! stood and its inputs. The mint is pure, so these run without a vault; the
//! doors test pins the record's first-touch write.
//!
//! - The lane's numbers give the design's pools: with three demand and two
//!   interest seats, a 104,400 s pinned pool and a 201,600 s market pool
//!   beside a 3,600 s reserve a side and a 14,400 s new-idea pool.
//! - `floor_plus_market` divides the market pool over every demand and
//!   interest seat, `exclusive` over the unpinned side's; a new idea never.
//! - `payoff_share@1` follows confirmed wins per GPU-second with a prior that
//!   is never zero and largest-remainder rounding; invalid time is cost only
//!   when the line counts it.
//! - T39: empty and extreme inputs neither divide by zero nor lose a second.
//! - T40: a period is fourteen days of milliseconds, half-open; a time before
//!   the anchor is refused.
//! - The bounds of section 3.1, and a policy the seats cannot fund, are
//!   refused before a line is stored.
//! - A new idea is funded in its first period and the next, then lapses;
//!   the bounds count only the seats the next mint funds.
//! - The record carries the policy it was minted under and the allocation the
//!   installer installs; its economic digest leaves out the mint time.
//! - T26, T27: the two allowance rules divide equal halves and conserve every
//!   second; the cohort blocks hold two arms of each rule and read no room.
use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    AllowanceRule, BudgetPolicy, DrawStep, FamilyPayoff, FamilySeat, GpuLine, Graduation,
    InvalidCost, LineInvalid, MintError, PeriodClockError, PinnedMode, RuleRef, SettledTally, Side,
    Track, cohort_rule, defaults, economic_digest, gpu_seconds, line_allocation_id, mint_period,
    payoff_share, period_balances, posterior_sampling,
};
use oneiron::llm::run_admission::LeaseUnit;

const ANCHOR_MS: u64 = 1_000;
const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const FLOOR: u64 = 3_600;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x01;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn seat(family: u8, track: Track) -> FamilySeat {
    FamilySeat {
        seat: id(family.wrapping_add(100)),
        project: id(family),
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

/// The open-models lane's preset (pass 34, 3.3; EM-21): the lane's own
/// document, which its kit passes to `vault.gpu.lines.set`. The engine's own
/// defaults are neutral.
fn open_models() -> BudgetPolicy {
    BudgetPolicy {
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
        ..BudgetPolicy::default()
    }
}

/// The lane's line under the open-models preset: 96 GPU-hours a
/// fortnight, a third pinned to the interest track, two floor arms.
fn line(seats: Vec<FamilySeat>, mode: PinnedMode) -> GpuLine {
    GpuLine {
        project: id(1),
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: vec!["rack-4090".to_owned()],
        machines: Vec::new(),
        leads: Vec::new(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            pinned_mode: mode,
            ..open_models()
        },
        families: seats,
        set_by: None,
        set_at_ms: 0,
        revision: 1,
        preset: None,
    }
}

/// Three demand families (10, 11, 12) and two interest families (20, 21).
fn five_families() -> Vec<FamilySeat> {
    vec![
        seat(10, Track::Demand),
        seat(11, Track::Demand),
        seat(12, Track::Demand),
        seat(20, Track::Interest),
        seat(21, Track::Interest),
    ]
}

/// Three demand families sharing a 60,000 s market pool: no pinned share,
/// no floor, no reserve, no new-idea pool.
fn market_only() -> GpuLine {
    let mut lane = line(
        vec![
            seat(10, Track::Demand),
            seat(11, Track::Demand),
            seat(12, Track::Demand),
        ],
        PinnedMode::FloorPlusMarket,
    );
    lane.budget.allowance_units = 60_000;
    lane.budget.pinned_parts = (0, 3);
    lane.budget.floor_arms = 0;
    lane.budget.rung_caps_secs = vec![1_800, 10_800, 60_000];
    lane
}

fn tally(wins: u64, losses: u64, cost_secs: u64, invalid_secs: u64) -> SettledTally {
    SettledTally {
        wins,
        losses,
        cost_secs,
        invalid_secs,
    }
}

fn ceilings(line: &GpuLine, tallies: &BTreeMap<EntityId, SettledTally>) -> Vec<(EntityId, u64)> {
    mint_period(line, 0, tallies, ANCHOR_MS + 5)
        .expect("the mint")
        .tables[0]
        .ceilings
        .clone()
}

#[test]
fn the_lane_numbers_give_the_designed_pools() {
    let record = mint_period(
        &line(five_families(), PinnedMode::FloorPlusMarket),
        0,
        &BTreeMap::new(),
        ANCHOR_MS + 5,
    )
    .expect("the mint");
    assert_eq!(record.pinned_units, 115_200, "32 h pinned");
    assert_eq!(record.unpinned_units, 230_400, "64 h unpinned");
    assert_eq!(record.reserve, (FLOOR, FLOOR));
    assert_eq!(record.new_idea_pool, 14_400, "four slots of one floor");
    assert_eq!(record.pinned_pool, 104_400, "29 h");
    assert_eq!(record.market_pool, 201_600, "56 h");
    assert_eq!(record.floors.len(), 5);
    assert!(record.floors.iter().all(|floor| floor.units == FLOOR));
    assert_eq!(record.split_remainder, 0);
    assert_eq!(record.tables[0].unallocated, 0);
    assert!(period_balances(&record), "the pools sum to the allowance");
}

#[test]
fn the_pinned_mode_decides_who_shares_the_market_pool() {
    let mut seats = five_families();
    seats.push(seat(30, Track::NewIdea));
    let families = |mode| -> Vec<EntityId> {
        ceilings(&line(seats.clone(), mode), &BTreeMap::new())
            .into_iter()
            .map(|(family, _)| family)
            .collect()
    };
    assert_eq!(
        families(PinnedMode::FloorPlusMarket),
        vec![id(10), id(11), id(12), id(20), id(21)],
        "floor_plus_market: every demand and interest seat, no new idea"
    );
    assert_eq!(
        families(PinnedMode::Exclusive),
        vec![id(10), id(11), id(12)],
        "exclusive: the unpinned side only"
    );
}

#[test]
fn payoff_share_follows_confirmed_wins_per_gpu_second() {
    let tallies = BTreeMap::from([
        (id(10), tally(2, 1, 7_200, 0)),
        (id(11), tally(0, 2, 7_200, 0)),
    ]);
    // The base rate is 14,400 s over 2 wins: 7,200 s a win, above the rung-1
    // cap. Weights 3/14,400, 1/14,400 and, for the unseen family 12, 1/7,200:
    // the base rate itself. Rounding down leaves two seconds, which go to the
    // two largest remainders.
    assert_eq!(
        ceilings(&market_only(), &tallies),
        vec![(id(10), 30_000), (id(11), 10_000), (id(12), 20_000)]
    );
}

#[test]
fn invalid_time_is_cost_only_when_the_line_counts_it() {
    let mut lane = market_only();
    // Family 11 labelled 7,200 s of its GPU time invalid.
    let tallies = BTreeMap::from([
        (id(10), tally(2, 1, 7_200, 0)),
        (id(11), tally(0, 2, 7_200, 7_200)),
    ]);
    let counted = ceilings(&lane, &tallies);
    assert!(
        counted[1].1 < 10_000,
        "counts_as_cost (LE-5 = A): the invalid seconds lower family 11's ceiling: {counted:?}"
    );
    assert_eq!(counted.iter().map(|(_, units)| units).sum::<u64>(), 60_000);
    let record = mint_period(&lane, 0, &tallies, ANCHOR_MS + 5).expect("the mint");
    let eleven = record
        .inputs
        .iter()
        .find(|input| input.family == id(11))
        .expect("family 11");
    assert_eq!(
        (eleven.wins, eleven.losses, eleven.invalid_secs),
        (0, 2, 7_200),
        "invalid time moves no win or loss"
    );

    lane.budget.invalid_cost = InvalidCost::CountsNowhere;
    assert_eq!(
        ceilings(&lane, &tallies),
        vec![(id(10), 30_000), (id(11), 10_000), (id(12), 20_000)],
        "counts_nowhere: the ceilings of no invalid time"
    );
}

#[test]
fn the_mint_is_a_pure_function_of_the_line_and_its_inputs() {
    let lane = line(five_families(), PinnedMode::FloorPlusMarket);
    let tallies = BTreeMap::from([(id(12), tally(1, 3, 9_000, 600))]);
    let first = mint_period(&lane, 2, &tallies, ANCHOR_MS + 7).expect("the first mint");
    let later = mint_period(&lane, 2, &tallies, ANCHOR_MS + 2 * PERIOD_MS + 9)
        .expect("the same mint, later");
    assert_ne!(first.minted_at_ms, later.minted_at_ms);
    assert_eq!(
        first.economic_digest, later.economic_digest,
        "the mint time is outside the economic digest"
    );
    assert_eq!(first.economic_digest, economic_digest(&first));
    let other = mint_period(
        &lane,
        2,
        &BTreeMap::from([(id(12), tally(2, 3, 9_000, 600))]),
        ANCHOR_MS + 7,
    )
    .expect("a mint with one more win");
    assert_ne!(first.economic_digest, other.economic_digest);
}

/// The record is the policy version of its period, and names the allocation
/// the installer installs: one id per line, one generation per period.
#[test]
fn the_record_carries_its_policy_and_its_allocation() {
    let lane = line(five_families(), PinnedMode::FloorPlusMarket);
    let record = mint_period(&lane, 3, &BTreeMap::new(), ANCHOR_MS + 3 * PERIOD_MS).expect("mint");
    assert_eq!(record.policy, lane.budget);
    assert_eq!(record.line_revision, lane.revision);
    assert_eq!(record.inputs_cutoff_ms, record.start_ms);
    assert_eq!(record.allocation.wallet, lane.wallet);
    assert_eq!(record.allocation.id, line_allocation_id(&lane.project));
    assert_eq!(record.allocation.generation, 4);
    assert_eq!(record.allocation.units, 345_600);
    assert_eq!(record.cohort_seed, None, "one rule: no cohort");
    assert_eq!(record.cohort_seed_commit, None);
}

/// T39.
#[test]
fn the_mint_survives_empty_and_extreme_inputs() {
    // No family: the whole market pool is unallocated.
    let empty = mint_period(
        &line(Vec::new(), PinnedMode::FloorPlusMarket),
        0,
        &BTreeMap::new(),
        ANCHOR_MS,
    )
    .expect("a line with no seat mints");
    assert!(empty.tables[0].ceilings.is_empty());
    assert_eq!(empty.tables[0].unallocated, empty.market_pool);
    assert!(period_balances(&empty));

    // Zero history everywhere: equal ceilings, the odd seconds to the lowest
    // ids, nothing lost.
    let mut lane = market_only();
    lane.budget.allowance_units = 60_001;
    let even = ceilings(&lane, &BTreeMap::new());
    assert_eq!(
        even,
        vec![(id(10), 20_001), (id(11), 20_000), (id(12), 20_000)]
    );

    // A win with zero cost: the prior is the rung-1 cap, never zero.
    let free_win = ceilings(
        &market_only(),
        &BTreeMap::from([(id(10), tally(1, 0, 0, 0))]),
    );
    assert!(free_win[0].1 > free_win[1].1);
    assert_eq!(free_win.iter().map(|(_, units)| units).sum::<u64>(), 60_000);

    // The bounds of section 3.1: the largest allowance, a million wins at
    // zero cost beside a family whose cost is the whole window at that
    // allowance. Every family keeps a ceiling above zero and the table
    // conserves every second.
    let mut lane = market_only();
    lane.budget.allowance_units = 1 << 40;
    lane.budget.window_periods = 26;
    let tallies = BTreeMap::from([
        (id(10), tally(1_000_000, 0, 0, 0)),
        (id(11), tally(0, 1_000_000, 26 << 40, 1 << 40)),
    ]);
    let record = mint_period(&lane, 0, &tallies, ANCHOR_MS).expect("the mint at the bounds");
    let table = &record.tables[0];
    assert!(
        table.ceilings.iter().all(|(_, units)| *units > 0),
        "no positive weight truncates to zero: {:?}",
        table.ceilings
    );
    assert_eq!(
        table.ceilings.iter().map(|(_, units)| units).sum::<u64>() + table.unallocated,
        table.pool_units
    );
    assert!(period_balances(&record));
}

/// T40.
#[test]
fn a_period_is_fourteen_days_of_milliseconds() {
    let lane = line(five_families(), PinnedMode::FloorPlusMarket);
    assert_eq!(lane.period_ms(), Some(14 * 24 * 60 * 60 * 1_000));
    assert_eq!(lane.period_index(ANCHOR_MS), Ok(0));
    assert_eq!(lane.period_index(ANCHOR_MS + PERIOD_MS - 1), Ok(0));
    assert_eq!(lane.period_index(ANCHOR_MS + PERIOD_MS), Ok(1));
    assert_eq!(
        lane.period_index(ANCHOR_MS - 1),
        Err(PeriodClockError::NotBegun),
        "a time before the anchor is refused"
    );
    assert_eq!(
        lane.period_index(ANCHOR_MS + (u64::from(u32::MAX) + 1) * PERIOD_MS),
        Err(PeriodClockError::OutOfRange)
    );
    assert_eq!(
        lane.period_bounds(1),
        Some((ANCHOR_MS + PERIOD_MS, ANCHOR_MS + 2 * PERIOD_MS))
    );
    let record = mint_period(&lane, 1, &BTreeMap::new(), ANCHOR_MS + PERIOD_MS).expect("mint");
    assert_eq!(
        (record.start_ms, record.end_ms),
        (ANCHOR_MS + PERIOD_MS, ANCHOR_MS + 2 * PERIOD_MS),
        "half-open: the end is the next period's start"
    );
}

#[test]
fn a_line_keeps_its_bounds() {
    let base = line(five_families(), PinnedMode::FloorPlusMarket);
    base.validate(0).expect("the lane's line is valid");
    let refused = |change: &dyn Fn(&mut GpuLine), expected: LineInvalid| {
        let mut lane = base.clone();
        change(&mut lane);
        assert_eq!(lane.validate(0), Err(expected.clone()), "{expected}");
    };
    let accepted = |change: &dyn Fn(&mut GpuLine)| {
        let mut lane = base.clone();
        change(&mut lane);
        lane.validate(0).expect("inside the bounds");
    };
    refused(&|lane| lane.period_secs = 3_599, LineInvalid::Period);
    accepted(&|lane| lane.period_secs = 3_600);
    refused(&|lane| lane.period_secs = 31_536_001, LineInvalid::Period);
    refused(
        &|lane| lane.budget.allowance_units = 0,
        LineInvalid::Allowance,
    );
    refused(
        &|lane| lane.budget.allowance_units = (1 << 40) + 1,
        LineInvalid::Allowance,
    );
    refused(
        &|lane| lane.budget.pinned_parts = (1, 1),
        LineInvalid::PinnedParts,
    );
    refused(
        &|lane| lane.budget.pinned_parts = (1, 1_001),
        LineInvalid::PinnedParts,
    );
    refused(
        &|lane| lane.budget.pinned_track = Track::NewIdea,
        LineInvalid::PinnedTrack,
    );
    refused(
        &|lane| lane.budget.rung_caps_secs = Vec::new(),
        LineInvalid::RungCaps,
    );
    refused(
        &|lane| lane.budget.rung_caps_secs = vec![1; 9],
        LineInvalid::RungCaps,
    );
    refused(
        &|lane| lane.budget.rung_caps_secs = vec![0, 10],
        LineInvalid::RungCaps,
    );
    refused(
        &|lane| lane.budget.rung_caps_secs = vec![1_800, 900],
        LineInvalid::RungCaps,
    );
    refused(
        &|lane| lane.budget.rung_caps_secs = vec![1_800, 345_601],
        LineInvalid::RungCaps,
    );
    accepted(&|lane| lane.budget.rung_caps_secs = vec![1_800, 1_800, 172_800]);
    refused(&|lane| lane.budget.floor_arms = 65, LineInvalid::FloorArms);
    refused(
        &|lane| lane.budget.new_idea_slots_per_period = 65,
        LineInvalid::NewIdeaSlots,
    );
    refused(&|lane| lane.budget.rules = Vec::new(), LineInvalid::Rules);
    refused(
        &|lane| lane.budget.rules = vec![RuleRef::PAYOFF_SHARE_1, RuleRef::PAYOFF_SHARE_1],
        LineInvalid::Rules,
    );
    refused(
        &|lane| {
            lane.budget.rules = vec![
                RuleRef::PAYOFF_SHARE_1,
                RuleRef::EVEN_SPLIT_1,
                RuleRef::POSTERIOR_SAMPLING_1,
            ];
        },
        LineInvalid::Rules,
    );
    refused(
        &|lane| {
            lane.budget.rules = vec![RuleRef {
                rule: AllowanceRule::EvenSplit,
                version: 2,
            }];
        },
        LineInvalid::RuleNotBuilt(MintError::RuleNotBuilt(RuleRef {
            rule: AllowanceRule::EvenSplit,
            version: 2,
        })),
    );
    refused(&|lane| lane.budget.window_periods = 0, LineInvalid::Window);
    refused(&|lane| lane.budget.window_periods = 27, LineInvalid::Window);
    refused(
        &|lane| lane.budget.posterior_max_slots = 0,
        LineInvalid::PosteriorSampling,
    );
    refused(
        &|lane| lane.budget.posterior_max_slots = 4_097,
        LineInvalid::PosteriorSampling,
    );
    refused(
        &|lane| lane.budget.posterior_max_evidence = 0,
        LineInvalid::PosteriorSampling,
    );
    refused(
        &|lane| lane.budget.posterior_max_evidence = 1_024,
        LineInvalid::PosteriorSampling,
    );
    accepted(&|lane| {
        lane.budget.posterior_max_slots = 1;
        lane.budget.posterior_max_evidence = 1;
    });
    accepted(&|lane| {
        lane.budget.posterior_max_slots = 4_096;
        lane.budget.posterior_max_evidence = 1_023;
    });
    refused(
        &|lane| {
            lane.budget.draw_orders.pop();
        },
        LineInvalid::DrawOrders,
    );
    refused(
        &|lane| lane.budget.draw_orders[0].first_rung.push(DrawStep::Floor),
        LineInvalid::DrawOrders,
    );
    refused(
        &|lane| lane.budget.draw_orders[0].first_rung.rotate_left(1),
        LineInvalid::DrawOrders,
    );
    refused(
        &|lane| {
            lane.budget.draw_orders[0]
                .later_rungs
                .insert(0, DrawStep::FirstAllowance)
        },
        LineInvalid::DrawOrders,
    );
    accepted(&|lane| {
        lane.budget.draw_orders[0]
            .later_rungs
            .insert(0, DrawStep::Pinned)
    });
    refused(
        &|lane| lane.offers.push(" ".to_owned()),
        LineInvalid::Offers,
    );
    refused(
        &|lane| lane.offers.push("rack-4090".to_owned()),
        LineInvalid::Offers,
    );
    refused(
        &|lane| lane.machines = vec![id(2), id(2)],
        LineInvalid::Machines,
    );
    refused(&|lane| lane.leads = vec![id(3), id(3)], LineInvalid::Roles);
    refused(
        &|lane| lane.budget.new_idea_periods = 0,
        LineInvalid::NewIdeaPeriods,
    );
    refused(
        &|lane| {
            lane.unit = serde_json::from_value(serde_json::json!("GPU seconds")).expect("raw");
        },
        LineInvalid::Unit,
    );
    accepted(&|lane| lane.unit = LeaseUnit::new("gpu_24g_seconds").expect("a unit name"));
}

/// Pass 34, 3.1 (EM-21): the engine ships only neutral defaults. A line
/// that states only its period, allowance and rung caps pins nothing, funds
/// no floor, no reserve and no new-idea slot, and the owner seats every
/// family; its whole allowance is a market over its families.
#[test]
fn the_engines_own_defaults_fund_no_pinned_share_no_floor_and_no_slot() {
    let neutral = BudgetPolicy::default();
    assert_eq!(
        (neutral.allowance_units, neutral.rung_caps_secs.len()),
        (0, 0),
        "no engine default for the allowance or the rung caps"
    );
    assert_eq!(neutral.pinned_parts, (0, 1));
    assert_eq!(
        (
            neutral.floor_arms,
            neutral.seat_reserve_floors,
            neutral.new_idea_slots_per_period
        ),
        (0, 0, 0)
    );
    assert_eq!((neutral.seat_cap, neutral.pinned_seat_cap), (0, 0));
    assert_eq!(
        (neutral.review_check_secs, neutral.max_running_per_family),
        (0, 0)
    );
    assert!(!neutral.forecast_required);
    assert_eq!(neutral.forecast_score_after, 20);
    assert_eq!(neutral.window_periods, 1);
    assert_eq!(neutral.draw_orders, defaults::draw_orders());

    let mut lane = line(
        vec![seat(10, Track::Demand), seat(11, Track::Demand)],
        PinnedMode::FloorPlusMarket,
    );
    lane.budget = neutral;
    assert_eq!(lane.validate(0), Err(LineInvalid::Allowance));
    lane.budget.allowance_units = 100_000;
    assert_eq!(lane.validate(0), Err(LineInvalid::RungCaps));
    lane.budget.rung_caps_secs = vec![3_600];
    lane.validate(0)
        .expect("the period, allowance and caps are all a line must state");
    let record = mint_period(&lane, 0, &BTreeMap::new(), ANCHOR_MS).expect("mint");
    assert_eq!((record.pinned_units, record.pinned_pool), (0, 0));
    assert!(record.floors.iter().all(|floor| floor.units == 0));
    assert_eq!((record.reserve, record.new_idea_pool), ((0, 0), 0));
    assert_eq!(
        record.market_pool, 100_000,
        "the whole allowance is the market"
    );
    assert_eq!(
        record.tables[0].ceilings,
        vec![(id(10), 50_000), (id(11), 50_000)]
    );
}

/// `policy_unfunded`: a policy whose seated families' floors and reserve do
/// not fit their own side is refused, and the mint of such a line refuses
/// too (`mint_blocked`) rather than take from the other side.
#[test]
fn every_floor_fits_its_own_side_of_the_allowance() {
    let mut lane = line(five_families(), PinnedMode::FloorPlusMarket);
    // Two interest floors and the reserve need 10,800 s of a 9,000 s
    // pinned side; the unpinned side has plenty.
    lane.budget.pinned_parts = (25, 960);
    assert_eq!(lane.budget.pinned_units(), 9_000);
    assert_eq!(
        lane.validate(0),
        Err(LineInvalid::Unfunded { side: Side::Pinned })
    );
    assert_eq!(
        mint_period(&lane, 0, &BTreeMap::new(), ANCHOR_MS),
        Err(MintError::Blocked { side: Side::Pinned })
    );
    // Eight new-idea slots on a 40,000 s unpinned side: three floors, the
    // reserve and 28,800 s of slots need 43,200 s.
    let mut lane = line(five_families(), PinnedMode::FloorPlusMarket);
    lane.budget.allowance_units = 60_000;
    lane.budget.rung_caps_secs = vec![1_800, 10_800, 60_000];
    lane.budget.new_idea_slots_per_period = 8;
    assert_eq!(
        lane.validate(0),
        Err(LineInvalid::Unfunded {
            side: Side::Unpinned
        })
    );
}

/// Review round 1 of #10398: the bounds a policy keeps count the seats of the
/// first mint it applies to. A new idea seated for period 0 is funded in
/// periods 0 and 1, so in period 1 a policy with no new-idea slots is valid
/// from period 2 on, which lists the seat no more.
#[test]
fn the_slot_bound_counts_only_the_seats_the_next_mint_funds() {
    let mut lane = line(vec![seat(30, Track::NewIdea)], PinnedMode::FloorPlusMarket);
    lane.budget.new_idea_slots_per_period = 1;
    lane.validate(1).expect("one slot holds the one new idea");
    assert_eq!((lane.new_idea_seats(1), lane.new_idea_seats(2)), (1, 0));
    lane.budget.new_idea_slots_per_period = 0;
    assert_eq!(
        lane.validate(1),
        Err(LineInvalid::NewIdeaSlots),
        "period 1 still lists the seat"
    );
    lane.validate(2)
        .expect("the seat lapses before period 2's mint");
}

/// LE-6: a new idea is funded in the period it was seated and the next one;
/// the mint after that lists it no more unless it graduated, and a lapsed
/// seat is never listed again.
#[test]
fn a_new_idea_seat_lapses_at_the_mint_after_its_second_period() {
    let mut idea = seat(30, Track::NewIdea);
    idea.effective_from_period = 3;
    idea.late_floor = Some((2, FLOOR));
    let listed = |seat: &FamilySeat, index| {
        let lane = line(vec![seat.clone()], PinnedMode::FloorPlusMarket);
        mint_period(&lane, index, &BTreeMap::new(), ANCHOR_MS)
            .expect("mint")
            .seats
            .iter()
            .any(|at| at.family == id(30))
    };
    assert_eq!(idea.first_funded_period(), 2);
    assert!(listed(&idea, 3), "funded in its second period");
    assert!(!listed(&idea, 4), "lapsed at the next mint");
    assert_eq!(idea.lapses_from(2), Some(4));

    let mut graduated = idea.clone();
    graduated.track = Track::Demand;
    graduated.graduated = Some(Graduation {
        from: Track::NewIdea,
        by: None,
        at_ms: ANCHOR_MS,
        arm: id(90),
        rung: 1,
    });
    assert!(listed(&graduated, 4), "a graduated seat stays");
    let lane = line(vec![graduated], PinnedMode::FloorPlusMarket);
    let record = mint_period(&lane, 4, &BTreeMap::new(), ANCHOR_MS).expect("mint");
    assert_eq!(record.floor_of(&id(30)), FLOOR, "a floor of its new kind");
    assert_eq!(record.tables[0].ceilings.len(), 1, "and a market ceiling");

    let mut marked = idea;
    marked.lapsed_from_period = Some(4);
    marked.track = Track::Demand;
    assert!(!listed(&marked, 5), "a lapsed seat is never listed again");
}

/// T26: a family with no history scores exactly the base rate.
#[test]
fn payoff_share_gives_an_unseen_family_the_base_rate() {
    let seen = FamilyPayoff {
        family: id(10),
        wins: 2,
        losses: 0,
        cost_secs: 7_200,
        invalid_secs: 0,
    };
    let unseen = FamilyPayoff {
        family: id(11),
        wins: 0,
        losses: 0,
        cost_secs: 0,
        invalid_secs: 0,
    };
    // The prior is max(1_800, 7_200 / 2) = 3_600, so the seen family's weight
    // (2 + 1) / (7_200 + 3_600) equals the unseen family's 1 / 3_600.
    assert_eq!(
        payoff_share(10_000, &[&seen, &unseen], 1_800, InvalidCost::CountsAsCost),
        (vec![(id(10), 5_000), (id(11), 5_000)], 0)
    );
}

/// T27: with two rules each rule divides one half of an odd market pool, and
/// every table conserves its half.
#[test]
fn both_rules_divide_equal_halves_and_conserve_every_second() {
    for rival in [RuleRef::EVEN_SPLIT_1, RuleRef::POSTERIOR_SAMPLING_1] {
        let mut lane = line(five_families(), PinnedMode::FloorPlusMarket);
        lane.budget.rules = vec![RuleRef::PAYOFF_SHARE_1, rival];
        let tallies = BTreeMap::from([
            (id(10), tally(3, 1, 9_000, 0)),
            (id(11), tally(0, 2, 3_600, 600)),
            (id(12), tally(1, 0, 0, 0)),
            (id(20), tally(5, 5, 18_000, 1_200)),
            (id(21), tally(0, 0, 1_800, 0)),
        ]);
        let mut record = mint_period(&lane, 0, &tallies, ANCHOR_MS + 5).expect("the mint");
        if record.market_pool % 2 == 0 {
            lane.budget.allowance_units += 1;
            record = mint_period(&lane, 0, &tallies, ANCHOR_MS + 5).expect("the mint");
        }
        assert_eq!(record.market_pool % 2, 1, "the market pool is odd");
        assert_eq!(record.tables.len(), 2);
        for table in &record.tables {
            assert_eq!(table.pool_units, record.market_pool / 2);
            let given: u64 = table.ceilings.iter().map(|(_, units)| *units).sum();
            assert_eq!(given + table.unallocated, table.pool_units);
        }
        assert_eq!(record.split_remainder, 1);
        assert!(period_balances(&record));
        assert_eq!(record.cohort_seed, None, "the store draws the seed");
        assert_eq!(record.cohort_seed_commit, None);
        let table = record
            .tables
            .iter()
            .find(|table| table.rule == rival)
            .expect("the rival's table");
        if rival == RuleRef::EVEN_SPLIT_1 {
            let families = table.ceilings.len() as u64;
            assert_eq!(families, 5);
            assert!(
                table
                    .ceilings
                    .iter()
                    .all(|(_, units)| *units == table.pool_units / families),
                "every ceiling is an equal share: {:?}",
                table.ceilings
            );
            assert!(table.unallocated < families);
        } else {
            let slots = (table.pool_units / 1_800).min(4_096);
            let slot_secs = table.pool_units / slots;
            assert!(
                table
                    .ceilings
                    .iter()
                    .all(|(_, units)| *units % slot_secs == 0),
                "every ceiling is whole slots: {:?}",
                table.ceilings
            );
        }
    }
}

#[test]
fn posterior_sampling_reads_wins_and_losses_and_no_cost() {
    let policy = open_models();
    let winner = FamilyPayoff {
        family: id(10),
        wins: 40,
        losses: 0,
        cost_secs: 7_200,
        invalid_secs: 0,
    };
    let loser = FamilyPayoff {
        family: id(11),
        wins: 0,
        losses: 40,
        cost_secs: 3_600,
        invalid_secs: 600,
    };
    let pool = 4_096 * 1_800;
    let first = posterior_sampling(
        pool,
        &[&winner, &loser],
        &policy,
        &id(1),
        0,
        RuleRef::POSTERIOR_SAMPLING_1,
    );
    let again = posterior_sampling(
        pool,
        &[&winner, &loser],
        &policy,
        &id(1),
        0,
        RuleRef::POSTERIOR_SAMPLING_1,
    );
    assert_eq!(first, again, "the same call twice gives the same result");
    let winner_other_cost = FamilyPayoff {
        family: id(10),
        wins: 40,
        losses: 0,
        cost_secs: 99_000,
        invalid_secs: 9_000,
    };
    let loser_other_cost = FamilyPayoff {
        family: id(11),
        wins: 0,
        losses: 40,
        cost_secs: 0,
        invalid_secs: 0,
    };
    let no_cost = posterior_sampling(
        pool,
        &[&winner_other_cost, &loser_other_cost],
        &policy,
        &id(1),
        0,
        RuleRef::POSTERIOR_SAMPLING_1,
    );
    assert_eq!(first, no_cost, "cost changes nothing");
    let (ceilings, unallocated) = &first;
    let won = ceilings
        .iter()
        .find(|(family, _)| *family == id(10))
        .expect("the winner")
        .1;
    let lost = ceilings
        .iter()
        .find(|(family, _)| *family == id(11))
        .expect("the loser")
        .1;
    assert!(won > lost, "the 40-win family wins more slots");
    assert_eq!(
        ceilings.iter().map(|(_, units)| *units).sum::<u64>() + *unallocated,
        pool
    );
    let (small, small_unallocated) = posterior_sampling(
        1_799,
        &[&winner, &loser],
        &policy,
        &id(1),
        0,
        RuleRef::POSTERIOR_SAMPLING_1,
    );
    assert!(
        small.iter().all(|(_, units)| *units == 0),
        "below the first rung every ceiling is zero"
    );
    assert_eq!(small_unallocated, 1_799);
    let mut capped = policy.clone();
    capped.posterior_max_slots = 8;
    let (few, _) = posterior_sampling(
        pool,
        &[&winner, &loser],
        &capped,
        &id(1),
        0,
        RuleRef::POSTERIOR_SAMPLING_1,
    );
    assert!(
        few.iter().all(|(_, units)| *units % (pool / 8) == 0),
        "eight slots: every ceiling is a multiple of pool / 8: {few:?}"
    );
}

#[test]
fn a_cohort_block_holds_two_arms_of_each_rule_and_reads_no_room() {
    let mut lane = line(five_families(), PinnedMode::FloorPlusMarket);
    lane.budget.rules = vec![RuleRef::PAYOFF_SHARE_1, RuleRef::EVEN_SPLIT_1];
    let mut record = mint_period(&lane, 0, &BTreeMap::new(), ANCHOR_MS + 5).expect("the mint");
    record.cohort_seed = Some([7; 32]);
    for track in [Track::Demand, Track::Interest] {
        for position in 0..16 {
            assert!(
                cohort_rule(&record, track, position).is_some(),
                "{track:?} position {position} has a cohort"
            );
        }
        for block in 0..4 {
            let mut first = 0;
            let mut second = 0;
            for offset in 0..4 {
                match cohort_rule(&record, track, block * 4 + offset) {
                    Some(rule) if rule == RuleRef::PAYOFF_SHARE_1 => first += 1,
                    Some(rule) if rule == RuleRef::EVEN_SPLIT_1 => second += 1,
                    other => panic!("{track:?} block {block}: no such rule: {other:?}"),
                }
            }
            assert_eq!((first, second), (2, 2), "{track:?} block {block}");
        }
    }
    let mut other_room = record.clone();
    for table in &mut other_room.tables {
        table.pool_units += 1_000;
        table.unallocated += 1_000;
        for (_, ceiling) in &mut table.ceilings {
            *ceiling += 5;
        }
    }
    for track in [Track::Demand, Track::Interest] {
        for position in 0..16 {
            assert_eq!(
                cohort_rule(&record, track, position),
                cohort_rule(&other_room, track, position),
                "{track:?} position {position} reads no room"
            );
        }
    }
    assert_eq!(cohort_rule(&record, Track::NewIdea, 0), None);
    let mut no_seed = record.clone();
    no_seed.cohort_seed = None;
    assert_eq!(cohort_rule(&no_seed, Track::Demand, 0), None);
    let mut one_rule = mint_period(
        &line(five_families(), PinnedMode::FloorPlusMarket),
        0,
        &BTreeMap::new(),
        ANCHOR_MS + 5,
    )
    .expect("a one-rule mint");
    one_rule.cohort_seed = Some([7; 32]);
    assert_eq!(cohort_rule(&one_rule, Track::Demand, 0), None);
    let mut other_seed = record.clone();
    other_seed.cohort_seed = Some([8; 32]);
    let first: Vec<_> = (0..64)
        .map(|position| cohort_rule(&record, Track::Demand, position))
        .collect();
    let second: Vec<_> = (0..64)
        .map(|position| cohort_rule(&other_seed, Track::Demand, position))
        .collect();
    assert_ne!(first, second, "another seed moves a block");
}
