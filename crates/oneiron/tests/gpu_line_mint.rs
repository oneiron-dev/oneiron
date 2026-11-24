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
//! - A new idea is funded in its first period and the next, then lapses.
//! - The record carries the policy it was minted under and the allocation the
//!   installer installs; its economic digest leaves out the mint time.
use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    BudgetPolicy, DrawStep, FamilySeat, GpuLine, Graduation, InvalidCost, LineInvalid, MintError,
    PeriodClockError, PinnedMode, RuleRef, SettledTally, Side, Track, defaults, economic_digest,
    gpu_seconds, line_allocation_id, mint_period, period_balances,
};

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

/// The lane's line under the default budget policy: 96 GPU-hours a
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
            ..BudgetPolicy::default()
        },
        families: seats,
        set_by: None,
        set_at_ms: 0,
        revision: 1,
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
    base.validate().expect("the lane's line is valid");
    let refused = |change: &dyn Fn(&mut GpuLine), expected: LineInvalid| {
        let mut lane = base.clone();
        change(&mut lane);
        assert_eq!(lane.validate(), Err(expected.clone()), "{expected}");
    };
    let accepted = |change: &dyn Fn(&mut GpuLine)| {
        let mut lane = base.clone();
        change(&mut lane);
        lane.validate().expect("inside the bounds");
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
        &|lane| lane.budget.rules = vec![RuleRef::EVEN_SPLIT_1],
        LineInvalid::RuleNotBuilt(MintError::RuleNotBuilt(RuleRef::EVEN_SPLIT_1)),
    );
    refused(&|lane| lane.budget.window_periods = 0, LineInvalid::Window);
    refused(&|lane| lane.budget.window_periods = 27, LineInvalid::Window);
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
    // The defaults are the lane's numbers, read in one place.
    assert_eq!(BudgetPolicy::default().seat_cap, defaults::SEAT_CAP);
    assert_eq!(defaults::SEAT_CAP, 6);
    assert_eq!(defaults::NEW_IDEA_SLOTS_PER_PERIOD, 4);
    assert_eq!(defaults::REVIEW_CHECK_SECS, 600);
    assert_eq!(defaults::HOLD_TTL_SECS, 259_200);
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
        lane.validate(),
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
        lane.validate(),
        Err(LineInvalid::Unfunded {
            side: Side::Unpinned
        })
    );
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
    assert_eq!(idea.lapses_from(), Some(4));

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
