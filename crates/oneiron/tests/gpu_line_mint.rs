//! The lane economy's mint (design pass 32, sections 4.1 and 4.3; LE-1 = B,
//! LE-5 = A): one period record from the line as it stood and the outcomes
//! settled before the period began. The mint is pure, so these run without
//! a vault; the doors test pins the record's first-touch write.
//!
//! - The lane's numbers give the design's buckets: 32 h pinned, 64 h demand,
//!   a 3,600 s floor per family, a 219,600 s market pool and a 108,000 s
//!   pinned pool (section 4.1).
//! - In `floor_plus_market` mode (the default) the market pool is divided
//!   over every seated family; in `exclusive` mode over the demand families
//!   only.
//! - `payoff_share@1` gives a family with no history the lane's base rate,
//!   and follows confirmed wins per GPU-second.
//! - Invalid time is cost in the divisor when the line says so (the default)
//!   and nowhere otherwise; it never moves a win or a loss.
//! - Two mints of one line, period and tally give the same bytes.
//! - Astra pass-32 findings 6, 8 and 17: a late seat has no floor until the
//!   next mint, the record freezes the rung caps and the forecast rule, the
//!   policy's bounds hold before it is stored, and the arithmetic neither
//!   divides by a zero prior nor overflows.
use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    Bucket, FamilySeat, GpuLine, InvalidCost, LineInvalid, MAX_SEED_COST_SECS,
    MAX_SEED_ORIGIN_BYTES, MAX_SEED_WEIGHT_PERIODS, MAX_SEED_WINS, PayoffSeed, PeriodRoom,
    PinnedMode, RuleRef, SettledTally, Track, gpu_seconds, mint_period,
};

const ANCHOR_MS: u64 = 1_000;
const PERIOD_SECS: u64 = 1_209_600;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x01;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn seat(family: u8, track: Track) -> FamilySeat {
    FamilySeat {
        project: id(family),
        track,
        seed: None,
        admitted_by: Some(id(2)),
        admitted_at_ms: 0,
    }
}

/// The open-models lane's line: 96 GPU-hours a fortnight, a third pinned to
/// the interest track, two floor arms, rung caps of 30 min, 3 h and 48 h,
/// and `payoff_share@1`, with `seats` seated before period 0.
fn line(seats: Vec<FamilySeat>, mode: PinnedMode) -> GpuLine {
    GpuLine {
        project: id(1),
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        fleet_who: "open-models".to_owned(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        allowance_units: 345_600,
        pinned_track: Track::Interest,
        pinned_parts: (1, 3),
        pinned_mode: mode,
        floor_arms: 2,
        rung_caps_secs: vec![1_800, 10_800, 172_800],
        forecast_required: true,
        rules: vec![RuleRef::PAYOFF_SHARE_1],
        invalid_cost: InvalidCost::CountsAsCost,
        window_periods: 3,
        hosts: vec!["mel".to_owned()],
        families: seats,
        set_by: Some(id(2)),
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

fn ceilings(line: &GpuLine, tallies: &BTreeMap<EntityId, SettledTally>) -> Vec<(EntityId, u64)> {
    let record = mint_period(line, 0, tallies, ANCHOR_MS + 5).expect("the mint");
    assert_eq!(record.tables.len(), 1, "one rule in force: {record:?}");
    record.tables[0].ceilings.clone()
}

#[test]
fn the_lane_numbers_give_the_designed_buckets() {
    let record = mint_period(
        &line(five_families(), PinnedMode::FloorPlusMarket),
        0,
        &BTreeMap::new(),
        ANCHOR_MS + 5,
    )
    .expect("the mint");
    assert_eq!(record.allowance_units, 345_600);
    assert_eq!(record.pinned_units, 115_200, "32 GPU-hours pinned");
    assert_eq!(record.floor_units, 3_600, "two rung-1 caps a family");
    assert_eq!(record.floors.len(), 5);
    assert_eq!(
        record.pinned_pool_units(),
        108_000,
        "30 GPU-hours of pinned pool"
    );
    assert_eq!(
        record.tables[0].pool_units, 219_600,
        "61 GPU-hours of market pool"
    );
    assert_eq!(
        record.pinned_pool_units() + 5 * record.floor_units + record.tables[0].pool_units,
        record.allowance_units,
        "the buckets add up to the allowance"
    );
    assert_eq!(
        (record.start_ms, record.end_ms),
        (ANCHOR_MS, ANCHOR_MS + PERIOD_SECS * 1_000)
    );
}

#[test]
fn the_pinned_mode_decides_who_shares_the_market_pool() {
    // No history anywhere: every family scores the base rate.
    let shared = ceilings(
        &line(five_families(), PinnedMode::FloorPlusMarket),
        &BTreeMap::new(),
    );
    assert_eq!(
        shared,
        vec![
            (id(10), 43_920),
            (id(11), 43_920),
            (id(12), 43_920),
            (id(20), 43_920),
            (id(21), 43_920),
        ],
        "floor_plus_market: the interest families share the market pool too"
    );
    let exclusive = ceilings(
        &line(five_families(), PinnedMode::Exclusive),
        &BTreeMap::new(),
    );
    assert_eq!(
        exclusive,
        vec![(id(10), 73_200), (id(11), 73_200), (id(12), 73_200)],
        "exclusive: the market pool is the demand families' alone"
    );
}

#[test]
fn payoff_share_follows_confirmed_wins_per_gpu_second() {
    let mut lane = line(
        vec![
            seat(10, Track::Demand),
            seat(11, Track::Demand),
            seat(12, Track::Demand),
        ],
        PinnedMode::FloorPlusMarket,
    );
    // A market pool of 60,000 s: no pinned share, no floor.
    lane.allowance_units = 60_000;
    lane.pinned_parts = (0, 3);
    lane.floor_arms = 0;
    let tallies = BTreeMap::from([
        (
            id(10),
            SettledTally {
                wins: 2,
                losses: 1,
                cost_secs: 7_200,
                invalid_secs: 0,
            },
        ),
        (
            id(11),
            SettledTally {
                wins: 0,
                losses: 2,
                cost_secs: 7_200,
                invalid_secs: 0,
            },
        ),
    ]);
    // The lane's base rate is 14,400 s over 2 wins: 7,200 s a win. Scores:
    // 3/14,400, 1/14,400 and, for the unseen family 12, 1/7,200: the base
    // rate itself. The rounding remainder goes to the highest score.
    assert_eq!(
        ceilings(&lane, &tallies),
        vec![(id(10), 30_002), (id(11), 9_999), (id(12), 19_999)]
    );
}

#[test]
fn invalid_time_is_cost_only_when_the_line_counts_it() {
    let mut lane = line(
        vec![
            seat(10, Track::Demand),
            seat(11, Track::Demand),
            seat(12, Track::Demand),
        ],
        PinnedMode::FloorPlusMarket,
    );
    lane.allowance_units = 60_000;
    lane.pinned_parts = (0, 3);
    lane.floor_arms = 0;
    let tally = |wins, losses, cost_secs, invalid_secs| SettledTally {
        wins,
        losses,
        cost_secs,
        invalid_secs,
    };
    // Family 11 labelled 7,200 s of its GPU time invalid.
    let tallies = BTreeMap::from([
        (id(10), tally(2, 1, 7_200, 0)),
        (id(11), tally(0, 2, 7_200, 7_200)),
    ]);

    let counted = ceilings(&lane, &tallies);
    assert_eq!(
        counted,
        vec![(id(10), 33_452), (id(11), 7_964), (id(12), 18_584)],
        "counts_as_cost (LE-5 = A): the invalid seconds lower family 11's ceiling"
    );
    let record = mint_period(&lane, 0, &tallies, ANCHOR_MS + 5).expect("the mint");
    let eleven = record
        .inputs
        .iter()
        .find(|input| input.family == id(11))
        .expect("family 11");
    assert_eq!(
        (eleven.wins, eleven.losses),
        (0, 2),
        "invalid time moves no win or loss"
    );
    assert_eq!(eleven.invalid_secs, 7_200);

    lane.invalid_cost = InvalidCost::CountsNowhere;
    assert_eq!(
        ceilings(&lane, &tallies),
        vec![(id(10), 30_002), (id(11), 9_999), (id(12), 19_999)],
        "counts_nowhere: the ceilings are those of no invalid time"
    );
}

#[test]
fn the_mint_is_a_pure_function_of_the_line_and_the_settled_outcomes() {
    let lane = line(five_families(), PinnedMode::FloorPlusMarket);
    let tallies = BTreeMap::from([(
        id(12),
        SettledTally {
            wins: 1,
            losses: 3,
            cost_secs: 9_000,
            invalid_secs: 600,
        },
    )]);
    let first = mint_period(&lane, 2, &tallies, ANCHOR_MS + 7).expect("the first mint");
    let second = mint_period(&lane, 2, &tallies, ANCHOR_MS + 7).expect("the replay");
    assert_eq!(
        rmp_serde::to_vec_named(&first).expect("encodes"),
        rmp_serde::to_vec_named(&second).expect("encodes"),
        "the same line, period and outcomes give the same bytes"
    );
    assert_eq!(
        first.inputs_digest,
        oneiron::gpu_line::inputs_digest(&first.inputs)
    );
    assert_eq!(first.line_revision, 1);
    assert_eq!(
        (first.rung_caps_secs.as_slice(), first.forecast_required),
        (lane.rung_caps_secs.as_slice(), lane.forecast_required),
        "the record freezes the rung caps and the forecast rule it read"
    );
}

/// Finding 6: a seat counts from the first mint after it. In the period
/// already begun it has neither a floor nor a market ceiling, so it cannot
/// spend room that period's record promised elsewhere.
#[test]
fn a_late_seat_has_no_floor_until_the_next_mint() {
    let mut later = line(five_families(), PinnedMode::FloorPlusMarket);
    let (start_ms, _) = later.period_bounds(2).expect("period 2");
    later.families.push(FamilySeat {
        admitted_at_ms: start_ms + 1,
        ..seat(13, Track::Demand)
    });
    let same_period = mint_period(&later, 2, &BTreeMap::new(), start_ms + 7).expect("the mint");
    assert!(
        same_period.tables[0]
            .ceilings
            .iter()
            .all(|(family, _)| *family != id(13)),
        "no market ceiling in the period it joined"
    );
    assert_eq!(same_period.floor_of(&id(13)), 0, "no floor either");
    let room = PeriodRoom::fold(&same_period, &[]);
    assert_eq!(room.left(Bucket::Floor { family: id(13) }), 0);
    assert_eq!(
        room.left(Bucket::Floor { family: id(10) }),
        same_period.floor_units,
        "a family seated at the mint keeps its floor"
    );

    let next_period =
        mint_period(&later, 3, &BTreeMap::new(), start_ms + 7).expect("the next mint");
    assert_eq!(next_period.floor_of(&id(13)), next_period.floor_units);
    assert!(
        next_period.tables[0]
            .ceilings
            .iter()
            .any(|(family, _)| *family == id(13))
    );
}

/// Findings 6 and 17: the policy's bounds hold before a line is stored.
#[test]
fn a_line_keeps_its_bounds() {
    let lane = || line(five_families(), PinnedMode::FloorPlusMarket);
    assert_eq!(lane().validate(), Ok(()));

    let mut caps = lane();
    caps.rung_caps_secs = vec![1_800, 1_800, 172_800];
    assert_eq!(
        caps.validate(),
        Err(LineInvalid::RungCaps),
        "caps rise strictly"
    );
    caps.rung_caps_secs = vec![10_800, 1_800];
    assert_eq!(caps.validate(), Err(LineInvalid::RungCaps));

    let mut rules = lane();
    rules.rules = vec![
        RuleRef::PAYOFF_SHARE_1,
        RuleRef::EVEN_SPLIT_1,
        RuleRef::POSTERIOR_SAMPLING_1,
    ];
    assert_eq!(
        rules.validate(),
        Err(LineInvalid::Rules),
        "at most two rules"
    );

    let bounded = PayoffSeed {
        wins: MAX_SEED_WINS,
        losses: 0,
        cost_secs: MAX_SEED_COST_SECS,
        weight_periods: MAX_SEED_WEIGHT_PERIODS,
        origin: "ledger.jsonl sha256:00".to_owned(),
    };
    assert!(bounded.is_bounded());
    for unbounded in [
        PayoffSeed {
            wins: MAX_SEED_WINS + 1,
            ..bounded.clone()
        },
        PayoffSeed {
            cost_secs: MAX_SEED_COST_SECS + 1,
            ..bounded.clone()
        },
        PayoffSeed {
            weight_periods: 0,
            ..bounded.clone()
        },
        PayoffSeed {
            weight_periods: MAX_SEED_WEIGHT_PERIODS + 1,
            ..bounded.clone()
        },
        PayoffSeed {
            origin: "x".repeat(MAX_SEED_ORIGIN_BYTES + 1),
            ..bounded.clone()
        },
    ] {
        assert!(!unbounded.is_bounded(), "{unbounded:?}");
        let mut seeded = lane();
        seeded.families[0].seed = Some(unbounded);
        assert_eq!(seeded.validate(), Err(LineInvalid::Seed));
    }

    // 345,600 s with a third pinned: 230,400 s for the demand floors, 64
    // of 3,600 s; 115,200 s for the interest floors, 32 of them.
    let mut full = lane();
    full.families = (0..64)
        .map(|n| seat(100 + n, Track::Demand))
        .chain((0..32).map(|n| seat(200 + n, Track::Interest)))
        .collect();
    assert!(full.floors_fit());
    assert_eq!(full.validate(), Ok(()));
    let mut one_more = full.clone();
    one_more.families.push(seat(99, Track::Demand));
    assert_eq!(
        one_more.validate(),
        Err(LineInvalid::FloorsDoNotFit),
        "a demand floor is never paid from the pinned side"
    );
    let mut wider = full;
    wider.floor_arms = 3;
    assert_eq!(
        wider.validate(),
        Err(LineInvalid::FloorsDoNotFit),
        "a policy edit under which the seated floors no longer fit is refused"
    );
}

/// Finding 17: a lane whose wins cost almost nothing keeps a prior of at
/// least one second, so its scores stay finite and ordered.
#[test]
fn the_payoff_prior_is_at_least_one_second() {
    let mut lane = line(
        vec![seat(10, Track::Demand), seat(11, Track::Demand)],
        PinnedMode::FloorPlusMarket,
    );
    lane.allowance_units = 50_000;
    lane.pinned_parts = (0, 3);
    lane.floor_arms = 0;
    // Two wins for one second: the lane's cost per win rounds to zero, and
    // the prior is one second. Scores: 3/2 for family 10, 1/1 for 11.
    let tallies = BTreeMap::from([(
        id(10),
        SettledTally {
            wins: 2,
            losses: 0,
            cost_secs: 1,
            invalid_secs: 0,
        },
    )]);
    assert_eq!(
        ceilings(&lane, &tallies),
        vec![(id(10), 30_000), (id(11), 20_000)]
    );
}

/// Finding 17: numbers at the edge of the types neither overflow nor leave
/// a unit unaccounted for.
#[test]
fn the_mint_does_not_overflow_at_the_edge_of_its_numbers() {
    let mut lane = line(
        vec![seat(10, Track::Demand), seat(11, Track::Demand)],
        PinnedMode::FloorPlusMarket,
    );
    lane.allowance_units = u64::MAX;
    lane.pinned_parts = (0, 3);
    lane.floor_arms = 0;
    let tallies = BTreeMap::from([(
        id(10),
        SettledTally {
            wins: u64::MAX / 2,
            losses: 0,
            cost_secs: 1,
            invalid_secs: 0,
        },
    )]);
    let given = ceilings(&lane, &tallies);
    assert_eq!(
        given
            .iter()
            .map(|(_, units)| u128::from(*units))
            .sum::<u128>(),
        u128::from(u64::MAX),
        "every unit of the pool is a ceiling: {given:?}"
    );
    assert!(given[0].1 > given[1].1, "the winning family leads");
}
