//! The lane economy's draw order and charging rule (design pass 32, sections
//! 3.7 and 4.2; LE-1 = B): the pinned share is never drawn by a demand arm,
//! an interest arm draws its market ceiling only after the pinned pool and
//! never in exclusive mode, a family's floor goes before its market ceiling,
//! a settled unit frees its uncharged tail, and unused room never crosses a
//! period boundary. The fold is pure, so these run without a vault.
use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::gpu_line::{
    AllowanceHold, AllowanceTable, Bucket, Draw, DrawAsk, DrawPurpose, DrawSource, FamilyFloor,
    GpuLinePeriod, InvalidCost, PeriodRoom, PinnedMode, RuleRef, SpendRow, Track, UnitCharge,
    plan_draws,
};

const RUNG_1: u64 = 1_800;
const FLOOR: u64 = 2 * RUNG_1;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x01;
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

/// One period of the lane's numbers (96 GPU-hours, a third pinned to the
/// interest track), with one demand and one interest family and the given
/// market ceilings under `payoff_share@1`.
fn period(
    index: u32,
    mode: PinnedMode,
    demand_ceiling: u64,
    interest_ceiling: u64,
) -> GpuLinePeriod {
    let allowance = 345_600;
    let pinned = allowance / 3;
    let mut ceilings = vec![(demand(), demand_ceiling)];
    if mode == PinnedMode::FloorPlusMarket {
        ceilings.push((interest(), interest_ceiling));
    }
    ceilings.sort();
    GpuLinePeriod {
        project: lane(),
        index,
        start_ms: 1_000 + u64::from(index) * 1_209_600_000,
        end_ms: 1_000 + u64::from(index + 1) * 1_209_600_000,
        line_revision: 1,
        allowance_units: allowance,
        pinned_track: Track::Interest,
        pinned_mode: mode,
        pinned_units: pinned,
        floor_units: FLOOR,
        floors: vec![
            FamilyFloor {
                family: demand(),
                track: Track::Demand,
                units: FLOOR,
            },
            FamilyFloor {
                family: interest(),
                track: Track::Interest,
                units: FLOOR,
            },
        ],
        rung_caps_secs: vec![RUNG_1, 10_800, 172_800],
        forecast_required: true,
        invalid_cost: InvalidCost::CountsAsCost,
        inputs: Vec::new(),
        inputs_digest: String::new(),
        tables: vec![AllowanceTable {
            rule: RuleRef::PAYOFF_SHARE_1,
            pool_units: allowance - pinned - FLOOR,
            ceilings,
        }],
        minted_at_ms: 1_000 + u64::from(index) * 1_209_600_000,
    }
}

fn unit(
    arm: EntityId,
    family: EntityId,
    period: u32,
    draws: Vec<Draw>,
    charge: UnitCharge,
) -> SpendRow {
    SpendRow::Unit {
        arm,
        family,
        period,
        draws,
        charge,
    }
}

fn draw(source: DrawSource, units: u64) -> Draw {
    Draw { source, units }
}

fn market() -> DrawSource {
    DrawSource::Market {
        rule: RuleRef::PAYOFF_SHARE_1,
    }
}

fn ask(arm: EntityId, family: EntityId, track: Track, purpose: DrawPurpose, units: u64) -> DrawAsk {
    DrawAsk {
        arm,
        family,
        track,
        purpose,
        units,
    }
}

#[test]
fn the_pinned_share_is_never_drawn_by_a_demand_arm() {
    // The demand family's market ceiling is zero and its floor is spent; the
    // pinned pool is full.
    let record = period(0, PinnedMode::FloorPlusMarket, 0, 50_000);
    let spent_floor = unit(
        id(30),
        demand(),
        0,
        vec![draw(DrawSource::Floor, FLOOR)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &[spent_floor]);
    assert_eq!(room.left(Bucket::Pinned), record.pinned_pool_units());
    assert!(room.left(Bucket::Pinned) > 0);

    for purpose in [
        DrawPurpose::Unit { rung: 1 },
        DrawPurpose::Unit { rung: 2 },
        DrawPurpose::FirstAllowanceHold,
    ] {
        let denied = plan_draws(&room, &ask(id(31), demand(), Track::Demand, purpose, 600))
            .expect_err("a demand ask with its own buckets spent is refused");
        assert!(
            denied
                .room
                .iter()
                .all(|(bucket, _)| *bucket != Bucket::Pinned),
            "a demand ask never lists the pinned pool: {denied:?}"
        );
        assert_eq!(denied.fits, 0);
        assert_eq!(
            denied.short,
            Some(Bucket::Market {
                family: demand(),
                rule: RuleRef::PAYOFF_SHARE_1
            })
        );
    }
}

#[test]
fn an_interest_arm_draws_the_market_only_after_the_pinned_pool_is_spent() {
    let record = period(0, PinnedMode::FloorPlusMarket, 50_000, 5_000);
    let pool = record.pinned_pool_units();
    // Another interest arm leaves 1,000 s in the pinned pool.
    let other = unit(
        id(40),
        interest(),
        0,
        vec![draw(DrawSource::Pinned, pool - 1_000)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &[other]);
    assert_eq!(room.left(Bucket::Pinned), 1_000);

    let within = plan_draws(
        &room,
        &ask(
            id(41),
            interest(),
            Track::Interest,
            DrawPurpose::Unit { rung: 2 },
            800,
        ),
    )
    .expect("the pinned pool covers it");
    assert_eq!(
        within,
        vec![draw(DrawSource::Pinned, 800)],
        "the market is untouched while the pinned pool has room"
    );

    let past = plan_draws(
        &room,
        &ask(
            id(41),
            interest(),
            Track::Interest,
            DrawPurpose::Unit { rung: 2 },
            1_500,
        ),
    )
    .expect("the pinned pool, then the market ceiling");
    assert_eq!(
        past,
        vec![draw(DrawSource::Pinned, 1_000), draw(market(), 500)]
    );
}

#[test]
fn in_exclusive_mode_an_interest_arm_never_draws_the_market_pool() {
    let record = period(0, PinnedMode::Exclusive, 50_000, 0);
    let pool = record.pinned_pool_units();
    let other = unit(
        id(40),
        interest(),
        0,
        vec![draw(DrawSource::Pinned, pool - 1_000)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &[other]);
    let denied = plan_draws(
        &room,
        &ask(
            id(41),
            interest(),
            Track::Interest,
            DrawPurpose::Unit { rung: 2 },
            1_500,
        ),
    )
    .expect_err("the pinned pool is all an interest arm may draw");
    assert_eq!(denied.room, vec![(Bucket::Pinned, 1_000)]);
    assert_eq!(denied.short, Some(Bucket::Pinned));
    assert_eq!(denied.fits, 1_000);
}

#[test]
fn a_family_floor_is_spent_before_its_market_ceiling() {
    let record = period(0, PinnedMode::FloorPlusMarket, 10_000, 5_000);
    let empty = PeriodRoom::fold(&record, &[]);
    let first = plan_draws(
        &empty,
        &ask(
            id(50),
            demand(),
            Track::Demand,
            DrawPurpose::Unit { rung: 1 },
            RUNG_1,
        ),
    )
    .expect("the floor covers it");
    assert_eq!(first, vec![draw(DrawSource::Floor, RUNG_1)]);

    // 3,000 of the 3,600 s floor is spent: 600 from the floor, the rest from
    // the market ceiling.
    let spent = unit(
        id(51),
        demand(),
        0,
        vec![draw(DrawSource::Floor, 3_000)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &[spent]);
    let split = plan_draws(
        &room,
        &ask(
            id(50),
            demand(),
            Track::Demand,
            DrawPurpose::Unit { rung: 1 },
            RUNG_1,
        ),
    )
    .expect("floor, then market");
    assert_eq!(
        split,
        vec![draw(DrawSource::Floor, 600), draw(market(), 1_200)]
    );

    // An arm's own first-allowance hold goes before the floor.
    let held = SpendRow::Hold {
        arm: id(50),
        family: demand(),
        hold: AllowanceHold {
            period: 0,
            units: RUNG_1,
            draws: vec![draw(DrawSource::Floor, RUNG_1)],
        },
        arm_open: true,
    };
    let room = PeriodRoom::fold(&record, &[held]);
    assert_eq!(room.left(Bucket::FirstAllowance { arm: id(50) }), RUNG_1);
    assert_eq!(
        room.left(Bucket::Floor { family: demand() }),
        FLOOR - RUNG_1
    );
    let own = plan_draws(
        &room,
        &ask(
            id(50),
            demand(),
            Track::Demand,
            DrawPurpose::Unit { rung: 1 },
            1_000,
        ),
    )
    .expect("the arm's hold covers it");
    assert_eq!(own, vec![draw(DrawSource::FirstAllowance, 1_000)]);
}

#[test]
fn a_settled_unit_frees_the_tail_it_did_not_use() {
    let record = period(0, PinnedMode::FloorPlusMarket, 10_000, 5_000);
    let reserved = vec![draw(DrawSource::Floor, 1_000), draw(market(), 800)];
    let live = PeriodRoom::fold(
        &record,
        &[unit(
            id(60),
            demand(),
            0,
            reserved.clone(),
            UnitCharge::Live,
        )],
    );
    assert_eq!(live.left(Bucket::Floor { family: demand() }), FLOOR - 1_000);
    let market_bucket = Bucket::Market {
        family: demand(),
        rule: RuleRef::PAYOFF_SHARE_1,
    };
    assert_eq!(live.left(market_bucket), 10_000 - 800);

    // Settled 1,200 of 1,800: the floor draw first, then 200 of the market.
    let settled = PeriodRoom::fold(
        &record,
        &[unit(
            id(60),
            demand(),
            0,
            reserved.clone(),
            UnitCharge::Settled(1_200),
        )],
    );
    assert_eq!(
        settled.left(Bucket::Floor { family: demand() }),
        FLOOR - 1_000
    );
    assert_eq!(settled.left(market_bucket), 10_000 - 200);

    // A box-lost or released unit charges nothing.
    let void = PeriodRoom::fold(
        &record,
        &[unit(id(60), demand(), 0, reserved, UnitCharge::Void)],
    );
    assert_eq!(void.left(Bucket::Floor { family: demand() }), FLOOR);
    assert_eq!(void.left(market_bucket), 10_000);

    // A closed arm's hold keeps only what its units took from it.
    let hold = SpendRow::Hold {
        arm: id(61),
        family: demand(),
        hold: AllowanceHold {
            period: 0,
            units: RUNG_1,
            draws: vec![draw(DrawSource::Floor, RUNG_1)],
        },
        arm_open: false,
    };
    let used = unit(
        id(61),
        demand(),
        0,
        vec![draw(DrawSource::FirstAllowance, RUNG_1)],
        UnitCharge::Settled(700),
    );
    let closed = PeriodRoom::fold(&record, &[hold, used]);
    assert_eq!(closed.left(Bucket::Floor { family: demand() }), FLOOR - 700);
    assert_eq!(closed.left(Bucket::FirstAllowance { arm: id(61) }), 0);
}

#[test]
fn unused_room_does_not_cross_a_period_boundary() {
    // Period 0 leaves most of its room unused, and an arm admitted in it
    // still holds its first allowance.
    let first = period(0, PinnedMode::FloorPlusMarket, 10_000, 5_000);
    let rows = vec![
        SpendRow::Hold {
            arm: id(70),
            family: demand(),
            hold: AllowanceHold {
                period: 0,
                units: RUNG_1,
                draws: vec![draw(DrawSource::Floor, RUNG_1)],
            },
            arm_open: true,
        },
        unit(
            id(71),
            interest(),
            0,
            vec![draw(DrawSource::Pinned, 4_000)],
            UnitCharge::Settled(1_000),
        ),
    ];
    let old = PeriodRoom::fold(&first, &rows);
    assert_eq!(old.left(Bucket::Pinned), first.pinned_pool_units() - 1_000);

    // Period 1 opens with exactly its own buckets: nothing carried, nothing
    // owed, and the old hold gives the arm no first-allowance room.
    let second = period(1, PinnedMode::FloorPlusMarket, 12_000, 6_000);
    let new = PeriodRoom::fold(&second, &rows);
    assert_eq!(new.left(Bucket::Pinned), second.pinned_pool_units());
    assert_eq!(new.left(Bucket::Floor { family: demand() }), FLOOR);
    assert_eq!(new.left(Bucket::Floor { family: interest() }), FLOOR);
    assert_eq!(
        new.left(Bucket::Market {
            family: demand(),
            rule: RuleRef::PAYOFF_SHARE_1
        }),
        12_000
    );
    assert_eq!(new.left(Bucket::FirstAllowance { arm: id(70) }), 0);
    let total = new.left(Bucket::Pinned)
        + new.left(Bucket::Floor { family: demand() })
        + new.left(Bucket::Floor { family: interest() })
        + second.tables[0].pool_units;
    assert_eq!(
        total, second.allowance_units,
        "the buckets add up to the period's allowance"
    );
}

/// Astra pass-32 finding 12: an arm's market rule is a seeded assignment
/// that never looks at which rule still has room. Swapping the two rules'
/// ceilings for the family leaves every arm's rule as it was, and the rule's
/// own ceiling then admits or refuses the draw.
#[test]
fn the_market_rule_is_assigned_without_looking_at_room() {
    let two_rules = |payoff_ceiling: u64, even_ceiling: u64| {
        let mut record = period(0, PinnedMode::FloorPlusMarket, payoff_ceiling, 0);
        let pool = record.tables[0].pool_units / 2;
        record.tables[0].pool_units = pool;
        record.tables.push(AllowanceTable {
            rule: RuleRef::EVEN_SPLIT_1,
            pool_units: pool,
            ceilings: vec![(demand(), even_ceiling)],
        });
        PeriodRoom::fold(&record, &[])
    };
    let payoff_only = two_rules(50_000, 0);
    let even_only = two_rules(0, 50_000);
    let mut assigned = BTreeSet::new();
    for n in 60..90 {
        let arm = id(n);
        let rule = payoff_only
            .market_rule(&arm)
            .expect("two rules are in force");
        assert_eq!(
            even_only.market_rule(&arm),
            Some(rule),
            "arm {n}: the rule does not follow the room"
        );
        assigned.insert(rule);
        let room = if rule == RuleRef::PAYOFF_SHARE_1 {
            &even_only
        } else {
            &payoff_only
        };
        let denied = plan_draws(
            room,
            &ask(
                arm,
                demand(),
                Track::Demand,
                DrawPurpose::Unit { rung: 2 },
                600,
            ),
        )
        .expect_err("the assigned rule has no room here, and no other rule is drawn");
        assert_eq!(
            denied.short,
            Some(Bucket::Market {
                family: demand(),
                rule
            })
        );
    }
    assert_eq!(
        assigned,
        BTreeSet::from([RuleRef::PAYOFF_SHARE_1, RuleRef::EVEN_SPLIT_1]),
        "the seed spreads the arms over both rules"
    );
}
