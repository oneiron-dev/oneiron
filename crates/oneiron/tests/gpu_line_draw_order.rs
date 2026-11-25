//! The lane economy's draw order and charging rule (design pass 32 r2,
//! sections 3.8 and 4.2; LE-1 = B, LE-6), on period records the mint makes
//! from the lane's default policy:
//!
//! - T2: the pinned share is never drawn by a demand arm, not through a
//!   floor and not through the reserve.
//! - T3: an interest arm draws the market only after the pinned pool; a
//!   mixed-source claim that settles short returns each tail to its own pool.
//! - T3b: exclusive mode keeps an interest arm out of the market.
//! - T4: a family's floor is spent before its market ceiling.
//! - T5: unused room does not cross a period boundary.
//! - T37: every pool conserves its seconds through mixed draws, partial
//!   settlements, cancels, releases, hold ends, late seats and a roll-over.
//! - T62 (draw-plan half): a new-idea arm draws its hold and its slot only,
//!   at rung 1 only.
//! - Review round 1: whatever the order names, the pinned pool pays only the
//!   pinned track, and a new idea draws nothing past rung 1.
//!
//! The fold is pure, so these run without a vault. Fleet command:
//! `cargo test --locked -p oneiron --all-features --test gpu_line_draw_order`.
use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    AllowanceHold, Bucket, BudgetPolicy, Draw, DrawAsk, DrawPurpose, DrawSource, DrawStep,
    FamilySeat, GpuLine, GpuLinePeriod, PeriodRoom, PinnedMode, RuleRef, Side, SpendRow, Track,
    UnitCharge, gpu_seconds, mint_period, plan_draws,
};

const RUNG_1: u64 = 1_800;
const FLOOR: u64 = 2 * RUNG_1;
const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000;
/// The lane's allowance and its pinned third.
const ALLOWANCE: u64 = 345_600;
const PINNED: u64 = ALLOWANCE / 3;
/// With one demand and one interest seat: the pinned share less one floor
/// and the pinned side's reserve.
const PINNED_POOL: u64 = PINNED - FLOOR - FLOOR;
/// The unpinned side less one floor, its reserve and the new-idea pool.
const MARKET_POOL: u64 = ALLOWANCE - PINNED - FLOOR - FLOOR - 4 * FLOOR;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x01;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn seat_id(family: EntityId) -> EntityId {
    let mut bytes = *family.as_bytes();
    bytes[0] = 0x02;
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
fn new_idea() -> EntityId {
    id(30)
}

/// A seat effective from `effective`, with the late floor it took, if any.
fn seat(
    family: EntityId,
    track: Track,
    effective: u32,
    late_floor: Option<(u32, u64)>,
) -> FamilySeat {
    FamilySeat {
        seat: seat_id(family),
        project: family,
        track,
        replaces: None,
        graduated: None,
        lapsed_from_period: None,
        effective_from_period: effective,
        late_floor,
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

/// The lane's line under the open-models preset (96 GPU-hours a
/// fortnight, a third pinned to the interest track) in `mode`.
fn line(mode: PinnedMode, families: Vec<FamilySeat>) -> GpuLine {
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
            pinned_mode: mode,
            ..open_models()
        },
        families,
        set_by: None,
        set_at_ms: 0,
        revision: 1,
        preset: None,
    }
}

/// One demand and one interest family, seated before period 0.
fn two_families(mode: PinnedMode) -> GpuLine {
    line(
        mode,
        vec![
            seat(demand(), Track::Demand, 0, None),
            seat(interest(), Track::Interest, 0, None),
        ],
    )
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

fn market_of(family: EntityId) -> Bucket {
    Bucket::Market {
        family,
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
fn the_lane_record_has_the_designed_pools() {
    let record = minted(&two_families(PinnedMode::FloorPlusMarket), 0);
    assert_eq!(record.pinned_units, PINNED);
    assert_eq!(record.unpinned_units, ALLOWANCE - PINNED);
    assert_eq!(record.reserve, (FLOOR, FLOOR));
    assert_eq!(record.new_idea_pool, 4 * FLOOR);
    assert_eq!(record.pinned_pool, PINNED_POOL);
    assert_eq!(record.market_pool, MARKET_POOL);
    assert_eq!(
        record.tables[0].ceilings,
        vec![(demand(), MARKET_POOL / 2), (interest(), MARKET_POOL / 2)]
    );
}

/// T2.
#[test]
fn the_pinned_share_is_never_drawn_by_a_demand_arm() {
    // A demand seat asked after the mint took the unpinned side's reserve.
    let late = id(11);
    let mut line = two_families(PinnedMode::FloorPlusMarket);
    line.families
        .push(seat(late, Track::Demand, 1, Some((0, FLOOR))));
    let record = minted(&two_families(PinnedMode::FloorPlusMarket), 0);
    // The demand family's floor and market ceiling are spent; the pinned
    // pool is full.
    let spent = [
        unit(
            id(40),
            demand(),
            0,
            vec![draw(DrawSource::Floor, FLOOR)],
            UnitCharge::Live,
        ),
        unit(
            id(40),
            demand(),
            0,
            vec![draw(market(), MARKET_POOL / 2)],
            UnitCharge::Live,
        ),
        unit(
            id(41),
            late,
            0,
            vec![draw(DrawSource::Floor, FLOOR)],
            UnitCharge::Live,
        ),
    ];
    let room = PeriodRoom::fold(&record, &line.families, &spent);
    assert_eq!(room.left(Bucket::Pinned), PINNED_POOL);
    assert_eq!(
        room.reserve_left(Side::Pinned),
        FLOOR,
        "a demand seat never takes the pinned side's reserve"
    );
    assert_eq!(room.reserve_left(Side::Unpinned), 0);

    for family in [demand(), late] {
        for purpose in [
            DrawPurpose::Unit { rung: 1 },
            DrawPurpose::Unit { rung: 2 },
            DrawPurpose::FirstAllowanceHold,
        ] {
            let denied = plan_draws(&room, &ask(id(42), family, Track::Demand, purpose, 600))
                .expect_err("a demand ask with its own buckets spent is refused");
            assert!(
                denied
                    .room
                    .iter()
                    .all(|(bucket, _)| *bucket != Bucket::Pinned),
                "a demand ask never lists the pinned pool: {denied:?}"
            );
            assert_eq!(denied.fits, 0);
            assert_eq!(denied.short, Some(market_of(family)));
        }
    }
}

/// T3.
#[test]
fn an_interest_arm_draws_the_market_only_after_the_pinned_pool() {
    let line = two_families(PinnedMode::FloorPlusMarket);
    let record = minted(&line, 0);
    // Another interest arm leaves 1,000 s in the pinned pool.
    let other = unit(
        id(40),
        interest(),
        0,
        vec![draw(DrawSource::Pinned, PINNED_POOL - 1_000)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &line.families, std::slice::from_ref(&other));
    assert_eq!(room.left(Bucket::Pinned), 1_000);

    let rung_2 = |units| {
        ask(
            id(41),
            interest(),
            Track::Interest,
            DrawPurpose::Unit { rung: 2 },
            units,
        )
    };
    let within = plan_draws(&room, &rung_2(800)).expect("the pinned pool covers it");
    assert_eq!(
        within,
        vec![draw(DrawSource::Pinned, 800)],
        "the market is untouched while the pinned pool has room"
    );
    let mixed = plan_draws(&room, &rung_2(1_500)).expect("the pinned pool, then the market");
    assert_eq!(
        mixed,
        vec![draw(DrawSource::Pinned, 1_000), draw(market(), 500)]
    );

    // The mixed claim settles 1,200 of 1,500: the pinned draw is charged
    // whole and 200 of the market draw; the market's tail returns there.
    let settled = |secs| {
        PeriodRoom::fold(
            &record,
            &line.families,
            &[
                other.clone(),
                unit(
                    id(41),
                    interest(),
                    0,
                    mixed.clone(),
                    UnitCharge::Settled(secs),
                ),
            ],
        )
    };
    let long = settled(1_200);
    assert_eq!(long.left(Bucket::Pinned), 0);
    assert_eq!(long.left(market_of(interest())), MARKET_POOL / 2 - 200);
    // Settled at 700: the pinned pool gets 300 back, the market all 500.
    let short = settled(700);
    assert_eq!(short.left(Bucket::Pinned), 300);
    assert_eq!(short.left(market_of(interest())), MARKET_POOL / 2);
}

/// T3b.
#[test]
fn exclusive_mode_keeps_an_interest_arm_out_of_the_market() {
    let line = two_families(PinnedMode::Exclusive);
    let record = minted(&line, 0);
    assert_eq!(
        record.tables[0].ceilings,
        vec![(demand(), MARKET_POOL)],
        "exclusive mode divides the market over the unpinned side only"
    );
    let other = unit(
        id(40),
        interest(),
        0,
        vec![draw(DrawSource::Pinned, PINNED_POOL - 1_000)],
        UnitCharge::Live,
    );
    let room = PeriodRoom::fold(&record, &line.families, &[other]);
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
    assert_eq!(
        denied.room,
        vec![(Bucket::Pinned, 1_000), (market_of(interest()), 0)]
    );
    assert_eq!(denied.fits, 1_000);
}

/// T4.
#[test]
fn a_family_floor_is_spent_before_its_market_ceiling() {
    let line = two_families(PinnedMode::FloorPlusMarket);
    let record = minted(&line, 0);
    let rung_1 = |units| {
        ask(
            id(50),
            demand(),
            Track::Demand,
            DrawPurpose::Unit { rung: 1 },
            units,
        )
    };
    let empty = PeriodRoom::fold(&record, &line.families, &[]);
    let first = plan_draws(&empty, &rung_1(RUNG_1)).expect("the floor covers it");
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
    let room = PeriodRoom::fold(&record, &line.families, &[spent]);
    let split = plan_draws(&room, &rung_1(RUNG_1)).expect("floor, then market");
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
    let room = PeriodRoom::fold(&record, &line.families, &[held]);
    assert_eq!(room.left(Bucket::FirstAllowance { arm: id(50) }), RUNG_1);
    assert_eq!(
        room.left(Bucket::Floor { family: demand() }),
        FLOOR - RUNG_1
    );
    let own = plan_draws(&room, &rung_1(1_000)).expect("the arm's hold covers it");
    assert_eq!(own, vec![draw(DrawSource::FirstAllowance, 1_000)]);
}

#[test]
fn a_settled_unit_frees_the_tail_it_did_not_use() {
    let line = two_families(PinnedMode::FloorPlusMarket);
    let record = minted(&line, 0);
    let ceiling = MARKET_POOL / 2;
    let reserved = vec![draw(DrawSource::Floor, 1_000), draw(market(), 800)];
    let fold = |charge| {
        PeriodRoom::fold(
            &record,
            &line.families,
            &[unit(id(60), demand(), 0, reserved.clone(), charge)],
        )
    };
    let live = fold(UnitCharge::Live);
    assert_eq!(live.left(Bucket::Floor { family: demand() }), FLOOR - 1_000);
    assert_eq!(live.left(market_of(demand())), ceiling - 800);

    // Settled 1,200 of 1,800: the floor draw first, then 200 of the market.
    let settled = fold(UnitCharge::Settled(1_200));
    assert_eq!(
        settled.left(Bucket::Floor { family: demand() }),
        FLOOR - 1_000
    );
    assert_eq!(settled.left(market_of(demand())), ceiling - 200);

    // A box-lost or released unit charges nothing.
    let void = fold(UnitCharge::Void);
    assert_eq!(void.left(Bucket::Floor { family: demand() }), FLOOR);
    assert_eq!(void.left(market_of(demand())), ceiling);

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
    let closed = PeriodRoom::fold(&record, &line.families, &[hold, used]);
    assert_eq!(closed.left(Bucket::Floor { family: demand() }), FLOOR - 700);
    assert_eq!(closed.left(Bucket::FirstAllowance { arm: id(61) }), 0);
}

/// T5.
#[test]
fn unused_room_does_not_cross_a_period_boundary() {
    let line = two_families(PinnedMode::FloorPlusMarket);
    // Period 0 leaves most of its room unused, and an arm admitted in it
    // still holds its first allowance.
    let first = minted(&line, 0);
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
    let old = PeriodRoom::fold(&first, &line.families, &rows);
    assert_eq!(old.left(Bucket::Pinned), PINNED_POOL - 1_000);

    // Period 1 opens with exactly its own pools: nothing carried, nothing
    // owed, and the old hold gives the arm no first-allowance room.
    let second = minted(&line, 1);
    let new = PeriodRoom::fold(&second, &line.families, &rows);
    assert_eq!(new.left(Bucket::Pinned), PINNED_POOL);
    assert_eq!(new.left(Bucket::Floor { family: demand() }), FLOOR);
    assert_eq!(new.left(Bucket::Floor { family: interest() }), FLOOR);
    assert_eq!(new.left(market_of(demand())), MARKET_POOL / 2);
    assert_eq!(new.left(Bucket::FirstAllowance { arm: id(70) }), 0);
    assert_eq!(new.reserve_left(Side::Pinned), FLOOR);
    assert_eq!(new.reserve_left(Side::Unpinned), FLOOR);
    let total = new.left(Bucket::Pinned)
        + new.left(Bucket::Floor { family: demand() })
        + new.left(Bucket::Floor { family: interest() })
        + new.reserve_left(Side::Pinned)
        + new.reserve_left(Side::Unpinned)
        + second.new_idea_pool
        + second.tables[0].pool_units
        + second.split_remainder;
    assert_eq!(total, ALLOWANCE, "the pools add up to the allowance");
}

/// T62, the draw-plan half: a new-idea arm's order is its hold and its slot,
/// at rung 1 only. Graduation and the reserve door's refusal are rows M2-E
/// and M2-C.
#[test]
fn a_new_idea_arm_never_draws_the_pinned_or_the_market_pool() {
    let late = id(31);
    let mut line = two_families(PinnedMode::FloorPlusMarket);
    line.families
        .push(seat(new_idea(), Track::NewIdea, 0, None));
    let record = minted(&line, 0);
    assert_eq!(record.floor_of(&new_idea()), FLOOR, "one slot is one floor");
    assert!(
        record.tables[0]
            .ceilings
            .iter()
            .all(|(family, _)| *family != new_idea()),
        "a new idea has no market ceiling"
    );
    // A second new idea asked after the mint takes a slot at once.
    line.families
        .push(seat(late, Track::NewIdea, 1, Some((0, FLOOR))));
    let room = PeriodRoom::fold(&record, &line.families, &[]);
    assert_eq!(room.new_idea_slots_taken(), 2);
    assert_eq!(room.left(Bucket::Pinned), PINNED_POOL);

    for family in [new_idea(), late] {
        let rung = |rung, units| {
            ask(
                id(80),
                family,
                Track::NewIdea,
                DrawPurpose::Unit { rung },
                units,
            )
        };
        assert_eq!(
            plan_draws(&room, &rung(1, RUNG_1)).expect("the slot covers a rung-1 unit"),
            vec![draw(DrawSource::Floor, RUNG_1)]
        );
        let past = plan_draws(&room, &rung(1, FLOOR + 1)).expect_err("the slot is all it draws");
        assert_eq!(
            past.room,
            vec![
                (Bucket::FirstAllowance { arm: id(80) }, 0),
                (Bucket::Floor { family }, FLOOR)
            ],
            "no pinned and no market bucket in a new idea's order"
        );
        let higher = plan_draws(&room, &rung(2, 1)).expect_err("rung 2 is refused outright");
        assert_eq!(higher.short, None);
        assert!(higher.room.is_empty());
        assert_eq!(higher.fits, 0);
    }
}

/// Review round 1 of #10398: whatever a valid policy's draw orders name, the
/// pinned pool pays only the policy's pinned track, and a new idea draws
/// nothing past rung 1 (section 4.2, `new_idea_rung_one_only`).
#[test]
fn a_configured_order_never_widens_the_pinned_pool_or_a_new_idea() {
    // The pinned share pays the demand track; interest keeps the default
    // order, which names the pinned pool.
    let mut line = two_families(PinnedMode::FloorPlusMarket);
    line.budget.pinned_track = Track::Demand;
    let record = minted(&line, 0);
    let room = PeriodRoom::fold(&record, &line.families, &[]);
    assert!(room.left(Bucket::Pinned) > 0, "the pinned pool has room");
    let unpinned = ask(
        id(41),
        interest(),
        Track::Interest,
        DrawPurpose::Unit { rung: 2 },
        1,
    );
    assert_eq!(
        plan_draws(&room, &unpinned).expect("the market covers it"),
        vec![draw(market(), 1)],
        "an arm off the pinned track never draws the pinned pool"
    );

    // A new-idea order that names the slot at later rungs too.
    let mut line = two_families(PinnedMode::FloorPlusMarket);
    line.families
        .push(seat(new_idea(), Track::NewIdea, 0, None));
    for order in &mut line.budget.draw_orders {
        if order.track == Track::NewIdea {
            order.later_rungs = vec![DrawStep::Floor];
        }
    }
    let record = minted(&line, 0);
    let room = PeriodRoom::fold(&record, &line.families, &[]);
    assert_eq!(room.left(Bucket::Floor { family: new_idea() }), FLOOR);
    let higher = plan_draws(
        &room,
        &ask(
            id(80),
            new_idea(),
            Track::NewIdea,
            DrawPurpose::Unit { rung: 2 },
            1,
        ),
    )
    .expect_err("rung 2 is refused outright");
    assert_eq!((higher.short, higher.fits), (None, 0));
    assert!(higher.room.is_empty());
}

/// A small deterministic generator for T37.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

/// Every bucket of `room`'s period for `families`.
fn buckets(families: &[(EntityId, Track)]) -> Vec<Bucket> {
    let mut buckets = vec![Bucket::Pinned];
    for (family, _) in families {
        buckets.push(Bucket::Floor { family: *family });
        buckets.push(market_of(*family));
    }
    buckets
}

/// The period's pools summed as the fold sees them: every floor (late ones
/// included), what each side's reserve and the new-idea pool still hold, the
/// pinned pool, every table and the split remainder.
fn pools_total(room: &PeriodRoom, families: &[(EntityId, Track)]) -> u64 {
    let record = room.period();
    let floors: u64 = families
        .iter()
        .map(|(family, _)| room.capacity(Bucket::Floor { family: *family }))
        .sum();
    let slots_left =
        record.new_idea_pool - record.floor_secs() * room.new_idea_slots_taken() as u64;
    let tables: u64 = record
        .tables
        .iter()
        .map(|table| table.ceilings.iter().map(|(_, units)| units).sum::<u64>() + table.unallocated)
        .sum();
    floors
        + room.reserve_left(Side::Pinned)
        + room.reserve_left(Side::Unpinned)
        + slots_left
        + record.pinned_pool
        + tables
        + record.split_remainder
}

/// T37: section 3.8 after every kind of row. For every pool, what the rows
/// charge never passes what the period minted, so `minted = free +
/// earmarked + reserved + charged`; the pools always sum to the allowance,
/// a late seat moving a floor out of its side's reserve; and the next
/// period opens with every pool free.
#[test]
fn every_pool_conserves_its_seconds() {
    let families = [
        (id(10), Track::Demand),
        (id(11), Track::Demand),
        (id(20), Track::Interest),
        (id(30), Track::NewIdea),
        // Asked after the mint: a floor from each side's reserve, a slot.
        (id(12), Track::Demand),
        (id(21), Track::Interest),
        (id(31), Track::NewIdea),
    ];
    let mut seats: Vec<FamilySeat> = families[..4]
        .iter()
        .map(|(family, track)| seat(*family, *track, 0, None))
        .collect();
    let line = line(PinnedMode::FloorPlusMarket, seats.clone());
    let record = minted(&line, 0);
    seats.extend(
        families[4..]
            .iter()
            .map(|(family, track)| seat(*family, *track, 1, Some((0, FLOOR)))),
    );
    let next = minted(&line, 1);

    for run in 1..=24u64 {
        let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15 ^ run);
        let mut rows: Vec<SpendRow> = Vec::new();
        // One hold per arm (M2-B refuses a second), and each arm is one
        // family's.
        let mut held: Vec<EntityId> = Vec::new();
        for step in 0..60u8 {
            let room = PeriodRoom::fold(&record, &seats, &rows);
            let which = rng.below(families.len() as u64);
            let (family, track) = families[which as usize];
            let arm = id(100 + 10 * which as u8 + rng.below(3) as u8);
            let hold = rng.below(5) == 0 && !held.contains(&arm);
            let purpose = if hold {
                DrawPurpose::FirstAllowanceHold
            } else {
                DrawPurpose::Unit {
                    rung: 1 + rng.below(2) as u8,
                }
            };
            let units = 1 + rng.below(3 * RUNG_1);
            let Ok(draws) = plan_draws(&room, &ask(arm, family, track, purpose, units)) else {
                continue;
            };
            rows.push(if hold {
                held.push(arm);
                SpendRow::Hold {
                    arm,
                    family,
                    hold: AllowanceHold {
                        period: 0,
                        units,
                        draws,
                    },
                    // A hold that ended keeps only what units took from it.
                    arm_open: rng.below(3) != 0,
                }
            } else {
                // Live, settled short or whole, released or cancelled.
                let charge = match rng.below(4) {
                    0 => UnitCharge::Live,
                    1 => UnitCharge::Settled(rng.below(units + 1)),
                    2 => UnitCharge::Settled(units),
                    _ => UnitCharge::Void,
                };
                unit(arm, family, 0, draws, charge)
            });
            let room = PeriodRoom::fold(&record, &seats, &rows);
            for bucket in buckets(&families) {
                assert!(
                    room.used(bucket) <= room.capacity(bucket),
                    "run {run} step {step}: {bucket:?} charged {} of {}",
                    room.used(bucket),
                    room.capacity(bucket)
                );
                assert_eq!(room.left(bucket) + room.used(bucket), room.capacity(bucket));
            }
            assert_eq!(
                pools_total(&room, &families),
                ALLOWANCE,
                "run {run} step {step}"
            );
        }
        // The roll-over: period 1 holds none of period 0's rows.
        let rolled = PeriodRoom::fold(&next, &seats, &rows);
        for bucket in buckets(&families) {
            assert_eq!(
                rolled.used(bucket),
                0,
                "run {run}: {bucket:?} after roll-over"
            );
        }
        assert_eq!(rolled.reserve_left(Side::Pinned), FLOOR);
        assert_eq!(rolled.reserve_left(Side::Unpinned), FLOOR);
    }
}
