//! A time phrase in the query re-anchors the temporal channel and never
//! filters on occurred time (canon research-1009 P1.1, ruling
//! RULER-TIME-PHRASE-FILTER = A). Only a host window filters.
//!
//! LongMemEval case 3a704032 (retrieval ruler screen 1, 15 Nov 2026) asks
//! "How many plants did I acquire in the last month?" on 30 May 2023 about
//! turns from 20-25 May. "Last month" names April, the calendar month before
//! the clock's, and the run used to return no row at all.

use std::collections::BTreeMap;

use oneiron::memory::Effort;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 2023-05-30T21:51:00Z, the case's question date; "last month" is April.
const NOW: u64 = 1_685_483_460;
const QUESTION: &str = "How many plants did I acquire in the last month?";
const QUESTION_WITHOUT_TIME: &str = "How many plants did I acquire?";
/// The turns, each with its occurred time; none falls in April.
const TURNS: [(u64, &str); 5] = [
    // 2023-05-20T00:22:00Z
    (
        1_684_542_120,
        "I got two new plants from the nursery today, a fern and a pothos.",
    ),
    // 2023-05-22T09:10:00Z
    (
        1_684_746_600,
        "We booked the train to Osaka for the summer festival.",
    ),
    // 2023-05-24T18:05:00Z
    (
        1_684_951_500,
        "My sister gave me three succulent plants for the balcony.",
    ),
    // 2023-05-25T12:40:00Z
    (
        1_685_018_400,
        "I picked up a basil plant and two more plants for the kitchen window.",
    ),
    // 2023-05-28T08:30:00Z
    (
        1_685_262_600,
        "The dentist moved my appointment to Friday morning.",
    ),
];
/// The indexes in `TURNS` of the turns about plants.
const PLANT_TURNS: [usize; 3] = [0, 2, 3];

struct Fixture {
    _directory: tempfile::TempDir,
    vault: Vault,
    turns: Vec<EntityId>,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(directory.path(), config)?;
    let mut turns = Vec::with_capacity(TURNS.len());
    let mut batch = vault.batch();
    for (seed, (moment, text)) in (0x51_u8..).zip(TURNS) {
        let id = EntityId::from_bytes([seed; 16])?;
        let body = BTreeMap::from([("txt", text), ("spkr", "user")]);
        batch = batch
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: moment,
                    end: moment,
                },
                moment,
                &rmp_serde::to_vec_named(&body)?,
            )
            .text(&id, &[("txt", text)]);
        turns.push(id);
    }
    batch.commit()?;
    Ok(Fixture {
        _directory: directory,
        vault,
        turns,
    })
}

/// The ids a Light-effort text query returns at `NOW`, as a recall runs it.
fn ask(
    vault: &Vault,
    query: &str,
    host_window: Option<(u64, u64)>,
) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    let mut builder = vault.query().with_temporal_now(NOW).search_text(query, 10);
    if let Some((start, end)) = host_window {
        builder = builder.filter_occurred_range(start, end);
    }
    let found = builder
        .limit(10)
        .retrieval_effort(Effort::Light, &[])
        .run()?;
    Ok(found.into_iter().map(|hit| hit.id).collect())
}

#[test]
fn last_month_with_no_turn_in_that_month_still_returns_the_turns() -> TestResult {
    let fixture = fixture()?;
    let without_time = ask(&fixture.vault, QUESTION_WITHOUT_TIME, None)?;
    let with_time = ask(&fixture.vault, QUESTION, None)?;
    for index in PLANT_TURNS {
        let turn = fixture.turns[index];
        assert!(
            without_time.contains(&turn),
            "plant turn {index} without the phrase: {without_time:?}"
        );
        assert!(
            with_time.contains(&turn),
            "plant turn {index} with \"last month\": {with_time:?}"
        );
    }
    Ok(())
}

#[test]
fn a_host_window_still_filters_on_occurred_time() -> TestResult {
    let fixture = fixture()?;
    // 2023-05-23T00:00:00Z to 2023-05-26T00:00:00Z: the 24 and 25 May turns.
    let found = ask(
        &fixture.vault,
        QUESTION,
        Some((1_684_800_000, 1_685_059_200)),
    )?;
    for index in [2, 3] {
        assert!(
            found.contains(&fixture.turns[index]),
            "plant turn {index} inside the host window: {found:?}"
        );
    }
    assert!(
        !found.contains(&fixture.turns[0]),
        "the 20 May turn is outside the host window: {found:?}"
    );
    Ok(())
}
