//! The night's partition limit counts (conversation, world, facet) buckets
//! (REVIEW-10633 round 1 P1 2). The partition key holds the TURN's stored
//! project, so one bucket whose TURNs sit in two projects plans two
//! partitions; a kept bucket keeps both, so neither project's spans wait for
//! another night, and one child still never holds two projects' TURNs.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test nightly_project_partitions`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::settle_extraction_rows_in_project;
use oneiron::test_doors::nightly::{
    PlannedThing, SpentSpan, SpentSpanKind, planned_things_within, witness_turn,
};
use oneiron::{EntityId, Vault};

/// One witnessed TURN and its one MESSAGE's words.
struct Said {
    turn: EntityId,
    message: EntityId,
    text: &'static str,
}

fn say(vault: &Vault, conversation: EntityId, text: &'static str, at: u64) -> Said {
    let (turn, message) = witness_turn(vault, conversation, text, at).expect("witness");
    Said {
        turn,
        message,
        text,
    }
}

/// A spent, unbound Name span over `words` in `said`.
fn name<'a>(said: &'a Said, words: &'a str, score: u32) -> SpentSpan<'a> {
    SpentSpan {
        turn: said.turn,
        message: said.message,
        text: said.text,
        words,
        kind: SpentSpanKind::Name,
        entity: None,
        score,
    }
}

fn planned_turns(things: &[PlannedThing]) -> BTreeSet<EntityId> {
    things
        .iter()
        .flat_map(|thing| thing.children.iter().flatten())
        .map(|(turn, _)| *turn)
        .collect()
}

/// T8: with `nightly_children` = 1, the highest scored bucket is kept whole:
/// its default-project TURN and its project-Q TURN are both planned, in two
/// children; a second conversation's lower scored span waits, as one bucket
/// was its limit before the key held the project.
#[test]
fn a_kept_bucket_keeps_every_project_partition_under_the_nightly_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let conversation = EntityId::now();
    let home = say(&vault, conversation, "Mira Vale came by the studio", 1_000);
    let other = say(
        &vault,
        conversation,
        "Mira Vale left the studio early",
        2_000,
    );
    let project = EntityId::now();
    settle_extraction_rows_in_project(&vault, &[other.turn, other.message], project)
        .expect("place the second TURN in project Q");
    let later = say(&vault, EntityId::now(), "Mira Vale wrote back", 3_000);

    let spans = [
        name(&home, "Mira Vale", 90),
        name(&other, "Mira Vale", 80),
        name(&later, "Mira Vale", 70),
    ];
    let things = planned_things_within(&vault, &spans, 1).expect("plan the night");
    let planned = planned_turns(&things);
    assert!(
        planned.contains(&home.turn),
        "the highest scored TURN is not planned: {things:?}"
    );
    assert!(
        planned.contains(&other.turn),
        "the kept bucket's project-Q partition was dropped by the limit: {things:?}"
    );
    assert!(
        !planned.contains(&later.turn),
        "the limit no longer counts buckets: a second conversation was planned: {things:?}"
    );
    for child in things.iter().flat_map(|thing| &thing.children) {
        let turns: BTreeSet<EntityId> = child.iter().map(|(turn, _)| *turn).collect();
        assert!(
            !(turns.contains(&home.turn) && turns.contains(&other.turn)),
            "one child holds two projects' TURNs: {things:?}"
        );
    }
}
