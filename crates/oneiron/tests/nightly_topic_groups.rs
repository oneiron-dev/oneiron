//! Nightly extraction groups unbound TURNs by topic (census L2-04; ARCH-0026
//! Nightly: "It groups the queued spans by thing, an entity or a topic").
//! A Name span that bound no entity names a topic, its words in lower case
//! with whitespace collapsed. The unbound TURNs naming one topic are one
//! thing, whichever conversation they are in, and their parts share a slice
//! line where their exposure agrees; TURNs naming two topics are two things,
//! and a TURN naming both lands in each.
//! A TURN that binds an entity stays with it, and one that names no topic
//! stays in the structural topic, each part on its own line, as before.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test nightly_topic_groups`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::nightly::{
    PlannedThing, SpentSpan, SpentSpanKind, planned_things, witness_turn,
};
use oneiron::{EntityId, Vault};

const READER: &str = "reader";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    Fixture { _dir: dir, vault }
}

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

/// A spent Name span over `words` in `said`, bound to `entity` or to none.
fn name<'a>(said: &'a Said, words: &'a str, entity: Option<EntityId>, score: u32) -> SpentSpan<'a> {
    SpentSpan {
        turn: said.turn,
        message: said.message,
        text: said.text,
        words,
        kind: SpentSpanKind::Name,
        entity,
        score,
    }
}

fn date<'a>(said: &'a Said, words: &'a str, score: u32) -> SpentSpan<'a> {
    SpentSpan {
        kind: SpentSpanKind::Date,
        ..name(said, words, None, score)
    }
}

fn turns_of(thing: &PlannedThing) -> BTreeSet<EntityId> {
    thing
        .children
        .iter()
        .flatten()
        .map(|(turn, _)| *turn)
        .collect()
}

/// Each TURN's slice line in `thing`, which must have one child.
fn lines_of(thing: &PlannedThing) -> BTreeMap<EntityId, u32> {
    assert_eq!(thing.children.len(), 1, "one child: {thing:?}");
    thing.children[0].iter().copied().collect()
}

/// The thing holding `turn`; there must be exactly one.
fn thing_of(things: &[PlannedThing], turn: EntityId) -> &PlannedThing {
    let holding: Vec<&PlannedThing> = things
        .iter()
        .filter(|thing| turns_of(thing).contains(&turn))
        .collect();
    assert_eq!(holding.len(), 1, "one thing holds the TURN: {things:?}");
    holding[0]
}

#[test]
fn unbound_turns_naming_two_unknown_names_in_one_conversation_are_two_things() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let conversation = EntityId::now();
    let budget = say(
        vault,
        conversation,
        "We should ask Kestrel about the budget.",
        10,
    );
    let flat = say(
        vault,
        conversation,
        "The Alder Street flat is still free.",
        11,
    );
    let things = planned_things(
        vault,
        &[
            name(&budget, "Kestrel", None, 90),
            name(&flat, "Alder Street", None, 80),
        ],
    )
    .expect("plan");

    assert_eq!(things.len(), 2, "one thing per unknown name: {things:?}");
    assert_eq!(turns_of(&things[0]), BTreeSet::from([budget.turn]));
    assert_eq!(turns_of(&things[1]), BTreeSet::from([flat.turn]));
    assert!(things.iter().all(|thing| thing.entity.is_none()));
}

#[test]
fn unbound_turns_naming_one_unknown_name_in_two_conversations_are_read_on_one_line() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let sent = say(vault, EntityId::now(), "Kestrel sent the draft over.", 10);
    let late = say(
        vault,
        EntityId::now(),
        "I told KESTREL the draft is late.",
        10,
    );
    let things = planned_things(
        vault,
        &[
            name(&sent, "Kestrel", None, 90),
            name(&late, "KESTREL", None, 80),
        ],
    )
    .expect("plan");

    assert_eq!(things.len(), 1, "one thing for the one name: {things:?}");
    let thing = &things[0];
    assert_eq!(thing.entity, None);
    let lines = lines_of(thing);
    assert_eq!(
        lines.get(&sent.turn),
        lines.get(&late.turn),
        "both conversations' TURNs about the name are read on one line: {thing:?}"
    );
}

#[test]
fn an_unbound_turn_naming_no_unknown_name_stays_in_the_structural_topic() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let planned = say(vault, EntityId::now(), "We met on 2026-10-12 to plan.", 10);
    let moved = say(
        vault,
        EntityId::now(),
        "It moved to 2026-10-19 after all.",
        10,
    );
    let things = planned_things(
        vault,
        &[
            date(&planned, "2026-10-12", 90),
            date(&moved, "2026-10-19", 80),
        ],
    )
    .expect("plan");

    assert_eq!(things.len(), 1, "one structural topic: {things:?}");
    let thing = &things[0];
    assert_eq!(thing.entity, None);
    assert_eq!(turns_of(thing), BTreeSet::from([planned.turn, moved.turn]));
    let lines = lines_of(thing);
    assert_ne!(
        lines.get(&planned.turn),
        lines.get(&moved.turn),
        "each conversation of the structural topic is a line of its own: {thing:?}"
    );
}

#[test]
fn a_turn_that_binds_an_entity_stays_with_the_entity_and_joins_no_topic() {
    let fixture = fixture();
    let vault = &fixture.vault;
    // The plan keys a thing by the bound id; it never reads the entity's row.
    let ana = EntityId::now();
    let met = say(vault, EntityId::now(), "Ana met Kestrel at noon.", 10);
    let wrote = say(vault, EntityId::now(), "Kestrel wrote back.", 10);
    let things = planned_things(
        vault,
        &[
            name(&met, "Ana", Some(ana), 90),
            name(&met, "Kestrel", None, 80),
            name(&wrote, "Kestrel", None, 70),
        ],
    )
    .expect("plan");

    assert_eq!(things.len(), 2, "{things:?}");
    let bound = thing_of(&things, met.turn);
    assert_eq!(bound.entity, Some(ana));
    assert_eq!(turns_of(bound), BTreeSet::from([met.turn]));
    let unbound = thing_of(&things, wrote.turn);
    assert_eq!(unbound.entity, None);
    assert_eq!(turns_of(unbound), BTreeSet::from([wrote.turn]));
}

#[test]
fn a_turn_naming_two_unknown_names_lands_in_each_of_their_things() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let both = say(
        vault,
        EntityId::now(),
        "Kestrel and Alder Street are both late.",
        10,
    );
    let kestrel = say(vault, EntityId::now(), "Kestrel sent the draft over.", 10);
    let alder = say(
        vault,
        EntityId::now(),
        "The Alder Street flat is still free.",
        10,
    );
    let things = planned_things(
        vault,
        &[
            name(&both, "Kestrel", None, 90),
            name(&both, "Alder Street", None, 85),
            name(&kestrel, "Kestrel", None, 80),
            name(&alder, "Alder Street", None, 70),
        ],
    )
    .expect("plan");

    assert_eq!(things.len(), 2, "one thing per unknown name: {things:?}");
    assert_eq!(
        turns_of(&things[0]),
        BTreeSet::from([both.turn, kestrel.turn])
    );
    assert_eq!(
        turns_of(&things[1]),
        BTreeSet::from([both.turn, alder.turn])
    );
}
