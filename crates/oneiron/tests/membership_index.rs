//! The per-participant membership index serves every roster check (ARCH-0052
//! :215, ASTRA-1406b): each check used to decode the room and fold its whole
//! membership ledger, two or more folds per call. Public paths plus the
//! `conversation_membership_index` doors only.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test membership_index`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::conversation::{ConversationBody, HistoryChoice};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::conversation_membership_index as doors;
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault with four PERSON rows and one empty room, as
/// `conversation/tests.rs` builds it on public paths. Alice acts and never
/// joins; bob, carol and dan are the members. The vault closes before its
/// directory goes.
struct Fixture {
    vault: Vault,
    actor: WriteActor,
    alice: EntityId,
    bob: EntityId,
    carol: EntityId,
    dan: EntityId,
    room: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let alice = EntityId::now();
    let bob = EntityId::now();
    let carol = EntityId::now();
    let dan = EntityId::now();
    let person = rmp_serde::to_vec_named(&serde_json::json!({}))?;
    for id in [alice, bob, carol, dan] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 0, end: 0 },
            0,
            &person,
        )?;
    }
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    let room = EntityId::now();
    vault.create_conversation(room, &ConversationBody::default(), actor, 1)?;
    Ok(Fixture {
        vault,
        actor,
        alice,
        bob,
        carol,
        dan,
        room,
        _dir: dir,
    })
}

/// A second empty room in the fixture's vault.
fn open_room(fixture: &Fixture) -> TestResult<EntityId> {
    let room = EntityId::now();
    fixture
        .vault
        .create_conversation(room, &ConversationBody::default(), fixture.actor, 1)?;
    Ok(room)
}

/// Seeds `rounds` join-bob / join-carol / history / leave-bob / leave-carol
/// rounds at rising times from `at`, alternating the join choice, the history
/// target and the history edge. Returns the next free time. Both are out when
/// a round ends, so a round never depends on the last.
fn seed_rounds(fixture: &Fixture, room: EntityId, rounds: u64, mut at: u64) -> TestResult<u64> {
    for round in 0..rounds {
        let bob_choice = match round % 3 {
            0 => HistoryChoice::Share,
            1 => HistoryChoice::None,
            _ => HistoryChoice::Inherit,
        };
        let carol_choice = match round % 3 {
            0 => HistoryChoice::None,
            1 => HistoryChoice::Inherit,
            _ => HistoryChoice::Share,
        };
        let vault = &fixture.vault;
        vault.join_member(room, fixture.bob, fixture.actor, at, bob_choice)?;
        let bob_joined = at;
        at += 1;
        vault.join_member(room, fixture.carol, fixture.actor, at, carol_choice)?;
        let carol_joined = at;
        at += 1;
        let (person, joined) = if round % 2 == 0 {
            (fixture.bob, bob_joined)
        } else {
            (fixture.carol, carol_joined)
        };
        let from = if round % 4 < 2 { 0 } else { joined };
        vault.set_history_visibility(room, person, fixture.actor, at, from)?;
        at += 1;
        vault.leave_member(room, fixture.bob, fixture.actor, at)?;
        at += 1;
        vault.leave_member(room, fixture.carol, fixture.actor, at)?;
        at += 1;
    }
    Ok(at)
}

/// Asserts every index-served answer for `room` equals the ledger fold: the
/// door readers and the public `members` / `membership_at` / `windows` at
/// each `at` and for each person of `people`, with `members_in_record_order`
/// compared as a set with `members`. The fold answers are read first and the
/// counter is measured only around the index reads; returns the rows the
/// index reads folded.
fn assert_index_matches_fold(
    vault: &Vault,
    room: EntityId,
    people: &[EntityId],
    ats: &[u64],
) -> TestResult<u64> {
    // Fold expectations first, outside the measurement: the folded_* doors
    // scan the ledger by design.
    let folded_now = doors::folded_members_at(vault, room, u64::MAX)?;
    let mut folded_at = Vec::with_capacity(ats.len());
    for at in ats {
        folded_at.push(doors::folded_members_at(vault, room, *at)?);
    }
    let mut folded_windows = Vec::with_capacity(people.len());
    let mut folded_joins = Vec::with_capacity(people.len());
    for person in people {
        folded_windows.push(doors::folded_windows(vault, room, *person)?);
        folded_joins.push(doors::folded_current_join(vault, room, *person)?);
    }
    let folded_ever = doors::folded_ever_members(vault, room)?;

    let before = doors::ledger_rows_folded();
    let members = doors::members(vault, room)?;
    let record_order = doors::members_in_record_order(vault, room)?;
    let ever = doors::ever_members(vault, room)?;
    let mut at_answers = Vec::with_capacity(ats.len());
    for at in ats {
        at_answers.push(doors::membership_at(vault, room, *at)?);
    }
    let mut member_answers = Vec::with_capacity(people.len());
    let mut join_answers = Vec::with_capacity(people.len());
    let mut window_answers = Vec::with_capacity(people.len());
    for person in people {
        member_answers.push(doors::is_member(vault, room, *person)?);
        join_answers.push(doors::current_join(vault, room, *person)?);
        window_answers.push(doors::windows(vault, room, *person)?);
    }
    let public_members = vault.members(room)?;
    let mut public_at = Vec::with_capacity(ats.len());
    for at in ats {
        public_at.push(vault.membership_at(room, *at)?);
    }
    let mut public_windows = Vec::with_capacity(people.len());
    for person in people {
        public_windows.push(vault.windows(room, *person)?);
    }
    let folded = doors::ledger_rows_folded() - before;

    // Comparisons after the measurement.
    let expected_now: Vec<EntityId> = folded_now.iter().copied().collect();
    assert_eq!(members, expected_now, "members match the fold");
    assert_eq!(
        record_order.iter().copied().collect::<BTreeSet<_>>(),
        members.iter().copied().collect::<BTreeSet<_>>(),
        "record order holds the members"
    );
    assert_eq!(ever, folded_ever, "ever members match the fold");
    assert_eq!(public_members, members, "public members match the index");
    for (index, at) in ats.iter().enumerate() {
        let expected: Vec<EntityId> = folded_at[index].iter().copied().collect();
        assert_eq!(
            at_answers[index], expected,
            "members at {at} match the fold"
        );
        assert_eq!(
            public_at[index], expected,
            "public members at {at} match the fold"
        );
    }
    for (index, person) in people.iter().enumerate() {
        let who = person.to_hex();
        assert_eq!(
            member_answers[index],
            folded_now.contains(person),
            "is_member for {who} matches the fold"
        );
        assert_eq!(
            join_answers[index], folded_joins[index],
            "current join for {who} matches the fold"
        );
        assert_eq!(
            window_answers[index], folded_windows[index],
            "windows for {who} match the fold"
        );
        assert_eq!(
            public_windows[index], folded_windows[index],
            "public windows for {who} match the fold"
        );
    }
    Ok(folded)
}

/// RED: every roster check on a long ledger serves from the per-participant
/// index and answers as the fold.
#[test]
fn roster_checks_serve_from_per_participant_index() -> TestResult {
    let fixture = open()?;
    let next = seed_rounds(&fixture, fixture.room, 40, 2)?;
    assert!(fixture.vault.membership_ledger(fixture.room)?.len() >= 120);
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    let ats = [0, 1, 2, 3, 100, 200, next - 1, next, u64::MAX];
    let folded = assert_index_matches_fold(&fixture.vault, fixture.room, &people, &ats)?;
    assert_eq!(folded, 0, "every roster check serves from the index");
    Ok(())
}

/// RED: a join, a history change and a leave on an indexed room fold no
/// ledger, and the index still matches the fold after them.
#[test]
fn a_membership_change_on_an_indexed_room_folds_no_ledger() -> TestResult {
    let fixture = open()?;
    let mut at = seed_rounds(&fixture, fixture.room, 40, 2)?;
    // Both are out after whole rounds; bob rejoins, moves his edge, leaves.
    let vault = &fixture.vault;
    let before = doors::ledger_rows_folded();
    vault.join_member(
        fixture.room,
        fixture.bob,
        fixture.actor,
        at,
        HistoryChoice::Share,
    )?;
    let joined = at;
    at += 1;
    assert_eq!(
        doors::ledger_rows_folded() - before,
        0,
        "join folds no ledger"
    );
    let before = doors::ledger_rows_folded();
    vault.set_history_visibility(fixture.room, fixture.bob, fixture.actor, at, joined)?;
    at += 1;
    assert_eq!(
        doors::ledger_rows_folded() - before,
        0,
        "history folds no ledger"
    );
    let before = doors::ledger_rows_folded();
    vault.leave_member(fixture.room, fixture.bob, fixture.actor, at)?;
    at += 1;
    assert_eq!(
        doors::ledger_rows_folded() - before,
        0,
        "leave folds no ledger"
    );
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    let ats = [0, 2, 100, at - 1, at, u64::MAX];
    let folded = assert_index_matches_fold(vault, fixture.room, &people, &ats)?;
    assert_eq!(folded, 0, "reads still serve from the index");
    Ok(())
}

/// RED: a room whose ledger predates the index folds on every read until its
/// next membership change, which indexes it.
#[test]
fn an_old_ledger_folds_until_its_next_change_indexes_it() -> TestResult {
    let fixture = open()?;
    let mut at = seed_rounds(&fixture, fixture.room, 40, 2)?;
    let vault = &fixture.vault;
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    let ats = [0, 2, 100, at - 1, at, u64::MAX];
    doors::drop_room_index(vault, fixture.room)?;
    let folded = assert_index_matches_fold(vault, fixture.room, &people, &ats)?;
    assert!(folded > 0, "an unindexed room folds its ledger");
    vault.join_member(
        fixture.room,
        fixture.bob,
        fixture.actor,
        at,
        HistoryChoice::None,
    )?;
    at += 1;
    let ats = [0, 2, 100, at - 1, at, u64::MAX];
    let folded = assert_index_matches_fold(vault, fixture.room, &people, &ats)?;
    assert_eq!(folded, 0, "the next change indexes the room");
    Ok(())
}

/// RED: the restore rebuild indexes every room.
#[test]
fn a_restore_rebuild_indexes_every_room() -> TestResult {
    let fixture = open()?;
    let second = open_room(&fixture)?;
    let first_next = seed_rounds(&fixture, fixture.room, 40, 2)?;
    let second_next = seed_rounds(&fixture, second, 40, 2)?;
    let vault = &fixture.vault;
    doors::drop_room_index(vault, fixture.room)?;
    doors::drop_room_index(vault, second)?;
    doors::rebuild_index(vault)?;
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    for (room, next) in [(fixture.room, first_next), (second, second_next)] {
        let ats = [0, 2, 100, next - 1, next, u64::MAX];
        let folded = assert_index_matches_fold(vault, room, &people, &ats)?;
        assert_eq!(folded, 0, "a rebuilt room serves from the index");
    }
    Ok(())
}

/// GUARD: index answers match the fold over equal-`at` ties, rejoins and
/// history edges, for every person including alice, who never joins.
#[test]
fn index_answers_match_the_fold_over_ties_rejoins_and_history_edges() -> TestResult {
    let fixture = open()?;
    let vault = &fixture.vault;
    let room = fixture.room;
    let actor = fixture.actor;
    vault.join_member(room, fixture.bob, actor, 2, HistoryChoice::Inherit)?;
    vault.join_member(room, fixture.carol, actor, 2, HistoryChoice::Share)?;
    vault.leave_member(room, fixture.bob, actor, 2)?;
    vault.join_member(room, fixture.bob, actor, 2, HistoryChoice::None)?;
    vault.set_history_visibility(room, fixture.carol, actor, 3, 2)?;
    vault.set_history_visibility(room, fixture.carol, actor, 3, 0)?;
    vault.leave_member(room, fixture.carol, actor, 4)?;
    vault.join_member(room, fixture.carol, actor, 4, HistoryChoice::Inherit)?;
    vault.leave_member(room, fixture.carol, actor, 4)?;
    vault.join_member(room, fixture.dan, actor, 5, HistoryChoice::Share)?;
    vault.leave_member(room, fixture.bob, actor, 6)?;
    vault.join_member(room, fixture.bob, actor, 6, HistoryChoice::Share)?;
    vault.set_history_visibility(room, fixture.bob, actor, 7, 6)?;
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    let ats: Vec<u64> = (0..=8).chain([u64::MAX]).collect();
    assert_index_matches_fold(vault, room, &people, &ats)?;
    Ok(())
}

/// GUARD: a ledger whose revision disagrees with its rows refuses every read
/// and every join.
#[test]
fn a_ledger_whose_revision_disagrees_with_its_rows_refuses_every_read() -> TestResult {
    let fixture = open()?;
    seed_rounds(&fixture, fixture.room, 5, 2)?;
    let vault = &fixture.vault;
    let room = fixture.room;
    let rows = vault.membership_ledger(room)?.len() as u64;
    doors::set_ledger_revision(vault, room, rows + 1)?;
    let people = [fixture.alice, fixture.bob, fixture.carol, fixture.dan];
    assert!(
        matches!(doors::members(vault, room), Err(Error::CorruptedIndex(_))),
        "members refuses"
    );
    assert!(
        matches!(
            doors::members_in_record_order(vault, room),
            Err(Error::CorruptedIndex(_))
        ),
        "record order refuses"
    );
    assert!(
        matches!(
            doors::ever_members(vault, room),
            Err(Error::CorruptedIndex(_))
        ),
        "ever members refuses"
    );
    for at in [0, 2, u64::MAX] {
        assert!(
            matches!(
                doors::membership_at(vault, room, at),
                Err(Error::CorruptedIndex(_))
            ),
            "members at {at} refuses"
        );
        assert!(
            matches!(vault.membership_at(room, at), Err(Error::CorruptedIndex(_))),
            "public members at {at} refuses"
        );
    }
    for person in people {
        assert!(
            matches!(
                doors::is_member(vault, room, person),
                Err(Error::CorruptedIndex(_))
            ),
            "is_member refuses"
        );
        assert!(
            matches!(
                doors::current_join(vault, room, person),
                Err(Error::CorruptedIndex(_))
            ),
            "current join refuses"
        );
        assert!(
            matches!(
                doors::windows(vault, room, person),
                Err(Error::CorruptedIndex(_))
            ),
            "windows refuses"
        );
        assert!(
            matches!(vault.windows(room, person), Err(Error::CorruptedIndex(_))),
            "public windows refuses"
        );
    }
    assert!(
        matches!(vault.members(room), Err(Error::CorruptedIndex(_))),
        "public members refuses"
    );
    assert!(
        matches!(vault.membership_ledger(room), Err(Error::CorruptedIndex(_))),
        "the audit read refuses"
    );
    assert!(
        matches!(
            vault.join_member(room, fixture.bob, fixture.actor, 1000, HistoryChoice::Share),
            Err(Error::CorruptedIndex(_))
        ),
        "join refuses"
    );
    Ok(())
}
