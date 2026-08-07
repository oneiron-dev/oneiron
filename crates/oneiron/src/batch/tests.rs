use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::off_record::OffRecordBackendClass;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use core::assert_matches;
#[cfg(feature = "sync")]
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;

struct EdgeFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    edge: EdgeRef,
    claim_id: EntityId,
}

type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

fn open_raw_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("open vault");
    (dir, vault)
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let (tmp, vault) = open_raw_test_vault();
    clear_default_policy_manifest_for_test(&vault);
    (tmp, vault)
}

fn clear_default_policy_manifest_for_test(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest");
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

#[test]
fn checkin_on_non_habit_rejected() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let task = EntityId::now();
    let checkin = EntityId::now();
    let task_body = crate::habit::task_body_for_test(TaskRole::Task);
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);

    vault.put_entity(
        &task,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &task_body,
    )?;

    let err = vault
        .put_habit_checkin(&task, &checkin, test_time_range(11, 11), 11, &checkin_body)
        .expect_err("check-in under non-Habit TASK must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert!(!vault.entity_exists(&checkin)?);
    assert!(!vault.edge_exists(&checkin, EdgeKind::ChildOf, &task)?);
    Ok(())
}

#[test]
fn checkin_immutable() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
    let replacement_body = crate::habit::task_body_for_test(TaskRole::Task);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault
        .get_raw(&checkin)?
        .expect("check-in row must be written");

    let err = vault
        .put_entity(
            &checkin,
            ENTITY_TYPE_TASK,
            test_time_range(12, 12),
            12,
            &replacement_body,
        )
        .expect_err("check-in re-put must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert_eq!(vault.get_raw(&checkin)?, Some(original));
    Ok(())
}

#[test]
fn checkin_same_role_mutation_rejected_and_identical_reput_idempotent() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault
        .get_raw(&checkin)?
        .expect("check-in row must be written");

    // Re-put with the role still HabitCheckin but mutated occurred/learned_at:
    // the immutability guard protects payload/time, not just role changes.
    let err = vault
        .put_entity(
            &checkin,
            ENTITY_TYPE_TASK,
            test_time_range(20, 20),
            20,
            &checkin_body,
        )
        .expect_err("same-role check-in time mutation must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert_eq!(vault.get_raw(&checkin)?, Some(original.clone()));

    // An identical re-put (same role, body, occurred, learned_at) stays accepted.
    vault.put_entity(
        &checkin,
        ENTITY_TYPE_TASK,
        test_time_range(11, 11),
        11,
        &checkin_body,
    )?;
    assert_eq!(vault.get_raw(&checkin)?, Some(original));
    Ok(())
}

#[test]
fn habit_with_checkins_cannot_change_role() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::habit::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
    let demoted_body = crate::habit::task_body_for_test(TaskRole::Task);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault.get_raw(&habit)?.expect("habit row must be written");

    let err = vault
        .put_entity(
            &habit,
            ENTITY_TYPE_TASK,
            test_time_range(12, 12),
            12,
            &demoted_body,
        )
        .expect_err("demoting a Habit that has check-ins must be rejected");

    match err {
        Error::InvalidTaskBody(msg) => {
            assert_eq!(msg, "Habit TASK with check-ins cannot change role");
        }
        other => panic!("expected InvalidTaskBody, got {other:?}"),
    }
    assert_eq!(vault.get_raw(&habit)?, Some(original));
    Ok(())
}

/// `day * 86_400 + offset` — the check-in timestamp whose UTC day bucket is
/// `day`. The offset proves the reducer buckets rather than compares seconds.
fn checkin_at(day: u64, offset: u64) -> u64 {
    day * 86_400 + offset
}

fn stored_task_body(vault: &Vault, id: &EntityId) -> Result<Vec<(Value, Value)>> {
    let raw = vault.get_raw(id)?.expect("entity row must exist");
    let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let value = rmpv::decode::read_value(&mut cursor).expect("stored TASK body must decode");
    Ok(value.as_map().expect("stored TASK body is a map").to_vec())
}

fn stored_streak_field(vault: &Vault, id: &EntityId, key: &str) -> Result<Option<u64>> {
    Ok(stored_task_body(vault, id)?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| {
            value
                .as_u64()
                .expect("streak counters are unsigned integers")
        }))
}

/// The stored `(currentStreak, longestStreak)` pair.
fn stored_streak(vault: &Vault, id: &EntityId) -> Result<(u64, u64)> {
    Ok((
        stored_streak_field(vault, id, "currentStreak")?.expect("currentStreak must be stored"),
        stored_streak_field(vault, id, "longestStreak")?.expect("longestStreak must be stored"),
    ))
}

fn habit_body_with_streak(current: u64, longest: u64) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::from(crate::habit::TASK_BODY_ROLE_KEY),
            Value::from(TaskRole::Habit.role_byte()),
        ),
        (Value::from("currentStreak"), Value::from(current)),
        (Value::from("longestStreak"), Value::from(longest)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode habit fixture body");
    bytes
}

#[test]
fn habit_streak_is_derived_from_checkin_children() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(checkin_at(10, 0), checkin_at(10, 0)),
        checkin_at(10, 0),
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    // A Habit with no children carries the empty pair, not a missing field.
    assert_eq!(stored_streak(&vault, &habit)?, (0, 0));

    // Days 10, 11 (twice — two separate entities, one streak day), then a gap
    // to day 14. `longest` is the 10-11 run; `current` is the run ending at
    // the NEWEST child day, which is the lone day 14.
    let checkins: Vec<(EntityId, u64)> = [
        checkin_at(11, 7_200),
        checkin_at(10, 3_600),
        checkin_at(14, 100),
        checkin_at(11, 60),
    ]
    .into_iter()
    .map(|occurred| (EntityId::now(), occurred))
    .collect();
    for (checkin, occurred) in &checkins {
        vault.put_habit_checkin(
            &habit,
            checkin,
            test_time_range(*occurred, *occurred),
            *occurred,
            &checkin_body,
        )?;
    }

    assert_eq!(stored_streak(&vault, &habit)?, (1, 2));
    assert_eq!(
        vault.sources(&habit, EdgeKind::ChildOf, None)?.len(),
        checkins.len(),
        "same-day check-ins stay separate append-only entities"
    );
    // A check-in body never gains counters of its own.
    for (checkin, _) in &checkins {
        assert_eq!(stored_streak_field(&vault, checkin, "currentStreak")?, None);
        assert_eq!(stored_streak_field(&vault, checkin, "longestStreak")?, None);
    }

    // Re-running the recompute over an unchanged child set is byte-idempotent
    // — the metadata header included.
    let before = vault.get_raw(&habit)?.expect("habit row");
    let (last, occurred) = checkins.last().copied().expect("check-in fixture");
    vault.put_habit_checkin(
        &habit,
        &last,
        test_time_range(occurred, occurred),
        occurred,
        &checkin_body,
    )?;
    assert_eq!(vault.get_raw(&habit)?, Some(before));
    Ok(())
}

#[test]
fn habit_body_edit_keeps_the_derived_streak_and_a_non_habit_task_never_gains_one() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let plain_task = EntityId::now();
    let occurred = checkin_at(10, 3_600);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    vault.put_habit_checkin(
        &habit,
        &checkin,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::HabitCheckin),
    )?;
    assert_eq!(stored_streak(&vault, &habit)?, (1, 1));

    // A later body edit carries no counters (the public door forbids them);
    // the derived pair must survive it rather than being dropped.
    let renamed = {
        let value = Value::Map(vec![
            (
                Value::from(crate::habit::TASK_BODY_ROLE_KEY),
                Value::from(TaskRole::Habit.role_byte()),
            ),
            (Value::from("title"), Value::from("morning pages")),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode renamed habit body");
        bytes
    };
    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &renamed,
    )?;
    assert_eq!(stored_streak(&vault, &habit)?, (1, 1));
    assert_eq!(
        stored_task_body(&vault, &habit)?
            .iter()
            .find(|(name, _)| name.as_str() == Some("title"))
            .map(|(_, value)| value.as_str().expect("title is a string").to_owned()),
        Some("morning pages".to_owned()),
        "the rewrite must preserve every unrelated body field"
    );

    // Non-Habit TASK rows are not touched by the recompute at all.
    vault.put_entity(
        &plain_task,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::Task),
    )?;
    assert_eq!(
        stored_streak_field(&vault, &plain_task, "currentStreak")?,
        None
    );
    assert_eq!(
        stored_streak_field(&vault, &plain_task, "longestStreak")?,
        None
    );
    Ok(())
}

#[test]
fn public_task_put_carrying_streak_fields_is_rejected() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let occurred = checkin_at(10, 3_600);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    vault.put_habit_checkin(
        &habit,
        &checkin,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::HabitCheckin),
    )?;
    let original = vault.get_raw(&habit)?.expect("habit row");

    for body in [
        habit_body_with_streak(41, 41),
        // Either key alone is enough to reject.
        {
            let value = Value::Map(vec![
                (
                    Value::from(crate::habit::TASK_BODY_ROLE_KEY),
                    Value::from(TaskRole::Habit.role_byte()),
                ),
                (Value::from("longestStreak"), Value::from(41_u64)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode forged habit body");
            bytes
        },
    ] {
        let err = vault
            .put_entity(
                &habit,
                ENTITY_TYPE_TASK,
                test_time_range(occurred, occurred),
                occurred,
                &body,
            )
            .expect_err("a caller-supplied streak counter must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
        assert_eq!(vault.get_raw(&habit)?, Some(original.clone()));
    }

    // The transactional builder shares the door.
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(
                    &habit,
                    ENTITY_TYPE_TASK,
                    test_time_range(occurred, occurred),
                    occurred,
                    &habit_body_with_streak(41, 41),
                )
                .apply(wtxn)
        })
        .expect_err("the txn builder must reject the same body");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert_eq!(vault.get_raw(&habit)?, Some(original));
    Ok(())
}

/// The stored counters must be a function of the PERSISTED children, so a
/// child leaving the set has to move them exactly as a child joining does.
/// `delete` tears the `ChildOf` edges down inside `deindex_entity` without
/// emitting a `DeleteEdge` op, so an invalidation keyed on explicit edge ops
/// alone never notices and the Habit keeps counting a check-in that is gone.
#[test]
fn deleting_a_checkin_recomputes_the_habit_streak() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin_body = crate::habit::task_body_for_test(TaskRole::HabitCheckin);
    let created = checkin_at(10, 0);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(created, created),
        created,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    let checkins: Vec<(EntityId, u64)> = [checkin_at(10, 100), checkin_at(11, 200)]
        .into_iter()
        .map(|occurred| (EntityId::now(), occurred))
        .collect();
    for (checkin, occurred) in &checkins {
        vault.put_habit_checkin(
            &habit,
            checkin,
            test_time_range(*occurred, *occurred),
            *occurred,
            &checkin_body,
        )?;
    }
    assert_eq!(stored_streak(&vault, &habit)?, (2, 2));

    // The newest check-in leaves through the public batch delete door — no
    // edge op, no TASK put naming the habit.
    let (newest, _) = checkins[1];
    vault.batch().delete(&newest).commit()?;
    assert!(!vault.edge_exists(&newest, EdgeKind::ChildOf, &habit)?);
    assert_eq!(
        stored_streak(&vault, &habit)?,
        (1, 1),
        "a deleted check-in must leave the derived counters"
    );

    // And the last one: an emptied child set is the empty pair, not a frozen
    // high-water mark.
    vault.batch().delete(&checkins[0].0).commit()?;
    assert_eq!(stored_streak(&vault, &habit)?, (0, 0));
    Ok(())
}

/// A `ChildOf` edge may PRE-EXIST its child — sync replay routinely lands the
/// edge before the entity, and the parent-role validator admits it. The put
/// that materializes the check-in then names no edge at all, so the parent is
/// reachable only through the child's already-stored `edges_out`.
#[test]
fn checkin_materializing_under_an_existing_edge_recomputes_the_habit_streak() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let created = checkin_at(10, 0);
    let occurred = checkin_at(11, 900);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(created, created),
        created,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    vault
        .batch()
        .edge(&checkin, EdgeKind::ChildOf, &habit, 1.0)
        .commit()?;
    assert_eq!(
        stored_streak(&vault, &habit)?,
        (0, 0),
        "an edge to a row that does not exist yet contributes no day"
    );

    // The child row arrives in its own transaction, carrying no edge.
    vault.put_entity(
        &checkin,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::HabitCheckin),
    )?;
    assert_eq!(
        stored_streak(&vault, &habit)?,
        (1, 1),
        "the qualifying child set changed, so the parent must be recomputed"
    );
    Ok(())
}

/// The sync door deliberately skips `validate_public_raw_put`, so it is the
/// one door a peer's counters can ride in through — on ANY role, not just
/// `Habit`. The tail reducer visits `Habit` rows alone, so anything it does
/// not visit must arrive already sanitized or the peer's number is stored
/// forever.
#[cfg(feature = "sync")]
#[test]
fn replicated_task_put_cannot_mint_streak_counters() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let plain_task = EntityId::now();
    let occurred = checkin_at(10, 3_600);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::Habit),
    )?;
    vault.put_habit_checkin(
        &habit,
        &checkin,
        test_time_range(occurred, occurred),
        occurred,
        &crate::habit::task_body_for_test(TaskRole::HabitCheckin),
    )?;
    assert_eq!(stored_streak(&vault, &habit)?, (1, 1));

    // A peer's Habit envelope: accepted as a body, but its arithmetic is
    // replaced by the local child set.
    vault
        .batch()
        .put_replicated(
            &habit,
            ENTITY_TYPE_TASK,
            test_time_range(occurred, occurred),
            occurred + 1,
            &habit_body_with_streak(99, 99),
        )
        .commit()?;
    assert_eq!(stored_streak(&vault, &habit)?, (1, 1));

    // A peer's non-Habit rows: the tail pass never visits them, so the keys
    // must be gone before the body is stored.
    for (id, role) in [
        (plain_task, TaskRole::Task),
        (EntityId::now(), TaskRole::Goal),
    ] {
        let body = {
            let value = Value::Map(vec![
                (
                    Value::from(crate::habit::TASK_BODY_ROLE_KEY),
                    Value::from(role.role_byte()),
                ),
                (Value::from("title"), Value::from("peer row")),
                (Value::from("currentStreak"), Value::from(99_u64)),
                (Value::from("longestStreak"), Value::from(99_u64)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode forged peer body");
            bytes
        };
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_TASK,
                test_time_range(occurred, occurred),
                occurred,
                &body,
            )
            .commit()?;
        assert_eq!(
            stored_streak_field(&vault, &id, "currentStreak")?,
            None,
            "a peer cannot mint a counter on a {role:?} row"
        );
        assert_eq!(stored_streak_field(&vault, &id, "longestStreak")?, None);
        assert_eq!(
            stored_task_body(&vault, &id)?
                .iter()
                .find(|(name, _)| name.as_str() == Some("title"))
                .map(|(_, value)| value.as_str().expect("title is a string").to_owned()),
            Some("peer row".to_owned()),
            "discarding the counters must not disturb the rest of the peer's body"
        );
    }

    // A HabitCheckin envelope is the sharpest case: the row is a CHILD, so a
    // counter on it would be both unowned and permanent.
    let forged_checkin = EntityId::now();
    let forged_checkin_body = {
        let value = Value::Map(vec![
            (
                Value::from(crate::habit::TASK_BODY_ROLE_KEY),
                Value::from(TaskRole::HabitCheckin.role_byte()),
            ),
            (Value::from("currentStreak"), Value::from(99_u64)),
            (Value::from("longestStreak"), Value::from(99_u64)),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode forged check-in body");
        bytes
    };
    let replayed = checkin_at(11, 10);
    vault
        .batch()
        .put_replicated(
            &forged_checkin,
            ENTITY_TYPE_TASK,
            test_time_range(replayed, replayed),
            replayed,
            &forged_checkin_body,
        )
        .edge(&forged_checkin, EdgeKind::ChildOf, &habit, 1.0)
        .commit()?;
    assert_eq!(
        stored_streak_field(&vault, &forged_checkin, "currentStreak")?,
        None,
        "a check-in row never gains a streak key"
    );
    assert_eq!(
        stored_streak_field(&vault, &forged_checkin, "longestStreak")?,
        None
    );
    // The replayed child still counts for the parent's arithmetic.
    assert_eq!(stored_streak(&vault, &habit)?, (2, 2));
    Ok(())
}

// ---------------------------------------------------------------------------
// STO-04 (ONE-1376) — ChildOf tree validation over the batch's FINAL state.
// ---------------------------------------------------------------------------

/// Stages a TASK row carrying `role`.
fn put_task_role<'a>(
    batch: BatchBuilder<'a>,
    id: &EntityId,
    role: TaskRole,
    stamp: u64,
) -> BatchBuilder<'a> {
    batch.put(
        id,
        ENTITY_TYPE_TASK,
        test_time_range(stamp, stamp),
        stamp,
        &crate::habit::task_body_for_test(role),
    )
}

/// Stages a generic NON-TASK row — a `ChildOf` user outside the productivity
/// pack, which the role matrix must never reach.
fn put_plain_node<'a>(batch: BatchBuilder<'a>, id: &EntityId, stamp: u64) -> BatchBuilder<'a> {
    batch.put(
        id,
        ENTITY_TYPE_PERSON,
        test_time_range(stamp, stamp),
        stamp,
        b"tree node",
    )
}

#[test]
fn valid_tree_accept() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let goal = EntityId::now();
    let milestone = EntityId::now();
    let task = EntityId::now();
    let habit = EntityId::now();
    let checkin = EntityId::now();

    let batch = put_task_role(vault.batch(), &goal, TaskRole::Goal, 1);
    let batch = put_task_role(batch, &milestone, TaskRole::Milestone, 3);
    let batch = put_task_role(batch, &task, TaskRole::Task, 5);
    let batch = put_task_role(batch, &habit, TaskRole::Habit, 7);
    put_task_role(batch, &checkin, TaskRole::HabitCheckin, 9)
        // Stored child -> parent, the direction the matrix is written in.
        .edge(&milestone, EdgeKind::ChildOf, &goal, 1.0)
        .edge(&task, EdgeKind::ChildOf, &milestone, 1.0)
        .edge(&checkin, EdgeKind::ChildOf, &habit, 1.0)
        .commit()?;

    assert!(vault.edge_exists(&milestone, EdgeKind::ChildOf, &goal)?);
    assert!(vault.edge_exists(&task, EdgeKind::ChildOf, &milestone)?);
    assert!(vault.edge_exists(&checkin, EdgeKind::ChildOf, &habit)?);
    // The committed topology is what the tree read APIs walk — unchanged by
    // this ticket, and the proof that the accepted edges are real.
    assert_eq!(vault.ancestors(&task)?, vec![milestone, goal]);

    // Roots stay legal: a TASK of ANY role with no ChildOf edge has no
    // nesting relation to validate.
    for role in TaskRole::ALL {
        let root = EntityId::now();
        put_task_role(vault.batch(), &root, role, 11).commit()?;
        assert!(
            vault.entity_exists(&root)?,
            "root {role:?} must be writable"
        );
    }
    Ok(())
}

#[test]
fn cycle_reject() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let goal = EntityId::now();
    let milestone = EntityId::now();
    let task = EntityId::now();

    let batch = put_task_role(vault.batch(), &goal, TaskRole::Goal, 1);
    let batch = put_task_role(batch, &milestone, TaskRole::Milestone, 3);
    put_task_role(batch, &task, TaskRole::Task, 5)
        .edge(&milestone, EdgeKind::ChildOf, &goal, 1.0)
        .edge(&task, EdgeKind::ChildOf, &milestone, 1.0)
        .commit()?;

    // Closing the loop is BOTH an ancestor cycle and a matrix violation (a
    // Task parents nothing). The pinned order says the CYCLE is what gets
    // reported: a role error must never mask it.
    let err = vault
        .batch()
        .edge(&goal, EdgeKind::ChildOf, &task, 1.0)
        .commit()
        .expect_err("an ancestor-cycle ChildOf commit must be rejected");
    assert_matches!(err, Error::CycleDetected);
    assert!(!vault.edge_exists(&goal, EdgeKind::ChildOf, &task)?);

    // Self-parent is the degenerate case and reports the same typed error.
    let self_err = vault
        .batch()
        .edge(&goal, EdgeKind::ChildOf, &goal, 1.0)
        .commit()
        .expect_err("a self-parent ChildOf commit must be rejected");
    assert_matches!(self_err, Error::CycleDetected);
    assert!(!vault.edge_exists(&goal, EdgeKind::ChildOf, &goal)?);

    // Nothing from either rejected batch is visible.
    assert_eq!(vault.ancestors(&goal)?, Vec::new());
    Ok(())
}

#[test]
fn dangling_parent_reject() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let task = EntityId::now();
    let absent = EntityId::now();
    put_task_role(vault.batch(), &task, TaskRole::Task, 1).commit()?;

    let err = vault
        .batch()
        .edge(&task, EdgeKind::ChildOf, &absent, 1.0)
        .commit()
        .expect_err("a ChildOf parent absent from final state must be rejected");
    // Coarse-mapped so sync replay keeps quarantine-and-continue, typed so
    // the caller learns WHICH parent went missing.
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    match err {
        Error::ChildOfParentMissing { parent } => assert_eq!(parent, absent),
        other => panic!("expected a dangling-parent rejection, got {other:?}"),
    }
    assert!(!vault.edge_exists(&task, EdgeKind::ChildOf, &absent)?);
    Ok(())
}

#[test]
fn child_of_existence_reads_final_batch_state() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    // A parent PUT LATER in the same batch exists as far as validation is
    // concerned: the check is on final state, never on op order.
    let child = EntityId::now();
    let later_parent = EntityId::now();
    let batch = put_task_role(vault.batch(), &child, TaskRole::Task, 1);
    put_task_role(
        batch.edge(&child, EdgeKind::ChildOf, &later_parent, 1.0),
        &later_parent,
        TaskRole::Milestone,
        3,
    )
    .commit()?;
    assert!(vault.edge_exists(&child, EdgeKind::ChildOf, &later_parent)?);

    // A parent the batch DELETES without re-putting is dangling, even though
    // it is a live row when the batch opens.
    let orphan = EntityId::now();
    let doomed_parent = EntityId::now();
    let batch = put_task_role(vault.batch(), &orphan, TaskRole::Task, 5);
    put_task_role(batch, &doomed_parent, TaskRole::Milestone, 7).commit()?;
    let err = vault
        .batch()
        .delete(&doomed_parent)
        .edge(&orphan, EdgeKind::ChildOf, &doomed_parent, 1.0)
        .commit()
        .expect_err("a parent deleted by this batch cannot receive a new child");
    match err {
        Error::ChildOfParentMissing { parent } => assert_eq!(parent, doomed_parent),
        other => panic!("expected a dangling-parent rejection, got {other:?}"),
    }
    assert!(vault.entity_exists(&doomed_parent)?, "the batch aborted");
    assert!(!vault.edge_exists(&orphan, EdgeKind::ChildOf, &doomed_parent)?);

    // A re-put after the delete restores existence and the batch commits.
    let batch = vault.batch().delete(&doomed_parent);
    put_task_role(batch, &doomed_parent, TaskRole::Milestone, 9)
        .edge(&orphan, EdgeKind::ChildOf, &doomed_parent, 1.0)
        .commit()?;
    assert!(vault.edge_exists(&orphan, EdgeKind::ChildOf, &doomed_parent)?);
    Ok(())
}

/// The pinned nesting matrix, written out here as an INDEPENDENT literal
/// table: `TaskRole::allows_child` may not silently widen.
#[test]
fn task_child_of_role_matrix_rejects_every_pair_outside_the_table() -> Result<()> {
    const LEGAL: [(TaskRole, TaskRole); 3] = [
        (TaskRole::Goal, TaskRole::Milestone),
        (TaskRole::Milestone, TaskRole::Task),
        (TaskRole::Habit, TaskRole::HabitCheckin),
    ];
    let (_dir, vault) = open_raw_test_vault();

    for parent_role in TaskRole::ALL {
        for child_role in TaskRole::ALL {
            let parent = EntityId::now();
            let child = EntityId::now();
            let batch = put_task_role(vault.batch(), &parent, parent_role, 1);
            let result = put_task_role(batch, &child, child_role, 3)
                .edge(&child, EdgeKind::ChildOf, &parent, 1.0)
                .commit();

            if LEGAL.contains(&(parent_role, child_role)) {
                result.unwrap_or_else(|err| {
                    panic!("{parent_role:?} must parent {child_role:?}, got {err:?}")
                });
                assert!(vault.edge_exists(&child, EdgeKind::ChildOf, &parent)?);
                continue;
            }

            let err = result.expect_err(&format!("{parent_role:?} must not parent {child_role:?}"));
            assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
            match err {
                Error::TaskChildOfNesting {
                    parent_role: got_parent,
                    child_role: got_child,
                } => {
                    assert_eq!(got_parent, parent_role.role_byte());
                    assert_eq!(got_child, child_role.role_byte());
                }
                other => panic!("expected a nesting rejection, got {other:?}"),
            }
            assert!(!vault.edge_exists(&child, EdgeKind::ChildOf, &parent)?);
        }
    }

    // A TASK child under a non-TASK parent is an ENDPOINT rejection: there is
    // no parent role to match against, so it is never admitted unchecked.
    let person = EntityId::now();
    let task = EntityId::now();
    let batch = put_plain_node(vault.batch(), &person, 1);
    let err = put_task_role(batch, &task, TaskRole::Task, 3)
        .edge(&task, EdgeKind::ChildOf, &person, 1.0)
        .commit()
        .expect_err("a TASK child under a non-TASK parent must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    match err {
        Error::TaskChildOfParentNotTask {
            child_role,
            parent_entity_type,
        } => {
            assert_eq!(child_role, TaskRole::Task.role_byte());
            assert_eq!(parent_entity_type, ENTITY_TYPE_PERSON);
        }
        other => panic!("expected an endpoint rejection, got {other:?}"),
    }
    assert!(!vault.edge_exists(&task, EdgeKind::ChildOf, &person)?);
    Ok(())
}

#[test]
fn non_task_child_of_keeps_tree_guarantees_without_role_rules() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let root = EntityId::now();
    let mid = EntityId::now();
    let leaf = EntityId::now();

    let batch = put_plain_node(vault.batch(), &root, 1);
    let batch = put_plain_node(batch, &mid, 3);
    put_plain_node(batch, &leaf, 5)
        .edge(&mid, EdgeKind::ChildOf, &root, 1.0)
        .edge(&leaf, EdgeKind::ChildOf, &mid, 1.0)
        .commit()?;

    // Cardinality and cycles still hold for a domain the matrix never reaches.
    let second_parent = EntityId::now();
    let cardinality_err = put_plain_node(vault.batch(), &second_parent, 7)
        .edge(&leaf, EdgeKind::ChildOf, &second_parent, 1.0)
        .commit()
        .expect_err("a non-TASK child still gets one parent");
    assert_matches!(cardinality_err, Error::ChildOfCardinality);

    let cycle_err = vault
        .batch()
        .edge(&root, EdgeKind::ChildOf, &leaf, 1.0)
        .commit()
        .expect_err("a non-TASK cycle is still rejected");
    assert_matches!(cycle_err, Error::CycleDetected);

    // And a missing parent is now rejected here too.
    let absent = EntityId::now();
    let orphan = EntityId::now();
    let dangling_err = put_plain_node(vault.batch(), &orphan, 9)
        .edge(&orphan, EdgeKind::ChildOf, &absent, 1.0)
        .commit()
        .expect_err("a non-TASK dangling parent is rejected");
    match dangling_err {
        Error::ChildOfParentMissing { parent } => assert_eq!(parent, absent),
        other => panic!("expected a dangling-parent rejection, got {other:?}"),
    }

    // The matrix keys off the edge SOURCE: a non-TASK child under a TASK
    // parent carries no role rule at all.
    let task_parent = EntityId::now();
    let plain_child = EntityId::now();
    let batch = put_task_role(vault.batch(), &task_parent, TaskRole::Task, 11);
    put_plain_node(batch, &plain_child, 13)
        .edge(&plain_child, EdgeKind::ChildOf, &task_parent, 1.0)
        .commit()?;
    assert!(vault.edge_exists(&plain_child, EdgeKind::ChildOf, &task_parent)?);
    Ok(())
}

fn first_party_eiri_connector_actor_id() -> Result<EntityId> {
    EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .map_err(|_| Error::InvariantViolation("invalid first-party Eiri actor fixture id"))
}

fn first_party_eiri_connector_actor_ref() -> String {
    crate::gate::first_party_eiri_connector_actor_ref()
}

fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
    let rtxn = vault.store.env.read_txn()?;
    let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
    let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
    let out = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .map(|value| value.to_vec());
    let inn = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .map(|value| value.to_vec());
    Ok((out, inn))
}

fn assert_edge_is_provenanced_reject(err: Error, expected_kind: EdgeKind, context: &str) {
    match err {
        Error::EdgeIsProvenanced { kind } => {
            assert_eq!(kind, expected_kind as u8, "{context}: kind byte");
        }
        other => panic!("{context}: expected EdgeIsProvenanced, got {other:?}"),
    }
}

fn assert_raw_edge_unchanged(
    vault: &Vault,
    edge: &EdgeRef,
    before: &[u8],
    context: &str,
) -> Result<()> {
    let (after_out, after_in) = raw_edge_values(vault, edge)?;
    assert_eq!(
        after_out.as_deref(),
        Some(before),
        "{context}: edges_out must stay byte-identical"
    );
    assert_eq!(
        after_in.as_deref(),
        Some(before),
        "{context}: edges_in must stay byte-identical"
    );
    Ok(())
}

const GITHUB_PAT_SECRET_FIXTURE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

#[test]
fn secret_scan_rejects_known_secret_fixture_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(10, 10);

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .commit()
        .expect_err("known secret fixture must reject before any batch write");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

#[test]
fn secret_scan_allows_non_secret_write_unchanged() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let occurred = test_time_range(20, 20);
    let data = b"ordinary memory body";

    vault
        .batch()
        .put(&id, ENTITY_TYPE_PERSON, occurred, 20, data)
        .text(&id, &[("body", "ordinary memory body")])
        .commit()?;

    assert_eq!(vault.get(&id)?.as_deref(), Some(&data[..]));
    assert_eq!(vault.search_text("ordinary", 10)?.len(), 1);
    Ok(())
}

#[test]
fn secret_scan_rejects_phonetic_payload_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let phonetic_id = EntityId::now();
    let occurred = test_time_range(25, 25);
    let secret_code =
        std::str::from_utf8(GITHUB_PAT_SECRET_FIXTURE).expect("secret fixture is UTF-8");

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            25,
            b"ordinary memory",
        )
        .phonetic(&phonetic_id, &[secret_code])
        .commit()
        .expect_err("known secret fixture in phonetic payload must reject before batch write");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    assert!(vault.get(&safe_id)?.is_none());

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .phonetic_index
            .get(&rtxn, secret_code.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .phonetic_forward
            .get(&rtxn, phonetic_id.as_bytes())?
            .is_none()
    );
    Ok(())
}

#[test]
fn txn_batch_secret_scan_rejects_before_staging_writes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(30, 30);
    let mut wtxn = vault.store.env.write_txn()?;

    let err = vault
        .batch_in()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .apply(&mut wtxn)
        .expect_err("txn batch secret fixture must reject before staging writes");

    assert_secret_scan_rejected(err, "gate.secret_scan.github_token");
    wtxn.commit()?;

    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

fn provenanced_edge_fixture() -> Result<EdgeFixture> {
    let (dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let actor = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &edge,
        &EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    Ok(EdgeFixture {
        _dir: dir,
        vault,
        edge,
        claim_id,
    })
}

fn evidence_entry<'a>(evidence: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = evidence else {
        panic!("expected write envelope evidence map, got {evidence:?}");
    };
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| {
            (entry_key.as_str() == Some(key)).then_some(entry_value)
        })
        .unwrap_or_else(|| panic!("missing evidence key {key:?} in {evidence:?}"))
}

fn has_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault.store.pending_embedding_token(&rtxn, id)?.is_some())
}

fn raw_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key.as_str())?
        .map(|value| value.to_vec()))
}

fn overwrite_pending_embedding_marker(vault: &Vault, id: &EntityId, token: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    vault.store.sync_state.put(&mut wtxn, key.as_str(), token)?;
    wtxn.commit()?;
    Ok(())
}

fn pending_embedding_token(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .pending_embedding_token(&rtxn, id)?
        .ok_or(Error::InvariantViolation("pending embedding token missing"))
}

fn seed_raw_claim_record(vault: &Vault, id: &EntityId, body: ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(&body)?;
    let occurred = test_time_range(30, 30);
    let learned_at = 31_u64;
    let payload = crate::test_util::entity_record(ENTITY_TYPE_CLAIM, occurred, learned_at, &data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &occurred_start_key, &[])?;
    let learned_key = Store::encode_temporal_key(learned_at, id);
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &learned_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

fn seed_stale_vector_state(vault: &Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for component in vector {
        bytes.extend_from_slice(&component.to_le_bytes());
    }
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vectors.put(&mut wtxn, id.as_bytes(), &bytes)?;
    let mut pending_rebuild = false;
    crate::hnsw::hnsw_insert_batched(
        &vault.store,
        &vault.config,
        &mut wtxn,
        id,
        vector,
        &mut pending_rebuild,
    )?;
    crate::hnsw::run_pending_legacy_rebuild(
        &vault.store,
        &vault.config,
        &mut wtxn,
        pending_rebuild,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn seed_claim_of_edge(vault: &Vault, claim: &EntityId, subject: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    apply_edge(
        &vault.store,
        &mut wtxn,
        *claim,
        EdgeKind::ClaimOf,
        *subject,
        1.0,
        Vad::NEUTRAL,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Deliberate gate consequence of the ONE-1645 provenance floor: unstamped
/// ToolOutput queues for consent under the default manifest.
///
/// `default_policy_manifest()` ships ToolOutput `max_auto_sensitivity: 0`.
/// Before the floor, an unstamped claim read band 0 and slipped under that
/// ceiling — the unstamped = public = auto-write fail-open ONE-1645 exists to
/// close. Post-floor the same claim reads band 2, exceeds the ceiling, and the
/// write is rejected `pending` with `gate.pending.source_trust`.
///
/// The manifest ceiling is NOT raised to restore the old outcome: that would
/// re-open the hole. The actor-ceiling grant this fixture also pins is still
/// live and still `Auto` — the second arm proves it by stamping `public` and
/// reaching auto through the very same default manifest.
#[test]
fn fresh_default_policy_manifest_queues_unstamped_tool_output_for_consent() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    let first_party_eiri_actor = first_party_eiri_connector_actor_id()?;
    let first_party_eiri_actor_ref = first_party_eiri_connector_actor_ref();
    let policy = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_actor_ref)),
        crate::gate::PolicyApprovalCeiling::Auto
    );
    assert_eq!(policy.signatures().len(), 1);
    let signed_auto_frontier = policy.read_frontier_hash()?;

    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(
        &first_party_eiri_actor,
        ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"first-party Eiri connector",
    )?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(first_party_eiri_actor, EdgeActorClass::Agent),
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
        .expect_err("unstamped ToolOutput must queue for consent, not auto-write");
    match &err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(*outcome, "pending");
            assert_eq!(reason_codes.as_slice(), ["gate.pending.source_trust"]);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "a consent-queued write must not land"
    );

    // Same actor, same default manifest, same source — only an explicit
    // `public` stamp differs. The actor-ceiling grant is intact; it was the
    // sensitivity ceiling, not the ceiling for this actor, that queued the
    // first write.
    let stamped_claim = EntityId::now();
    let stamped_candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    )
    .with_scope(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));

    vault
        .batch()
        .claim_candidate(
            &stamped_claim,
            stamped_candidate,
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;

    let stored = vault
        .get_claim(&stamped_claim)?
        .expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

    let decisions = vault.store.gate_decisions(10)?;
    let claim_decisions: Vec<_> = decisions
        .iter()
        .filter(|decision| decision.claim_id == Some(*stamped_claim.as_bytes()))
        .collect();
    assert_eq!(
        claim_decisions.len(),
        1,
        "successful claim write must persist exactly one gate decision"
    );
    let decision = claim_decisions[0];
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_eiri_actor_ref.as_str())
    );

    let policy_after_write = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        signed_auto_frontier,
        policy_after_write.read_frontier_hash()?
    );
    Ok(())
}

fn lh_prefixed_id(fill: u8) -> Result<EntityId> {
    let mut raw = [fill; ENTITY_ID_LEN];
    raw[0] = b'L';
    raw[1] = b'H';
    EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid LH fixture id"))
}

fn test_write_envelope(actor: EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Approved,
    ))
}

#[test]
fn write_envelope_validation_rejects_missing_required_axes() -> Result<()> {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let provenance = WriteProvenance::new(Value::from("fixture"))?;

    let err = WriteEnvelope::try_new(
        None,
        Some(ClaimSource::UserStated),
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("actor is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing actor")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        None,
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("source is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing source")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        None,
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("provenance is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        Some(provenance),
        None,
    )
    .expect_err("approval is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing approval")
    ));

    let err = WriteProvenance::new(Value::Nil).expect_err("nil provenance must reject");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));
    Ok(())
}

#[test]
fn claim_candidate_phase_two_validation_failure_leaves_no_orphan_gate_decision() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::now();
    let missing_actor = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(missing_actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    );

    let metric_emissions_before = crate::gate::gate_metric_emission_count_for_test();
    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(1, 1), 2)
        .commit()
        .expect_err("missing actor entity must reject");
    assert!(matches!(err, Error::EntityNotFound));
    assert_eq!(
        crate::gate::gate_metric_emission_count_for_test(),
        metric_emissions_before,
        "a rolled-back gate receipt must not emit committed-decision metrics"
    );
    assert!(vault.get_claim(&claim)?.is_none());
    assert_eq!(
        vault.store.gate_decisions(10)?.len(),
        0,
        "phase-2 validation failure must roll back the gate decision with the claim"
    );
    Ok(())
}

/// A closed off-record fence rejects before standalone preflight can leave a
/// decision receipt behind.
#[test]
fn standalone_claim_write_does_not_record_gate_decision_before_closed_fence_rejection() -> Result<()>
{
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "fenced candidate")?;
    vault.enter_off_record_session("sess-claim-preflight", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-claim-preflight", &claim)?;
    let log = vault.off_record_receipt_log("sess-claim-preflight")?;
    vault.close_off_record_session("sess-claim-preflight", log)?;
    assert!(vault.gate_decisions(10)?.is_empty());

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
        .expect_err("closed fence must reject before the gate decision persists");
    assert_eq!(err.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(vault.gate_decisions(10)?.is_empty());
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

/// Covers the boundary after a standalone preflight has persisted its gate
/// decision but before the apply pass can write the entity: close must remove
/// that receipt when the tagged id remains missing and install the typed
/// closed-fence denial for the late apply.
#[test]
fn off_record_close_removes_preflight_gate_decision_for_never_written_turn() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "preflight-close race")?;
    vault.enter_off_record_session("sess-preflight-close", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-preflight-close", &claim)?;

    let body = candidate.clone().into_claim_body(&envelope);
    vault.with_write_txn(|wtxn| {
        let policy = crate::gate::resolve_policy_manifest(&vault.store, wtxn)?;
        crate::gate::check_claim_policy_for_write(
            &vault.store,
            wtxn,
            &claim,
            &body,
            Some(&envelope),
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
        )
    })?;
    assert_eq!(vault.gate_decisions(10)?.len(), 1);

    let log = vault.off_record_receipt_log("sess-preflight-close")?;
    let outcome = vault.close_off_record_session("sess-preflight-close", log)?;
    assert_eq!(outcome.turns_deleted, 0);
    assert_eq!(outcome.turns_missing, 1);
    assert!(vault.gate_decisions(10)?.is_empty());

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
        .expect_err("closed fence must reject the deferred apply");
    assert_eq!(err.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(vault.gate_decisions(10)?.is_empty());
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_put_is_rejected_while_off_record_fence_is_live() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let turn = EntityId::now();
    vault.enter_off_record_session("sess-replicated-fence", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-replicated-fence", &turn)?;

    let err = vault
        .batch()
        .put_replicated(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            test_time_range(10, 10),
            10,
            b"stale remote off-record turn",
        )
        .commit()
        .expect_err("a remote payload must not materialize under a live fence");

    assert_eq!(err.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
    assert!(vault.get(&turn)?.is_none());
    Ok(())
}

#[test]
fn claim_candidate_write_stamps_approved_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let provenance = Value::Map(vec![(
        Value::from("source_record_id"),
        Value::from("fixture-approved-1"),
    )]);
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(provenance.clone())?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    )
    .with_salience(0.4);

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
    assert_eq!(stored.source, Some(ClaimSource::UserStated));
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.salience, Some(0.4));

    let evidence = stored.evidence.as_ref().expect("envelope evidence");
    match evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
        Value::Binary(bytes) => assert_eq!(bytes.as_slice(), actor.as_bytes()),
        other => panic!("actor evidence must be binary, got {other:?}"),
    }
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).as_u64(),
        Some(EdgeActorClass::Human as u64)
    );
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
        &provenance
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn affect_trigger_batch_helper_writes_and_conflict_uses_claim_lifecycle() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let occurred = test_time_range(1, 1);
    let actor = EntityId::now();
    let person = EntityId::now();
    let trigger = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"person")?;
    vault.put_entity(
        &trigger,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let envelope = test_write_envelope(actor)?;

    let affect_claim = EntityId::now();
    let trigger_value = crate::affect::AffectTriggerValue::new(
        person,
        trigger,
        crate::affect::VadDelta::new(-0.2, 0.4, -0.3)?,
        0.75,
        2,
        9,
    )?;
    vault
        .batch()
        .affect_trigger_claim(
            &affect_claim,
            trigger_value.clone(),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;

    let stored = vault
        .get_claim(&affect_claim)?
        .expect("affect trigger claim stored");
    assert_eq!(
        crate::affect::decode_affect_trigger_claim(&stored)?,
        Some(trigger_value)
    );
    assert_eq!(stored.subject, ClaimSubject::Entity(person));
    assert_eq!(vault.claims_for_subject(&person)?, vec![affect_claim]);

    let open_conflict = EntityId::now();
    let resolved_conflict = EntityId::now();
    vault
        .batch()
        .conflict_open_claim(
            &open_conflict,
            person,
            Value::from("open conflict"),
            0.7,
            &envelope,
            test_time_range(20, 20),
            21,
        )
        .conflict_resolved_claim(
            &resolved_conflict,
            person,
            Value::from("resolved conflict"),
            0.8,
            &envelope,
            test_time_range(22, 22),
            23,
        )
        .commit()?;
    vault.supersede_claim(&resolved_conflict, &open_conflict, 30)?;

    let open_stored = vault
        .get_claim(&open_conflict)?
        .expect("open conflict preserved");
    let resolved_stored = vault
        .get_claim(&resolved_conflict)?
        .expect("resolved conflict active");
    assert_eq!(open_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(resolved_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(open_stored.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(resolved_stored.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_write_read_and_search_source_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &[
                "green tea preferences",
                "  matcha order history  ",
                "green tea preferences",
            ],
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);
    let mut stored_queries = Vec::new();
    for hint_claim in &hint_claims {
        assert!(
            hint_claim
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
        );
        assert!(
            !has_pending_embedding_marker(&vault, hint_claim)?,
            "lexical hint side claims must not be queued for embeddings"
        );
        let stored = vault
            .get_claim(hint_claim)?
            .expect("lexical hint claim stored");
        assert_eq!(stored.predicate, crate::claim::PREDICATE_LEXICAL_QUERY_HINT);
        assert!(stored.stale, "lexical hint side claims are derived data");
        assert_eq!(stored.source, Some(ClaimSource::UserStated));
        assert!(stored.evidence.is_some());
        let value = crate::claim::decode_lexical_query_hint_value(&stored.value)?;
        assert_eq!(value.target, claim);
        stored_queries.push(value.query);
    }
    stored_queries.sort();
    assert_eq!(
        stored_queries,
        vec!["green tea preferences", "matcha order history"]
    );

    let hits = vault.search_text("matcha order", 10)?;
    assert_eq!(hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint docs must collapse to the source claim"
    );
    let ppr_hits = vault.query().search_ppr(&[claim], 2).run()?;
    assert!(
        !ppr_hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint side claims must not surface through PPR"
    );
    let rtxn = vault.store.env.read_txn()?;
    for hint in &hint_claims {
        assert!(
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "lexical hint side claims must not receive public short ids"
        );
    }
    Ok(())
}

#[test]
fn lexical_hint_claim_of_edges_do_not_dilute_ppr_claim_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["ppr synthetic one", "ppr synthetic two"],
        )
        .commit()?;
    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);

    let real_neighbor = EntityId::now();
    let real_neighbor_body = ClaimBody::new(
        "profile.related",
        ClaimSubject::Entity(claim),
        Value::from("real ppr neighbor"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &real_neighbor, real_neighbor_body)?;
    seed_claim_of_edge(&vault, &real_neighbor, &claim)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = crate::ppr::ppr_compute(&vault.store, &rtxn, &[claim], 1, 0.15)?;
    let score_for = |id: EntityId| -> f32 {
        scores
            .iter()
            .find(|scored| scored.id == id)
            .map_or(0.0, |scored| scored.score)
    };
    assert!(
        score_for(real_neighbor) > 0.84,
        "real ClaimOf neighbor should receive the full inbound ClaimOf mass"
    );
    for hint in hint_claims {
        assert_eq!(
            score_for(hint),
            0.0,
            "lexical hint ClaimOf rows must not receive PPR mass"
        );
    }
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_bypass_hint_policy_gate() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["policy bypass lexical hint"],
        )
        .commit()?;

    assert_eq!(
        vault
            .search_text("policy bypass lexical", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn raw_lexical_hint_put_does_not_bypass_policy_gate() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let query = "raw policy lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(20, 20), 21, &data)
        .commit()
        .expect_err("raw lexical hint puts must still pass ordinary policy");
    assert_matches!(err, Error::GateWriteRejected { .. });
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_replace_and_delete_stale_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["retireduniquealpha", "liveuniquebeta"])?;
    let obsolete_hint = lexical_query_hint_claim_id(&claim, "retireduniquealpha")?;
    let live_hint = lexical_query_hint_claim_id(&claim, "liveuniquebeta")?;
    assert!(vault.get_claim(&obsolete_hint)?.is_some());
    assert!(vault.get_claim(&live_hint)?.is_some());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&obsolete_hint)?.is_none());
    assert!(vault.get_claim(&live_hint)?.is_some());
    assert_eq!(vault.claims_for_subject(&claim)?, vec![live_hint]);
    assert!(vault.search_text("retireduniquealpha", 10)?.is_empty());
    assert_eq!(
        vault
            .search_text("liveuniquebeta", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let plain_candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(
            &claim,
            plain_candidate,
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&live_hint)?.is_some());

    vault.batch().delete(&claim).commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());
    Ok(())
}

#[test]
fn local_raw_claim_put_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["rawputretiredunique"],
        )
        .commit()?;

    let hint = lexical_query_hint_claim_id(&claim, "rawputretiredunique")?;
    assert!(vault.get_claim(&hint)?.is_some());
    assert_eq!(
        vault
            .search_text("rawputretiredunique", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("gyokuro"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &replacement, test_time_range(12, 12), 13)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("rawputretiredunique", 10)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn soft_delete_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["soft delete lexical hint"],
        )
        .commit()?;
    let hint = lexical_query_hint_claim_id(&claim, "soft delete lexical hint")?;

    vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("soft delete lexical", 10)?.is_empty());
    Ok(())
}

#[test]
fn plain_overwrite_removes_orphan_lexical_hint_without_claim_of() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stale_query = "legacy orphan lexical hint";
    let orphan_hint = lexical_query_hint_claim_id(&claim, stale_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, stale_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", stale_query)])
        .commit()?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "fixture intentionally omits the legacy hint ClaimOf edge"
    );
    assert_eq!(
        vault
            .search_text(stale_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("hojicha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, replacement, &envelope, test_time_range(12, 12), 13)
        .commit()?;

    assert!(vault.get_claim(&orphan_hint)?.is_none());
    assert!(vault.search_text(stale_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn raw_claim_put_rejects_malformed_lexical_hint_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let hint = EntityId::now();
    let body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        Value::from("not a typed lexical hint value"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("malformed lexical hint values must reject at the write door");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn raw_lexical_hint_put_rejects_non_lh_prefixed_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let target_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &target, target_body)?;

    let mut raw = [0x44; ENTITY_ID_LEN];
    raw[ENTITY_ID_LEN - 1] &= 0x7F;
    let hint =
        EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid test id"))?;
    assert!(
        !hint
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    );
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non lh id hint"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("lexical.query_hint records must live under derived LH ids");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_self_and_synthetic_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "self target")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "self target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    let self_data = crate::claim::encode_claim_body(&self_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: self_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data: self_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("self-target lexical hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&self_hint)?.is_none());

    let source = EntityId::now();
    let source_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &source, source_body)?;
    let synthetic_target = lexical_query_hint_claim_id(&source, "synthetic target")?;
    let mut synthetic_target_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(source),
        crate::claim::encode_lexical_query_hint_value(&source, "synthetic target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_target_body.stale = true;
    seed_raw_claim_record(&vault, &synthetic_target, synthetic_target_body)?;
    let outer_hint = lexical_query_hint_claim_id(&source, "outer target")?;
    let mut synthetic_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(synthetic_target),
        crate::claim::encode_lexical_query_hint_value(&synthetic_target, "outer target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_body.stale = true;
    let synthetic_data = crate::claim::encode_claim_body(&synthetic_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: outer_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(22, 22),
            learned_at: 23,
            data: synthetic_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints targeting synthetic hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&outer_hint)?.is_none());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_non_claim_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    vault.put_entity(
        &target,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"not a claim",
    )?;
    let hint = lexical_query_hint_claim_id(&target, "non claim target")?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non claim target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints must target claim records");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn legacy_cyclic_lexical_hints_delete_without_recursive_cleanup() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let hint_a = lexical_query_hint_claim_id(&EntityId::now(), "cycle a")?;
    let hint_b = lexical_query_hint_claim_id(&EntityId::now(), "cycle b")?;
    let mut body_a = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_b),
        crate::claim::encode_lexical_query_hint_value(&hint_b, "cycle a"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_a.stale = true;
    let mut body_b = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_a),
        crate::claim::encode_lexical_query_hint_value(&hint_a, "cycle b"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_b.stale = true;
    seed_raw_claim_record(&vault, &hint_a, body_a)?;
    seed_raw_claim_record(&vault, &hint_b, body_b)?;
    seed_claim_of_edge(&vault, &hint_a, &hint_b)?;
    seed_claim_of_edge(&vault, &hint_b, &hint_a)?;

    vault.batch().delete(&hint_a).commit()?;

    assert!(vault.get_claim(&hint_a)?.is_none());
    assert!(vault.get_claim(&hint_b)?.is_none());

    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "legacy self")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "legacy self"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    seed_raw_claim_record(&vault, &self_hint, self_body)?;
    seed_claim_of_edge(&vault, &self_hint, &self_hint)?;

    vault.batch().delete(&self_hint).commit()?;

    assert!(vault.get_claim(&self_hint)?.is_none());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_indexes_query_text_and_deletes_without_claim_of() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let query = "replicated rematerialized hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "regression fixture starts without a hint ClaimOf edge"
    );
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &hint)?,
        "replayed lexical hint side claims must not be queued for embeddings"
    );
    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );

    vault.batch().delete(&claim).commit()?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_defers_until_target_claim_materializes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::from_bytes([0x7A; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::Put {
                id: claim,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(10, 10),
                learned_at: 11,
                data: claim_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
        ],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn deferred_lexical_hint_materialization_fails_closed_when_text_index_untrusted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let subject = EntityId::now();
    let claim = EntityId::from_bytes([0x7B; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred trust replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;

    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    {
        let vault = Vault::open(dir.path(), embedding_test_config())?;
        vault
            .batch()
            .put(
                &subject,
                ENTITY_TYPE_PERSON,
                test_time_range(1, 1),
                1,
                b"subject",
            )
            .text(&subject, &[("body", "trusted seed text")])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            }],
            true,
            false,
            false,
        )?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .text_forward
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "missing-target replicated hint must defer text indexing"
        );
    }

    let mut cfg = embedding_test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(dir.path(), cfg)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: claim,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(30, 30),
            learned_at: 31,
            data: claim_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        false,
        false,
        false,
    )
    .expect_err("target-only replay must not index deferred hints while untrusted");
    assert_matches!(err, Error::CorruptedIndex(_));
    drop(wtxn);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, hint.as_bytes())?
            .is_none(),
        "failed deferred materialization must leave hint text unindexed"
    );
    drop(rtxn);
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "failed target replay transaction must not commit the target claim"
    );
    Ok(())
}

#[test]
fn bm25_drops_orphan_and_inactive_lexical_hint_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let missing_hint_query = "missingrowuniquealpha";
    let missing_hint = lexical_query_hint_claim_id(&EntityId::now(), missing_hint_query)?;
    vault
        .batch()
        .text(&missing_hint, &[("query_hint", missing_hint_query)])
        .commit()?;
    assert_eq!(
        vault
            .search_text(missing_hint_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(missing_hint)
    );

    let missing_claim = EntityId::now();
    let orphan_query = "orphanrowuniquebeta";
    let orphan_hint = lexical_query_hint_claim_id(&missing_claim, orphan_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(missing_claim),
        crate::claim::encode_lexical_query_hint_value(&missing_claim, orphan_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", orphan_query)])
        .commit()?;
    assert!(vault.search_text(orphan_query, 10)?.is_empty());

    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;
    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let inactive_query = "inactiverowuniquegamma";
    let inactive_hint = lexical_query_hint_claim_id(&claim, inactive_query)?;
    let mut inactive_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, inactive_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Superseded,
    );
    inactive_body.stale = true;
    seed_raw_claim_record(&vault, &inactive_hint, inactive_body)?;
    vault
        .batch()
        .text(&inactive_hint, &[("query_hint", inactive_query)])
        .commit()?;
    assert!(vault.search_text(inactive_query, 10)?.is_empty());

    let soft_deleted_query = "softdeletedrowuniquedelta";
    let soft_deleted_hint = lexical_query_hint_claim_id(&claim, soft_deleted_query)?;
    let payload =
        crate::test_util::entity_record(ENTITY_TYPE_CLAIM, test_time_range(30, 30), 31, &[]);
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, soft_deleted_hint.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &soft_deleted_hint);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    vault
        .batch()
        .text(&soft_deleted_hint, &[("query_hint", soft_deleted_query)])
        .commit()?;
    assert!(vault.search_text(soft_deleted_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn retained_lexical_hint_reput_clears_stale_vector_and_embedding_state() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = || -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &["retained vector cleanup hint"],
            )
            .commit()
    };

    write_hints()?;
    let hint = lexical_query_hint_claim_id(&claim, "retained vector cleanup hint")?;
    let err = vault
        .put_vector(&hint, &[1.0, 0.0, 0.0, 0.0])
        .expect_err("synthetic lexical hint vectors must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_vector(&hint)?.is_none());
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "rejected vector writes must never expose lexical hints"
    );

    seed_stale_vector_state(&vault, &hint, &[1.0, 0.0, 0.0, 0.0])?;
    overwrite_pending_embedding_marker(&vault, &hint, b"stale lexical hint marker")?;

    assert_eq!(
        vault.get_vector(&hint)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(raw_pending_embedding_marker(&vault, &hint)?.is_some());
    assert!(
        vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "seeded stale vector must be reachable before the retained hint re-put"
    );

    write_hints()?;

    assert!(
        raw_pending_embedding_marker(&vault, &hint)?.is_none(),
        "retained lexical hint re-put must clear stale embedding marker state"
    );
    assert!(
        vault.get_vector(&hint)?.is_none(),
        "retained lexical hint re-put must delete stale vector rows"
    );
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "retained lexical hint must not remain reachable through vector search"
    );
    assert_eq!(
        vault
            .search_text("retained vector cleanup hint", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim),
        "lexical hint text must remain searchable after vector cleanup"
    );
    Ok(())
}

#[test]
fn lh_prefixed_normal_ids_are_not_treated_as_synthetic_hints() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let normal_entity = lh_prefixed_id(0x11)?;
    vault.put_entity(
        &normal_entity,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"ordinary LH-prefixed entity",
    )?;
    vault
        .batch()
        .text(&normal_entity, &[("body", "ordinary LH text")])
        .commit()?;
    assert_eq!(
        vault
            .search_text("ordinary LH text", 10)?
            .first()
            .map(|hit| hit.id),
        Some(normal_entity)
    );
    vault.put_vector(&normal_entity, &[1.0, 0.0, 0.0, 0.0])?;
    assert_eq!(
        vault.get_vector(&normal_entity)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );

    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(2, 2);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 2, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 2, b"subject")?;

    let claim = lh_prefixed_id(0x22)?;
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["normal LH source claim hint"],
        )
        .commit()?;

    assert_eq!(
        vault
            .search_text("normal LH source", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hint_ids_are_order_stable() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["spring roadmap migration", "account recovery plan"])?;
    let mut first_hint_claims = vault.claims_for_subject(&claim)?;
    first_hint_claims.sort();
    assert_eq!(first_hint_claims.len(), 2);

    write_hints(&["account recovery plan", "spring roadmap migration"])?;
    let mut reordered_hint_claims = vault.claims_for_subject(&claim)?;
    reordered_hint_claims.sort();
    assert_eq!(reordered_hint_claims, first_hint_claims);
    assert!(reordered_hint_claims.iter().all(|hint_claim| {
        hint_claim
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    }));

    let roadmap_hits = vault.search_text("spring roadmap migration", 10)?;
    assert_eq!(roadmap_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !roadmap_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );

    let recovery_hits = vault.search_text("account recovery plan", 10)?;
    assert_eq!(recovery_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !recovery_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_are_capped() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    let hints = [
        "hint zero",
        "hint one",
        "hint two",
        "hint three",
        "hint four",
        "hint five",
        "hint six",
        "hint seven",
        "hint eight",
        "hint nine",
    ];

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &hints,
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(
        hint_claims.len(),
        crate::claim::MAX_LEXICAL_QUERY_HINTS_PER_CLAIM
    );
    assert!(
        vault
            .search_text("seven", 10)?
            .iter()
            .any(|hit| hit.id == claim)
    );
    assert!(vault.search_text("nine", 10)?.is_empty());
    Ok(())
}

fn claim_candidate_fixture(vault: &Vault, value: &str) -> Result<(WriteEnvelope, ClaimCandidate)> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
    );
    Ok((envelope, candidate))
}

fn commit_claim_candidate_with_value(vault: &Vault, claim: EntityId, value: &str) -> Result<()> {
    let (envelope, candidate) = claim_candidate_fixture(vault, value)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
}

fn commit_claim_candidate_fixture(vault: &Vault, claim: EntityId) -> Result<()> {
    commit_claim_candidate_with_value(vault, claim, "Alice")
}

#[test]
fn claim_candidate_commit_writes_pending_embedding_marker_before_vector_exists() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();

    commit_claim_candidate_fixture(&vault, claim)?;

    assert!(vault.get_claim(&claim)?.is_some(), "claim must be durable");
    assert!(
        vault.get_vector(&claim)?.is_none(),
        "claim commit must not fabricate a vector row"
    );
    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "claim commit must mark embedding as pending"
    );
    Ok(())
}

#[test]
fn batch_vector_rejects_non_finite_without_persisting_vectors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let good = EntityId::now();
    let bad = EntityId::now();

    let err = vault
        .batch()
        .vector(&good, &[1.0, 0.0, 0.0, 0.0])
        .vector(&bad, &[0.0, f32::NEG_INFINITY, 0.0, 0.0])
        .commit()
        .expect_err("non-finite batch vector must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_negative()
    );
    assert!(vault.get_vector(&good)?.is_none());
    assert!(vault.get_vector(&bad)?.is_none());
    Ok(())
}

#[test]
fn vector_fill_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "vector fill must clear the pending marker"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "token-proven vector fill must remove durable marker state"
    );
    Ok(())
}

#[test]
fn pending_vector_fill_rejects_non_finite_without_clearing_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    let err = vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, f32::INFINITY, 0.0, 0.0], &token)
        .commit()
        .expect_err("non-finite pending vector fill must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_positive()
    );
    assert!(vault.get_vector(&claim)?.is_none());
    assert_eq!(pending_embedding_token(&vault, &claim)?, token);
    Ok(())
}

#[test]
fn duplicate_vector_fill_keeps_pending_embedding_marker_cleared() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "duplicate fills must be idempotent"
    );
    assert_eq!(
        vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn plain_vector_fill_keeps_current_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        token,
        "un-tokened vector fills cannot prove they embedded the current claim body"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_claim_materialization_writes_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("replicated Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "replicated claim materialization must request embedding"
    );
    assert!(
        !pending_embedding_token(&vault, &claim)?.is_empty(),
        "replicated marker must carry a body token"
    );
    Ok(())
}

#[cfg(feature = "sync")]
fn authority_test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(feature = "sync")]
fn authority_key_from_signing(signing: &SigningKey) -> crate::authority::AuthorityKey {
    crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

#[cfg(feature = "sync")]
fn authority_test_device(key: crate::authority::AuthorityKey) -> crate::authority::DeviceAuthority {
    crate::authority::DeviceAuthority {
        key,
        transport_key_binding: [0; 32],
        attestation: crate::authority::AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: crate::authority::AuthorityTier::Software,
        roles: crate::authority::ROLE_OWNER,
    }
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: authority_test_device(key.clone()),
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_enroll_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: authority_test_device(new_key),
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_first_seen_for_test(vault: &Vault, key: &str) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key)?
        .and_then(|raw| crate::authority::decode_authority_first_seen_secs(&raw)))
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_sidecar_drives_live_fold() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = authority_test_key(74);
    let genesis = authority_genesis_fixture(74);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 75, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(75));

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let enroll_id = vault.put_authority_log_entry(&enroll, test_time_range(2, 2), 2)?;

    let first_seen = authority_first_seen_for_test(&vault, &enroll_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    let fold = vault.authority_fold()?;
    assert!(fold.pending_widens.contains_key(&enroll_hash));
    assert!(!fold.roster.contains_key(&enroll_key));

    let replayed_id = vault.put_authority_log_entry(&enroll, test_time_range(3, 3), 999_999)?;
    assert_eq!(
        replayed_id, enroll_id,
        "a byte-identical replay must land on the same content-derived store key"
    );
    assert_eq!(
        authority_first_seen_for_test(&vault, &enroll_sidecar)?,
        Some(first_seen),
        "metadata-only rewrites must not move local first-seen"
    );

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_sidecar_fold = vault.authority_fold()?;
    assert_eq!(
        missing_sidecar_fold
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None,
        "missing local first-seen data must fail closed instead of trusting entity metadata"
    );
    assert!(!missing_sidecar_fold.roster.contains_key(&enroll_key));
    Ok(())
}

/// ONE-1604-D1 T4: the write door derives the store key from the entry's
/// content hash and returns it; the row is readable under exactly that id.
#[cfg(feature = "sync")]
#[test]
fn put_authority_log_entry_returns_derived_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(90);
    let hash = crate::authority::authority_entry_hash(&genesis)?;

    let id = vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;

    assert_eq!(
        id.as_bytes(),
        &hash[..16],
        "the store key must be the first 16 bytes of the entry hash"
    );
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));
    Ok(())
}

/// ONE-1604-D1 T1: the ONE-1604 regression — an existing type-122 row can no
/// longer be body-replaced at its store key. A replicated write carrying a
/// DIFFERENT valid signed body for an occupied derived id is rejected (the
/// divergent body derives a different key, so the bind refuses it); the
/// stored bytes and the fold are unchanged. This is the LWW hole closing:
/// before the keystone this same write silently overwrote folded history.
#[cfg(feature = "sync")]
#[test]
fn authority_log_body_divergent_overwrite_rejected_at_store_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(91);
    let id = vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let stored = vault.get_raw(&id)?.expect("authority row must be stored");
    let vault_id_before = vault.authority_fold()?.vault_id;

    // A different, independently valid signed entry — divergent bytes staged
    // at the FIRST entry's occupied store key.
    let divergent = authority_genesis_fixture(92);
    let divergent_body = crate::authority::encode_authority_log_entry_body(&divergent)?;
    let err = vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &divergent_body,
        )
        .commit()
        .expect_err("body-divergent overwrite of a type-122 row must be rejected");

    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert_eq!(
        vault.get_raw(&id)?,
        Some(stored),
        "local bytes must be kept"
    );
    assert_eq!(vault.authority_fold()?.vault_id, vault_id_before);
    Ok(())
}

/// ONE-1604-D1 T2: a valid entry offered under a NON-derived id is refused at
/// the chokepoint, and nothing is stored under either key.
#[cfg(feature = "sync")]
#[test]
fn authority_log_store_key_mismatch_rejected() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(95);
    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let owner = authority_test_key(95);
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 96, 1);
    let enroll_body = crate::authority::encode_authority_log_entry_body(&enroll)?;
    let derived = crate::authority::authority_log_entity_id(&enroll)?;
    let wrong_id = EntityId::now();

    let err = vault
        .batch()
        .put_replicated(
            &wrong_id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &enroll_body,
        )
        .commit()
        .expect_err("a type-122 row under a non-derived id must be rejected");

    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert!(!vault.entity_exists(&wrong_id)?);
    assert!(!vault.entity_exists(&derived)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 1, P2-a — chokepoint half): the local write door
/// applies the same dominance as the replicated one. A cross-type squatter at
/// a derived type-122 key is evicted WITH its indexes — a stale type_index or
/// short-id row pointing at an authority body would corrupt reads — and the
/// same-type append-only rule is untouched by the change.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_cross_type_squatter_and_its_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(97);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    vault.put_entity(
        &derived,
        crate::registry::ENTITY_TYPE_EVENT,
        test_time_range(1, 1),
        1,
        b"squatter",
    )?;
    assert!(vault.entity_exists(&derived)?);

    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis.clone()));

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(crate::registry::ENTITY_TYPE_EVENT, &id)
            )?
            .is_none(),
        "the evicted squatter must leave no type_index row behind"
    );
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(ENTITY_TYPE_AUTHORITY_LOG, &id)
            )?
            .is_some(),
        "the authority row must own the type_index entry at its derived key"
    );
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "the squatter's short-id rows must not survive the eviction"
    );
    drop(rtxn);

    // Same-type append-only is unchanged: a divergent body still cannot
    // overwrite an admitted authority row (it derives a different key).
    let divergent = authority_genesis_fixture(98);
    let divergent_body = crate::authority::encode_authority_log_entry_body(&divergent)?;
    let err = vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(3, 3),
            3,
            &divergent_body,
        )
        .commit()
        .expect_err("dominance must not weaken the same-type append-only guard");
    assert_eq!(err.kind(), ErrorKind::AuthorityLogStoreKeyMismatch);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, LMDB door): evicting a squatter's ENTITY row is
/// only half the eviction — its incident EDGES are keyed independently
/// (`src|kind|tgt`), so an entity-only eviction would leave a revoked
/// squatter traversable through the graph at a key the authority substrate
/// took over. `deindex_entity` → `delete_related_edges` already sweeps both
/// directions; this pins that guarantee against a future narrowing of the
/// eviction, and is the LMDB twin of the reverse-remat edge sweep.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_cross_type_squatter_incident_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(101);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC1; 16])?;

    for (id, body) in [(&derived, b"squatter"), (&neighbor, b"neighbor")] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_EVENT,
            test_time_range(1, 1),
            1,
            body.as_slice(),
        )?;
    }
    // Both directions: the squatter as edge SOURCE and as edge TARGET.
    vault
        .batch()
        .edge(&derived, EdgeKind::Mentions, &neighbor, 1.0)
        .edge(&neighbor, EdgeKind::Mentions, &derived, 1.0)
        .commit()?;
    assert_eq!(vault.edges_out(&derived)?.len(), 1);
    assert_eq!(vault.edges_in(&derived)?.len(), 1);

    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    assert!(
        vault.edges_out(&derived)?.is_empty(),
        "the squatter's outbound edge rows must not survive the eviction"
    );
    assert!(
        vault.edges_in(&derived)?.is_empty(),
        "the squatter's inbound edge rows must not survive the eviction"
    );
    // The mirrored rows on the NEIGHBOUR's side are the ones a one-sided
    // sweep would strand — they still name the evicted id.
    assert!(
        vault.edges_out(&neighbor)?.is_empty() && vault.edges_in(&neighbor)?.is_empty(),
        "the neighbour's mirrored edge rows must not keep the evicted id reachable"
    );
    Ok(())
}

/// Plants a type-76 (IDENTITY_TOPOLOGY_EVENT) row through the shared write
/// chokepoint, the way the sync ingest door stores a replicated record.
#[cfg(feature = "sync")]
fn put_identity_topology_event_for_test(
    vault: &Vault,
    id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    let data = crate::identity_topology::encode_identity_topology_event_body(record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            occurred: test_time_range(1, 1),
            learned_at: 1,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Plants a type-76 record at `id` through the REPLICATED INGEST door, so the
/// full ARCH-0055 shell reconciliation runs exactly as it does for an honest
/// peer record — the only way to get a squatter that has really installed
/// participant edges.
#[cfg(feature = "sync")]
fn ingest_replicated_identity_topology_event_for_test(
    vault: &Vault,
    id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    let body = crate::identity_topology::encode_identity_topology_event_body(record)?;
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    blob.push(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT);
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&1u64.to_be_bytes());
    blob.extend_from_slice(&body);
    let header = EntityMetadataHeader::parse(&blob).expect("blob header");
    vault.with_write_txn(|wtxn| {
        crate::sync::bridge::ingest_replicated_identity_topology_event_in_txn(
            vault, wtxn, id, &header, &blob, &body, 7,
        )
        .map(|_| ())
    })
}

/// A structural (mergeable) participant row materialized at `id`.
#[cfg(feature = "sync")]
fn put_topology_participant_for_test(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    vault.put_entity(id, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, body)
}

/// Asserts BOTH halves of the canonical shell pair agree with `present` — a
/// one-sided sweep leaves the mirrored `edges_in` row naming a peer with no
/// ledger writer, which is the residue these regressions exist to catch.
#[cfg(feature = "sync")]
fn assert_shell_edge_pair(
    vault: &Vault,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    present: bool,
    context: &str,
) -> Result<()> {
    assert_eq!(
        vault.edge_exists(src, kind, tgt)?,
        present,
        "{context}: outbound {kind:?} edge presence"
    );
    assert_eq!(
        vault
            .edges_in(tgt)?
            .iter()
            .any(|edge| edge.kind == kind && edge.target == *src),
        present,
        "{context}: inbound {kind:?} mirror presence"
    );
    Ok(())
}

/// ONE-1604-D1 PRECEDENCE PIN (fix-leg 3): authority dominance outranks
/// delete protection. `registry::is_delete_protected_engine_record` covers
/// type-76 IDENTITY_TOPOLOGY_EVENT, and every ordinary delete door refuses
/// that kind — but a type-76 row squatting a validated type-122 row's
/// CONTENT-DERIVED store key is evicted anyway. It has to be: the key is a
/// pure function of fully-validated authority bytes, so a type-76 body can
/// never legitimately hash there; the eviction UNWINDS the squatter's induced
/// shell effects via explicit-source reconciliation (fix-leg 4, pinned by
/// `authority_dominance_unwinds_evicted_type_76_participant_shell_edges`), so
/// for a copied row it is curative; and exempting the protected band would
/// hand a squatter a protected band to suppress a pending RevokeDevice from —
/// the D1 attack dominance exists to close.
///
/// If someone later narrows the eviction to spare delete-protected kinds,
/// THIS TEST MUST FAIL. That is its job: the precedence is a ratified design
/// decision (`gseal-wave2-p1-adjudication`), so changing it needs a design
/// conversation, not a silent edit.
#[cfg(feature = "sync")]
#[test]
fn authority_log_put_evicts_delete_protected_squatter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(103);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;
    let survivor = EntityId::from_bytes([0xD1; 16])?;
    let loser = EntityId::from_bytes([0xD2; 16])?;
    let squatter_record = crate::identity_topology::StoredIdentityOpEvent {
        seq: 50,
        at: 1,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: crate::identity_topology::StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };

    // The squatter is a REAL delete-protected row at the derived key.
    put_identity_topology_event_for_test(&vault, &derived, &squatter_record)?;
    assert_eq!(
        vault.identity_topology_event(&derived)?.as_ref(),
        Some(&squatter_record),
        "fixture must plant a genuine type-76 row at the derived authority key"
    );

    // Dominance wins: the protected occupant is evicted and the authority
    // row owns its content-derived key.
    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2).expect(
        "authority dominance must evict a delete-protected squatter; if this now fails the eviction was narrowed to exempt protected kinds — that reopens the D1 revocation-suppression squat",
    );
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, &id)
            )?
            .is_none(),
        "the evicted type-76 squatter must leave no type_index row behind"
    );
    assert!(
        vault
            .store
            .type_index
            .get(
                &rtxn,
                &Store::encode_type_key(ENTITY_TYPE_AUTHORITY_LOG, &id)
            )?
            .is_some(),
        "the authority row must own the type_index entry at its derived key"
    );
    // Curative, not destructive: the ledger fold no longer sees the copied
    // event, so a replayed type-76 body cannot be counted twice.
    assert!(
        vault.identity_topology_events_in_txn(&rtxn)?.is_empty(),
        "the evicted copy must leave the type-76 ledger family empty"
    );
    drop(rtxn);

    // Control: delete protection for type-76 is genuinely LIVE at an
    // ordinary id — the eviction above is a scoped precedence rule, not a
    // hole in `is_delete_protected_engine_record`.
    let protected = EntityId::from_bytes([0xD3; 16])?;
    put_identity_topology_event_for_test(&vault, &protected, &squatter_record)?;
    let err = vault
        .batch()
        .delete(&protected)
        .commit()
        .expect_err("type-76 rows must stay delete-protected at their own ids");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
    assert!(vault.entity_exists(&protected)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4): evicting a type-76 squatter must UNWIND the shell
/// edges the reconciler installed FROM it.
///
/// The pin above argued eviction "orphans no legitimate structure" because a
/// type-76 event's shell edges name its own id. That is false in the one case
/// that matters. A squatter arriving through the replicated-ingest door is
/// enumerated by `reconcile_identity_topology_edges_in_txn` like any ledger
/// event, so by eviction time it has installed REAL `merged_into` edges on
/// live PARTICIPANT entities — ids the squatter merely names. `deindex_entity`
/// removes only edges incident to the EVENT id, and once the event row is
/// gone it is no longer enumerable, so the full reconciler (touched set
/// derived from SURVIVING events) can never repair those participant edges.
///
/// Left standing they are shell edges with no ledger writer: the ARCH-0055
/// wedge — participant undo hits `EntityNotFound`, the loser stays
/// permanently redirected — reached through authority dominance, i.e. exactly
/// the state type-76 delete protection exists to prevent.
///
/// MUTATION PROBE: drop the explicit-source reconciliation at the end of
/// `apply_ops` and this test fails on the surviving `loser -> survivor` edge.
#[cfg(feature = "sync")]
#[test]
fn authority_dominance_unwinds_evicted_type_76_participant_shell_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(104);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    // Structural participants must be MATERIALIZED, else the reconciler
    // defers and no shell edge is ever installed (the bug needs a real one).
    let survivor = EntityId::from_bytes([0xE1; 16])?;
    let loser = EntityId::from_bytes([0xE2; 16])?;
    put_topology_participant_for_test(&vault, &survivor, b"survivor")?;
    put_topology_participant_for_test(&vault, &loser, b"loser___")?;

    let squatter_record = crate::identity_topology::StoredIdentityOpEvent {
        seq: 50,
        at: 1,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: crate::identity_topology::StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    ingest_replicated_identity_topology_event_for_test(&vault, &derived, &squatter_record)?;

    // PRECONDITION: the induced participant edge genuinely EXISTS. Without
    // it the test proves nothing about unwinding.
    assert!(
        vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "fixture precondition: the squatter must induce a real shell edge on the participants"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        crate::identity_topology::EntityLifecycleState::Merged
    );

    // Admit the authority row; dominance evicts the squatter.
    let id = vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?;
    assert_eq!(id, derived);
    assert_eq!(vault.get_authority_log_entry(&id)?, Some(genesis));

    // The event's own edges were never the problem — these are the
    // PARTICIPANT edges the event induced on ids it merely named.
    assert!(
        !vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "the evicted event's induced shell edge must be unwound, not left dangling"
    );
    assert!(
        vault.edges_out(&loser)?.is_empty() && vault.edges_in(&survivor)?.is_empty(),
        "no half of the shell pair may survive its ledger justification"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "with its event gone the loser must fold back to Active"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&survivor)?,
        crate::identity_topology::EntityLifecycleState::Active
    );

    // The ARCH-0055 wedge itself: with the edge gone, the participants are
    // ordinary Active entities again — a fresh merge applies instead of
    // rejecting `NotActive`, and its undo resolves instead of wedging.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    let op =
        crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![loser],
            survivor,
            evidence: crate::identity_topology::IdentityOpEvidence::default(),
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        });
    let event = match vault.apply_identity_topology_op(&op, &write, 3)? {
        crate::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("a post-eviction merge must apply, got {other:?}"),
    };
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    vault
        .undo_identity_topology_event(&event, &write, 4)
        .expect("undo must resolve, not hit EntityNotFound on an orphaned shell");
    assert!(!vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5), direction 1 — evicting an APPLY event UNLOCKS a
/// later merge, so an edge must be CREATED on a participant the evicted event
/// never named.
///
/// Fold shape: squatter apply `T([A] -> B)` shells `A`, which makes the later
/// honest merge `M([A, C] -> D)` fold to REJECTED (`A` is not Active), so `C`
/// carries no edge. Dominance then evicts `T`. `A` folds back to Active, `M`
/// becomes effective, and BOTH `A -> D` and `C -> D` are now mandated — but
/// `C` is not in `T`'s captured source set, so leg 4's explicit-source-only
/// pass never visits it.
///
/// Leg 4's pass alone leaves `C` Active with no edge while the ledger says
/// Merged: the fold and the edge witness disagree, so an undo of `M` is
/// rejected `NotCurrent` and `C`'s topology is permanently stuck.
#[cfg(feature = "sync")]
#[test]
fn evicting_an_apply_creates_unlocked_merge_edges_on_undirect_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(105);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    let a = EntityId::from_bytes([0x51; 16])?;
    let b = EntityId::from_bytes([0x52; 16])?;
    let c = EntityId::from_bytes([0x53; 16])?;
    let d = EntityId::from_bytes([0x54; 16])?;
    put_topology_participant_for_test(&vault, &a, b"aaaaaaaa")?;
    put_topology_participant_for_test(&vault, &b, b"bbbbbbbb")?;
    put_topology_participant_for_test(&vault, &c, b"cccccccc")?;
    put_topology_participant_for_test(&vault, &d, b"dddddddd")?;

    // T: the squatter apply, at the authority row's derived key.
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &derived,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 40,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a],
                survivor: b,
            },
        },
    )?;
    // M: a LATER multi-participant merge sharing only `A` with T. It folds
    // rejected while T stands, so neither of its sources is shelled.
    let m = EntityId::from_bytes([0x11; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &m,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 41,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a, c],
                survivor: d,
            },
        },
    )?;

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, true, "precondition T")?;
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        false,
        "precondition M",
    )?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "precondition: M is rejected while T shells A, so C is untouched"
    );

    // Dominance evicts T. The replay makes M effective.
    assert_eq!(
        vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?,
        derived
    );

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, false, "T unwound")?;
    assert_shell_edge_pair(
        &vault,
        &a,
        EdgeKind::MergedInto,
        &d,
        true,
        "M direct source",
    )?;
    // THE FINDING: C is only reachable through the SURVIVING family.
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        true,
        "M's other source, never named by the evicted event",
    )?;
    for shelled in [&a, &c] {
        assert_eq!(
            vault.entity_lifecycle_state(shelled)?,
            crate::identity_topology::EntityLifecycleState::Merged,
            "the unlocked merge must shell BOTH of its sources"
        );
    }

    // The fold and the edge witness must agree well enough that the follow-up
    // undo of M resolves rather than rejecting NotCurrent.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    vault
        .undo_identity_topology_event(&m, &write, 3)
        .expect("undoing the unlocked merge must resolve for BOTH sources");
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, false, "M undone")?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5), direction 2 — evicting an UNDO event RE-LOCKS the
/// event it reverted, so an edge must be REMOVED from a participant the
/// evicted undo never named. This is the finder's exact shape and the
/// MUTATION PROBE: drop the surviving-family half of
/// `reconcile_shell_edges_after_eviction_in_txn` and this test fails on the
/// surviving `C -> D` edge.
///
/// Fold shape: honest merge `T([A] -> B)`; squatter undo `U(T)` at the
/// authority row's derived key, which reverts T and lets the later honest
/// merge `M([A, C] -> D)` apply, shelling `A` and `C`. Dominance evicts `U`.
/// T is effective again, so `M` folds to REJECTED and BOTH `A -> D` and
/// `C -> D` must go. `U` names only `A` (through the one-hop walk to T), so
/// leg 4's capture reaches `A` and stops — `C` keeps a `merged_into D` edge
/// no surviving ledger event justifies, which is the ARCH-0055 wedge one hop
/// out from where leg 4 closed it.
#[cfg(feature = "sync")]
#[test]
fn evicting_an_undo_removes_relocked_merge_edges_on_undirect_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(106);
    let derived = crate::authority::authority_log_entity_id(&genesis)?;

    let a = EntityId::from_bytes([0x61; 16])?;
    let b = EntityId::from_bytes([0x62; 16])?;
    let c = EntityId::from_bytes([0x63; 16])?;
    let d = EntityId::from_bytes([0x64; 16])?;
    put_topology_participant_for_test(&vault, &a, b"aaaaaaaa")?;
    put_topology_participant_for_test(&vault, &b, b"bbbbbbbb")?;
    put_topology_participant_for_test(&vault, &c, b"cccccccc")?;
    put_topology_participant_for_test(&vault, &d, b"dddddddd")?;

    let t = EntityId::from_bytes([0x22; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &t,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 40,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a],
                survivor: b,
            },
        },
    )?;
    // U: the squatter, an UNDO of T, parked at the authority row's key.
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &derived,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 41,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Undo { target: t },
        },
    )?;
    // M: applies only because U reverted T.
    let m = EntityId::from_bytes([0x33; 16])?;
    ingest_replicated_identity_topology_event_for_test(
        &vault,
        &m,
        &crate::identity_topology::StoredIdentityOpEvent {
            seq: 42,
            at: 1,
            actor: None,
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: crate::identity_topology::StoredIdentityOpAction::Merge {
                sources: vec![a, c],
                survivor: d,
            },
        },
    )?;

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, false, "T reverted")?;
    assert_shell_edge_pair(
        &vault,
        &a,
        EdgeKind::MergedInto,
        &d,
        true,
        "M direct source",
    )?;
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, true, "M other source")?;
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Merged
    );

    // Dominance evicts U. The replay re-locks T and rejects M.
    assert_eq!(
        vault.put_authority_log_entry(&genesis, test_time_range(2, 2), 2)?,
        derived
    );

    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &b, true, "T re-locked")?;
    assert_shell_edge_pair(&vault, &a, EdgeKind::MergedInto, &d, false, "M rejected")?;
    // THE FINDING / MUTATION PROBE: C is neither U's direct source nor
    // reachable through U's one-hop walk to T.
    assert_shell_edge_pair(
        &vault,
        &c,
        EdgeKind::MergedInto,
        &d,
        false,
        "M's other source must lose the edge no surviving event justifies",
    )?;
    assert_eq!(
        vault.entity_lifecycle_state(&a)?,
        crate::identity_topology::EntityLifecycleState::Merged,
        "A is shelled by the re-locked T, not by the rejected M"
    );
    assert_eq!(
        vault.entity_lifecycle_state(&c)?,
        crate::identity_topology::EntityLifecycleState::Active,
        "with M rejected, C must fold back to Active"
    );

    // C is an ordinary Active entity again: a fresh merge applies instead of
    // rejecting NotActive, and its undo resolves instead of wedging.
    let write = crate::identity_topology::IdentityOpWrite::auto(ClaimSource::UserStated);
    let op =
        crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![c],
            survivor: d,
            evidence: crate::identity_topology::IdentityOpEvidence::default(),
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        });
    let event = match vault.apply_identity_topology_op(&op, &write, 3)? {
        crate::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("a post-eviction merge on C must apply, got {other:?}"),
    };
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, true, "fresh merge")?;
    vault
        .undo_identity_topology_event(&event, &write, 4)
        .expect("undo must resolve, not hit a stranded shell");
    assert_shell_edge_pair(&vault, &c, EdgeKind::MergedInto, &d, false, "fresh undo")?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_write_does_not_mark_legacy_backfill_complete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(86);

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(
                &rtxn,
                crate::authority::authority_first_seen_backfill_sync_key(),
            )?
            .is_none(),
        "a single authority write must not suppress the legacy sidecar scan"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_ignores_future_learned_at_metadata() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(87);
    let genesis_hash = crate::authority::authority_entry_hash(&genesis)?;
    let genesis_sidecar = crate::authority::authority_first_seen_sync_key(&genesis_hash);
    let future_learned_at = crate::unix_seconds_now()
        .saturating_add(crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS);

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), future_learned_at)?;

    let first_seen = authority_first_seen_for_test(&vault, &genesis_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    assert!(
        first_seen < future_learned_at,
        "local first-seen must come from local observation time, not future learned_at metadata"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_fold_backfills_legacy_missing_first_seen_sidecars_once() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = authority_test_key(84);
    let genesis = authority_genesis_fixture(84);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 85, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(85));

    vault.put_authority_log_entry(&genesis, test_time_range(1, 1), 1)?;
    vault.put_authority_log_entry(&enroll, test_time_range(2, 2), 2)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        vault.store.sync_state.delete(
            wtxn,
            crate::authority::authority_first_seen_backfill_sync_key(),
        )?;
        Ok(())
    })?;

    let observed_before = crate::unix_seconds_now();
    let backfilled_fold = vault.authority_fold()?;
    // fix-leg 4: the migration dates a legacy row at LOCAL OBSERVATION time, not
    // at the peer-written `learned_at` in its header. Trusting the header let a
    // sidecar-less `EnrollDevice` claiming `learned_at = 0` present as matured
    // before it arrived. The consequence here is that the migrated enrollment
    // starts its delay now, so it stays PENDING and its key stays out of the
    // roster — a legacy widen serves its window once rather than skipping it.
    let migrated = authority_first_seen_for_test(&vault, &enroll_sidecar)?
        .expect("migration must write a sidecar");
    assert!(
        migrated >= observed_before,
        "migrated first-seen must be the local observation ({migrated}), not learned_at (2)"
    );
    assert!(
        backfilled_fold.pending_widens.contains_key(&enroll_hash),
        "an enrollment first observed at migration time is inside its delay"
    );
    assert!(!backfilled_fold.roster.contains_key(&enroll_key));

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_after_marker = vault.authority_fold()?;
    assert!(
        !missing_after_marker.roster.contains_key(&enroll_key),
        "after migration, a missing sidecar must still fail closed"
    );
    assert_eq!(
        missing_after_marker
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_authority_log_rejects_foreign_vault_root() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let local = authority_genesis_fixture(72);
    vault.put_authority_log_entry(&local, test_time_range(1, 1), 1)?;

    // The row carries its own CORRECT content-derived id, so the store-key
    // bind passes and the foreign-root rejection is what is actually under
    // test (ONE-1604-D1 checks precede the vault-id fold check).
    let foreign = authority_genesis_fixture(73);
    let foreign_body = crate::authority::encode_authority_log_entry_body(&foreign)?;
    let foreign_id = crate::authority::authority_log_entity_id(&foreign)?;
    let err = vault
        .batch()
        .put_replicated(
            &foreign_id,
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &foreign_body,
        )
        .commit()
        .expect_err("foreign authority log must not enter replicated storage");

    assert_eq!(err.kind(), ErrorKind::InvalidAuthorityLogBody);
    Ok(())
}

#[test]
fn stale_vector_fill_does_not_clear_or_overwrite_newer_claim_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &old_token)
        .commit()?;
    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &old_token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "stale fill must not overwrite the current vector row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "stale fill must leave the newer marker token pending"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &new_token)
        .commit()?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "current-token fill must clear the marker"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([0.0, 1.0, 0.0, 0.0].as_slice())
    );
    Ok(())
}

#[test]
fn plain_vector_fill_does_not_clear_stale_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );
    overwrite_pending_embedding_marker(&vault, &claim, &old_token)?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "stale marker token must not report as current pending work"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(old_token.as_slice()),
        "plain vector fills must not clear stale markers by id alone"
    );
    Ok(())
}

#[test]
fn plain_vector_fill_after_claim_overwrite_keeps_newer_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "legacy vector path still writes the row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "un-tokened vector fills must not clear a newer pending marker"
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(new_token.as_slice()),
        "the durable marker row must remain for the current claim body"
    );
    Ok(())
}

#[test]
fn same_batch_claim_then_vector_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "same-batch vector after claim materialization proves freshness"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "same-batch vector after claim must remove durable marker state"
    );
    Ok(())
}

#[test]
fn same_batch_delete_clears_pending_embedding_token_cache_before_plain_vector() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .delete(&claim)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        vault.get_claim(&claim)?.is_none(),
        "delete must remove the same-batch claim materialization"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "delete must not leave a stale same-batch token that drops later vectors"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "delete must clear durable pending marker state"
    );
    Ok(())
}

#[test]
fn same_batch_vector_then_claim_leaves_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "vector before claim materialization cannot prove it embedded the claim"
    );
    Ok(())
}

#[test]
fn soft_delete_removes_pending_embedding_state_for_claim_shell() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    assert!(has_pending_embedding_marker(&vault, &claim)?);

    let outcome = vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "soft-erased header-only claims must not remain pending"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "soft delete must remove the durable marker row, not only hide API-visible pending state"
    );
    Ok(())
}

#[test]
fn raw_public_batch_put_rejects_claim_without_write_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    let data = crate::claim::encode_claim_body(&body)?;

    let batch_claim = EntityId::now();
    let err = vault
        .batch()
        .put(
            &batch_claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &data,
        )
        .commit()
        .expect_err("raw batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&batch_claim)?.is_none());

    let txn_claim = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(
                    &txn_claim,
                    ENTITY_TYPE_CLAIM,
                    test_time_range(1, 1),
                    2,
                    &data,
                )
                .apply(wtxn)
        })
        .expect_err("raw transaction-batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&txn_claim)?.is_none());
    Ok(())
}

#[test]
fn raw_public_put_rejects_legacy_generated_code_revision_without_auto_permit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "code.revision",
        ClaimSubject::Entity(subject),
        Value::from("finalized"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    let data = crate::claim::encode_claim_body(&body)?;

    let claim = EntityId::now();
    let err = vault
        .put_entity(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .expect_err("generated source requires explicit auto permit");
    assert!(matches!(
        err,
        Error::SourceNotTrustedForAuto {
            claim_source: "generated"
        }
    ));
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

#[test]
fn claim_candidate_overwrite_reconciles_claim_of_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject_a = EntityId::now();
    let subject_b = EntityId::now();
    let edge_source = EntityId::now();
    let edge_target = EntityId::now();
    let occurred = test_time_range(1, 1);
    for (id, body) in [
        (actor, b"actor".as_slice()),
        (subject_a, b"subject-a".as_slice()),
        (subject_b, b"subject-b".as_slice()),
        (edge_source, b"edge-source".as_slice()),
        (edge_target, b"edge-target".as_slice()),
    ] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred, 1, body)?;
    }

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_a),
                Value::from("Alice"),
                0.9,
            ),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;
    assert_eq!(vault.claims_for_subject(&subject_a)?, vec![claim]);

    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_b),
                Value::from("Bob"),
                0.8,
            ),
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_a)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject_b)?, vec![claim]);

    let edge_subject = ClaimSubject::Edge {
        source: edge_source,
        kind: EdgeKind::Supports,
        target: edge_target,
    };
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "graph.observation",
                edge_subject,
                Value::from("supports"),
                0.7,
            ),
            &envelope,
            test_time_range(14, 14),
            15,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_b)?.is_empty());
    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.subject, edge_subject);
    assert!(
        vault
            .edges_out(&claim)?
            .iter()
            .all(|edge| edge.kind != EdgeKind::ClaimOf),
        "edge-subject overwrite must remove stale ClaimOf rows"
    );
    Ok(())
}

#[test]
fn public_timestamped_builder_rejects_over_provenanced_edge() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let vad = Vad {
        valence: 0.1,
        arousal: 0.2,
        dominance: 0.3,
    };

    let (before_out, before_in) = raw_edge_values(vault, &fixture.edge)?;
    let before_out = before_out.expect("provenanced edge");
    assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at(&src, kind, &tgt, 0.5, 2_000)
        .commit()
        .expect_err("batch edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at",
    )?;

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_001, vad)
        .commit()
        .expect_err("batch edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at_and_vad",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at(&src, kind, &tgt, 0.5, 2_002)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_003, vad)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at_and_vad",
    )?;

    let claim = vault
        .get_claim(&fixture.claim_id)?
        .expect("provenance claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn public_timestamped_builder_accepts_over_bare_edge() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let src = EntityId::now();
    let tgt = EntityId::now();
    let absent_tgt = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&absent_tgt, ENTITY_TYPE_PERSON, occurred, 1, b"absent")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let bare_edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    vault
        .batch()
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.5, 2_000)
        .commit()?;
    let (bare_out, bare_in) = raw_edge_values(&vault, &bare_edge)?;
    let bare_out = bare_out.expect("bare edge");
    assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(bare_in.as_deref(), Some(bare_out.as_slice()));

    let absent_edge = EdgeRef::new(src, EdgeKind::About, absent_tgt);
    vault
        .batch()
        .edge_with_created_at_and_vad(&src, EdgeKind::About, &absent_tgt, 0.5, 2_001, Vad::NEUTRAL)
        .commit()?;
    let (absent_out, absent_in) = raw_edge_values(&vault, &absent_edge)?;
    let absent_out = absent_out.expect("formerly absent edge");
    assert_eq!(absent_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(absent_in.as_deref(), Some(absent_out.as_slice()));
    Ok(())
}

#[test]
fn public_timestamped_builder_keeps_structural_edge_layout() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let child = EntityId::now();
    let parent = EntityId::now();
    let occurred = test_time_range(1, 1);
    // Milestone -> Task is the matrix-valid pair (ONE-1376); this test is
    // about the structural edge value layout, not about nesting.
    vault.put_entity(
        &parent,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(TaskRole::Milestone),
    )?;
    vault.put_entity(
        &child,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(TaskRole::Task),
    )?;

    vault
        .batch()
        .edge_with_created_at(&child, EdgeKind::ChildOf, &parent, 0.5, 2_000)
        .commit()?;

    let edge = EdgeRef::new(child, EdgeKind::ChildOf, parent);
    let (out, inn) = raw_edge_values(&vault, &edge)?;
    let out = out.expect("structural edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(
            &child,
            EdgeKind::ChildOf,
            &parent,
            0.5,
            2_001,
            Vad {
                valence: 0.1,
                arousal: 0.2,
                dominance: 0.3,
            },
        )
        .commit()
        .expect_err("structural edge must reject VAD payload");
    assert!(
        matches!(
            err,
            Error::InvariantViolation("structural edges do not carry VAD")
        ),
        "expected structural VAD rejection, got {err:?}"
    );
    assert_raw_edge_unchanged(&vault, &edge, &out, "structural VAD rejection")?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replay_edge_with_created_at_accepts_bare_over_provenanced() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let (before_out, _) = raw_edge_values(vault, &fixture.edge)?;
    assert_eq!(
        before_out.expect("provenanced edge").len(),
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    );

    vault.with_write_txn(|wtxn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight: 0.91,
                created_at: 3_000,
                vad: Vad::NEUTRAL,
                provenance: None,
            }],
            true,
            false,
            false,
        )
    })?;

    let (after_out, after_in) = raw_edge_values(vault, &fixture.edge)?;
    let after_out = after_out.expect("replayed edge");
    assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(after_in.as_deref(), Some(after_out.as_slice()));
    Ok(())
}

use crate::test_util::{assert_secret_scan_rejected, embedding_test_config, entity};

fn child_of_edge(child: EntityId, parent: EntityId) -> BatchOp {
    BatchOp::Edge {
        src: child,
        kind: EdgeKind::ChildOf,
        tgt: parent,
        weight: 1.0,
        vad: Vad::NEUTRAL,
    }
}

#[test]
fn child_of_overlay_orders_entity_clear_against_same_pair_edge() {
    let child = entity(0x41);
    let parent = entity(0x62);

    let edge_after_clear = ChildOfBatchOverlay::from_ops(&[
        BatchOp::Delete { id: child },
        child_of_edge(child, parent),
    ]);
    assert_eq!(
        edge_after_clear.final_edge_override(&child, &parent),
        Some(true),
        "a ChildOf edge re-added after clearing the child must win"
    );

    let clear_after_edge = ChildOfBatchOverlay::from_ops(&[
        child_of_edge(child, parent),
        BatchOp::Delete { id: child },
    ]);
    assert_eq!(
        clear_after_edge.final_edge_override(&child, &parent),
        Some(false),
        "clearing the child after touching the ChildOf pair must win"
    );
}

// ─── ONE-1645 FacetOf write-time type table ─────────────────────────────────

/// Writes a minimal entity row of the given type. CLAIM rows carry a real
/// encoded claim body so they survive the write-door body validation; every
/// other type takes an opaque payload.
fn put_typed(vault: &Vault, id: &EntityId, entity_type: u8) -> Result<()> {
    let payload = if entity_type == ENTITY_TYPE_CLAIM {
        let body = ClaimBody::new(
            "facet.type_table_probe",
            ClaimSubject::Entity(*id),
            Value::from("v"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        crate::claim::encode_claim_body(&body)?
    } else {
        b"payload".to_vec()
    };
    vault.put_entity(id, entity_type, test_time_range(1, 1), 1, &payload)
}

fn facet_of_edge_stored(vault: &Vault, src: &EntityId, tgt: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let key = Store::encode_edge_key(src, EdgeKind::FacetOf, tgt);
    Ok(vault.store.edges_out.get(&rtxn, &key)?.is_some())
}

fn assert_invalid_facet_of_edge(
    err: &Error,
    expected_src_type: Option<u8>,
    expected_tgt_type: Option<u8>,
    context: &str,
) {
    match err {
        Error::InvalidFacetOfEdge {
            src_type, tgt_type, ..
        } => {
            assert_eq!(*src_type, expected_src_type, "{context}: src type");
            assert_eq!(*tgt_type, expected_tgt_type, "{context}: tgt type");
        }
        other => panic!("{context}: expected InvalidFacetOfEdge, got {other:?}"),
    }
}

/// The admitted table: CLAIM → FACET, TURN → FACET, EVENT → FACET.
///
/// Two semantics ride one edge kind. CLAIM|TURN-sourced stamps are
/// DISCLOSURE-SCOPING — CLAIM adjacency is what `claim_facet_scope`
/// prefix-scans and what strict-mode filtering acts on; TURN is admitted
/// alongside CLAIM because per-turn facet stamps are what transcript filtering
/// rides. EVENT-sourced stamps are WORLD-MODEL: they exist for ARCH-0039 PPR
/// traversal (`facet_of` λ 0.05), and rejecting EVENT would make a ratified
/// traversal contract unwritable.
///
/// "World-model" is scoped to the LOCAL QUERY door, not to disclosure at
/// large. `apply_facet_filter` keeps every non-CLAIM entity unconditionally,
/// so an EVENT-sourced stamp is inert THERE — but the federation selector
/// scopes by every source type THIS table admits, EVENT included, so the same
/// stamp is disclosure-EFFECTIVE on that door (pinned by
/// `sync::selector::tests::selector_denies_event_scoped_to_unselected_facet`).
#[test]
fn facet_of_edge_valid_source_types_accepted() -> Result<()> {
    for (label, src_type) in [
        ("claim source", ENTITY_TYPE_CLAIM),
        ("turn source", ENTITY_TYPE_TURN),
        (
            "event source (world-model; federation-door effective)",
            ENTITY_TYPE_EVENT,
        ),
    ] {
        let (_dir, vault) = open_test_vault();
        let src = EntityId::now();
        let facet = EntityId::now();
        put_typed(&vault, &src, src_type)?;
        put_typed(&vault, &facet, ENTITY_TYPE_FACET)?;

        vault
            .batch()
            .edge(&src, EdgeKind::FacetOf, &facet, 0.7)
            .commit()?;
        assert!(
            facet_of_edge_stored(&vault, &src, &facet)?,
            "{label} must be admitted"
        );
    }
    Ok(())
}

/// The rejected table. Every row aborts the batch atomically and reports the
/// types actually found — including `None` for an endpoint with no entity
/// row, whose type is unknowable rather than merely wrong.
///
/// Admitting EVENT widened the source set to {CLAIM, TURN, EVENT}; it did not
/// soften the teeth. Sources OUTSIDE that set are still rejected (the SESSION
/// and PERSON rows pin this), the target must still be a FACET, and a missing
/// endpoint row still fails closed.
#[test]
fn facet_of_edge_type_table_rejects_off_table_endpoints() -> Result<()> {
    // (label, src type, tgt type) — `None` means "write no entity row".
    let table: [(&str, Option<u8>, Option<u8>); 5] = [
        (
            "wrong target type",
            Some(ENTITY_TYPE_CLAIM),
            Some(ENTITY_TYPE_PERSON),
        ),
        (
            "wrong source type",
            Some(ENTITY_TYPE_PERSON),
            Some(ENTITY_TYPE_FACET),
        ),
        (
            "off-table source stays rejected after the EVENT widening",
            Some(crate::registry::ENTITY_TYPE_SESSION),
            Some(ENTITY_TYPE_FACET),
        ),
        ("missing source row", None, Some(ENTITY_TYPE_FACET)),
        ("missing target row", Some(ENTITY_TYPE_CLAIM), None),
    ];
    for (label, src_type, tgt_type) in table {
        let (_dir, vault) = open_test_vault();
        let src = EntityId::now();
        let tgt = EntityId::now();
        if let Some(t) = src_type {
            put_typed(&vault, &src, t)?;
        }
        if let Some(t) = tgt_type {
            put_typed(&vault, &tgt, t)?;
        }

        let err = vault
            .batch()
            .edge(&src, EdgeKind::FacetOf, &tgt, 0.7)
            .commit()
            .expect_err(label);
        assert_invalid_facet_of_edge(&err, src_type, tgt_type, label);
        assert_eq!(err.kind(), ErrorKind::InvalidFacetOfEdge, "{label}");
        assert!(
            !facet_of_edge_stored(&vault, &src, &tgt)?,
            "{label}: the rejected edge must not be stored"
        );
    }
    Ok(())
}

/// Ops apply in order inside one write txn, so an entity put and the edge
/// that stamps it commit together in a single batch.
#[test]
fn facet_of_edge_same_batch_entity_then_edge_accepted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let facet = EntityId::now();
    let claim_body = crate::claim::encode_claim_body(&ClaimBody::new(
        "facet.type_table_probe",
        ClaimSubject::Entity(claim),
        Value::from("v"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    ))?;

    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &claim_body,
        )
        .put(&facet, ENTITY_TYPE_FACET, test_time_range(1, 1), 1, b"f")
        .edge(&claim, EdgeKind::FacetOf, &facet, 0.7)
        .commit()?;

    assert!(facet_of_edge_stored(&vault, &claim, &facet)?);
    Ok(())
}

/// The gate covers the public timestamped builder arm too, with the same
/// table — the public write door is one boundary, not two.
#[test]
fn facet_of_edge_via_public_created_at_builder_rejected_same_table() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let person = EntityId::now();
    put_typed(&vault, &claim, ENTITY_TYPE_CLAIM)?;
    put_typed(&vault, &person, ENTITY_TYPE_PERSON)?;

    let err = vault
        .batch()
        .edge_with_created_at(&claim, EdgeKind::FacetOf, &person, 0.7, 5)
        .commit()
        .expect_err("public timestamped arm must run the same type table");
    assert_invalid_facet_of_edge(
        &err,
        Some(ENTITY_TYPE_CLAIM),
        Some(ENTITY_TYPE_PERSON),
        "public created_at arm",
    );
    assert!(!facet_of_edge_stored(&vault, &claim, &person)?);

    // Control: the same builder admits a well-typed stamp.
    let facet = EntityId::now();
    put_typed(&vault, &facet, ENTITY_TYPE_FACET)?;
    vault
        .batch()
        .edge_with_created_at(&claim, EdgeKind::FacetOf, &facet, 0.7, 5)
        .commit()?;
    assert!(facet_of_edge_stored(&vault, &claim, &facet)?);
    Ok(())
}

/// Collateral check: the gate keys on `FacetOf` alone. Any other edge kind
/// between arbitrary typed entities commits exactly as it did before.
#[test]
fn non_facet_of_edges_unaffected() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person_a = EntityId::now();
    let person_b = EntityId::now();
    put_typed(&vault, &person_a, ENTITY_TYPE_PERSON)?;
    put_typed(&vault, &person_b, ENTITY_TYPE_PERSON)?;

    vault
        .batch()
        .edge(&person_a, EdgeKind::Mentions, &person_b, 0.7)
        .commit()?;
    assert!(vault.edge_exists(&person_a, EdgeKind::Mentions, &person_b)?);

    // Even an edge whose endpoints do not exist at all stays ungated when the
    // kind is not FacetOf.
    let ghost_a = EntityId::now();
    let ghost_b = EntityId::now();
    vault
        .batch()
        .edge(&ghost_a, EdgeKind::Mentions, &ghost_b, 0.7)
        .commit()?;
    assert!(vault.edge_exists(&ghost_a, EdgeKind::Mentions, &ghost_b)?);
    Ok(())
}

/// The sync-replay arm stays UNGATED by design (H2). A replicated LWW winner
/// must never wedge local sync into a permanent abort, so the type table is
/// enforced one layer up, at the REPLAY chokepoint, where an off-table row
/// can be quarantined instead of aborting the window: see
/// `sync::window::tests::forward_remat_quarantines_off_table_facet_of_and_admits_the_on_table_row`.
/// Pinned deliberately: an ill-typed FacetOf edge still applies at THIS arm,
/// and the internal builder is `pub(crate)` — no local actor reaches it
/// without sync replay, and no replay reaches it without passing the
/// chokepoint's table.
#[test]
fn facet_of_edge_sync_replay_arm_ungated() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let person = EntityId::now();
    put_typed(&vault, &claim, ENTITY_TYPE_CLAIM)?;
    put_typed(&vault, &person, ENTITY_TYPE_PERSON)?;

    vault
        .batch()
        .edge_with_value_fields(
            &claim,
            EdgeKind::FacetOf,
            &person,
            EdgeValueFields {
                weight: 0.7,
                created_at: 1,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()?;

    assert!(
        facet_of_edge_stored(&vault, &claim, &person)?,
        "the replay arm must apply a wrong-typed FacetOf edge unchanged"
    );
    Ok(())
}

// ─── ONE-1728 K4 · in-transaction op-decode-point taint guard ────────────

/// Stages one live overlay entity for `id` on `session`, so the K4 guard sees
/// a genuine live-overlay member — the same shape `off_record/tests.rs` uses.
fn stage_live_overlay_entity(
    session: &crate::off_record::OffRecordSession<'_>,
    id: &EntityId,
) -> Result<()> {
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        id.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()
}

/// An `Ordinary` base write naming a live-overlay id in an op ref OTHER than
/// the written entity itself — here an edge TARGET — is rejected. This is the
/// case the entity-materialization door cannot catch: `guard_off_record_entity_put`
/// only sees ids that materialize, and an edge target materializes nothing.
#[test]
fn taint_guard_rejects_edge_targeting_a_live_overlay_id() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-edge", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = vault
        .batch()
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()
        .expect_err("an edge into a live overlay id must be refused");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert_matches!(
        err,
        Error::OffRecordTaintedBaseWrite { entity_ref } if entity_ref == overlay_id.to_hex()
    );
    assert!(!vault.edge_exists(&source, EdgeKind::Mentions, &overlay_id)?);
    session.close()?;
    Ok(())
}

/// A raw base CLAIM put whose BODY names a live-overlay id as its subject is
/// rejected: the guard decodes the opaque body through the same decoder the
/// apply path uses, so the subject ref joins the referenced-id set even though
/// the claim's own id is untainted.
#[test]
fn taint_guard_decodes_raw_claim_body_subject_refs() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-claim", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(overlay_id),
        Value::from("subject rides in the opaque body"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let err = vault
        .put_entity(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .expect_err("a claim body naming a live overlay subject must be refused");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.get_raw(&claim)?.is_none());
    session.close()?;
    Ok(())
}

/// Commits one raw CLAIM-prefixed put through the reserved-claim door, which
/// (unlike the public `put`) carries the body to the op loop unvalidated — the
/// only way an undecodable body can reach the decode point at all.
fn commit_raw_claim_put(vault: &Vault, claim: &EntityId, data: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(claim, test_time_range(1, 1), 1, data)
            .apply(wtxn)
    })
}

/// An UNDECODABLE CLAIM-prefixed body fails closed with the taint error while a
/// live overlay holds entities: its refs cannot be enumerated, so membership
/// cannot be disproved, and deciding it untainted is exactly the open-by-default
/// shape the guard forbids.
#[test]
fn taint_guard_fails_closed_on_undecodable_claim_body() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-undecodable", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = commit_raw_claim_put(&vault, &claim, b"not a decodable claim body")
        .expect_err("an undecodable claim body must fail closed");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.get_raw(&claim)?.is_none());
    session.close()?;
    Ok(())
}

/// With no live overlay entity the guard is inert: the same undecodable body
/// reaches its precise `InvalidClaimBody` verdict. The taint error names a real
/// membership fact, never a decode failure on its own.
#[test]
fn taint_guard_is_inert_without_live_overlay_entities() {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let err = commit_raw_claim_put(&vault, &claim, b"not a decodable claim body")
        .expect_err("an undecodable claim body is still rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
}

/// The guard runs INSIDE the applying transaction, so a batch it refuses is
/// atomic: the earlier ops of the same batch leave no base row behind. There is
/// no preflight pass whose verdict could be published before the transaction.
#[test]
fn taint_guard_rejection_rolls_back_the_whole_batch() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let clean = EntityId::now();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-atomic", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = vault
        .batch()
        .put(
            &clean,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"untainted op ordered before the tainted one",
        )
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()
        .expect_err("the tainted op must refuse the batch");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(
        vault.get_raw(&clean)?.is_none(),
        "the untainted op that preceded the refusal must roll back with it"
    );
    session.close()?;
    Ok(())
}

/// Closing the session drops the membership, and the identical write then
/// succeeds — the refusal tracks LIVE overlay state read inside the applying
/// transaction, not a durable mark on the id.
#[test]
fn taint_guard_releases_after_session_close() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-release", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;
    assert!(
        vault
            .batch()
            .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
            .commit()
            .is_err()
    );
    session.close()?;

    vault
        .batch()
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()?;
    assert!(vault.edge_exists(&source, EdgeKind::Mentions, &overlay_id)?);
    Ok(())
}

/// The session apply entry refuses a STALE route before staging anything.
///
/// `SessionWriteRoute::revalidate` being correct in isolation is not enough:
/// what matters is that `apply_ops_session` actually CALLS it. A mode flip
/// landing between mint and apply must abort the write whole — half a turn
/// staged into a room the caller no longer believes it is in would be worse
/// than either outcome.
#[test]
fn session_apply_refuses_a_route_minted_before_a_mode_flip() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-apply-stale-route", OffRecordBackendClass::Local)?;
    let route = session.write_route()?;
    // The flip republishes the mode generation, stranding the route above.
    session.flip_on_record()?;
    session.flip_off_record()?;

    let turn = EntityId::now();
    let entry = crate::session_overlay::JournalEntry {
        scope: crate::session_overlay::JournalScope::new(EntityId::now(), turn),
        role: crate::session_overlay::JournalRole::TurnPut,
        learned_at: 10,
        occurred: TimeRange { start: 10, end: 10 },
        op: BatchOp::Put {
            id: turn,
            entity_type: crate::registry::ENTITY_TYPE_TURN,
            occurred: TimeRange { start: 10, end: 10 },
            learned_at: 10,
            data: b"stale-route turn".to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
    };

    let overlay = session.overlay();
    let mut wtxn = vault.store.env.write_txn()?;
    let segment = overlay.install_txn_segment()?;
    let view = session.read_view()?;
    let refused = crate::batch::apply_ops_session(
        &view,
        &route,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![entry],
    )
    .expect_err("a route minted before the flip must be refused");
    assert_eq!(
        refused.kind(),
        crate::error::ErrorKind::OffRecordOverlayLeaseClosed
    );
    drop(view);
    drop(segment);
    drop(wtxn);

    // Nothing staged: the refusal happens before the first row. The snapshot
    // holds a read lease and close DRAINS leases, so it is scoped tightly —
    // holding one across close deadlocks the closing thread.
    {
        let snapshot = overlay.snapshot()?;
        assert_eq!(
            snapshot.row_count(crate::session_overlay::OverlayKeyspace::Entities),
            0,
            "a refused session apply stages no rows"
        );
        assert_eq!(
            snapshot.journal_entries().len(),
            0,
            "a refused session apply journals nothing"
        );
    }
    session.close()?;
    Ok(())
}

/// The session apply door validates CLAIM BODIES, not just the type byte.
///
/// `apply_ops_session` ran `validate_public_entity_type` and went straight to
/// staging, so a malformed CLAIM body landed in the overlay, was journaled,
/// and read back through the room's composed view. Promote replays that very
/// op through `apply_put`, whose D18 arm rejects it — so the room showed its
/// caller a claim that could never land, and the refusal arrived a whole
/// session later attached to promote rather than to the write that was wrong.
/// Fail-closed at promote is not enough: the wrongness has to be
/// unrepresentable IN the room, not merely unpromotable out of it.
///
/// Both halves of the validator chain are covered, because either alone leaves
/// a door open: a body the DECODER rejects, and well-formed bodies a family's
/// STRUCTURAL arm rejects (wrong subject kind, wrong value shape).
#[test]
fn session_apply_validates_claim_bodies_before_staging() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-claim-body-door", OffRecordBackendClass::Local)?;

    let encode = |predicate: &str, subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
        crate::claim::encode_claim_body(&ClaimBody::new(
            predicate,
            subject,
            value,
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        ))
    };

    let mut undecodable = encode(
        "dream.symbol",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("a blue door"),
    )?;
    undecodable.push(0x00);

    let cases: [(&str, Vec<u8>); 3] = [
        ("trailing bytes after the body map", undecodable),
        (
            "a calendar claim whose subject is an EDGE, not an entity",
            encode(
                crate::calendar::claims::PREDICATE_CALENDAR_TZ,
                ClaimSubject::Edge {
                    source: EntityId::now(),
                    kind: EdgeKind::Mentions,
                    target: EntityId::now(),
                },
                Value::from("Europe/Berlin"),
            )?,
        ),
        (
            "a calendar claim whose tz value is an integer, not a string",
            encode(
                crate::calendar::claims::PREDICATE_CALENDAR_TZ,
                ClaimSubject::Entity(EntityId::now()),
                Value::from(7),
            )?,
        ),
    ];

    for (case, data) in cases {
        let claim_id = EntityId::now();
        let occurred = TimeRange { start: 5, end: 5 };
        let entry = crate::session_overlay::JournalEntry {
            scope: crate::session_overlay::JournalScope::new(EntityId::now(), claim_id),
            role: crate::session_overlay::JournalRole::TurnOwnedArtifact,
            learned_at: 5,
            occurred,
            op: BatchOp::Put {
                id: claim_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred,
                learned_at: 5,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
        };

        let route = session.write_route()?;
        let overlay = session.overlay();
        let mut wtxn = vault.store.env.write_txn()?;
        let segment = overlay.install_txn_segment()?;
        let view = session.read_view()?;
        let refused = crate::batch::apply_ops_session(
            &view,
            &route,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![entry],
        )
        .expect_err(case);
        assert_eq!(refused.kind(), ErrorKind::InvalidClaimBody, "{case}");
        drop(view);
        drop(segment);
        drop(wtxn);

        // The refusal must precede the first staged byte, exactly as the base
        // door's does: a half-written turn in a room is the outcome both doors
        // exist to prevent.
        {
            let snapshot = overlay.snapshot()?;
            assert_eq!(
                snapshot.row_count(crate::session_overlay::OverlayKeyspace::Entities),
                0,
                "{case}: no row may stage"
            );
            assert_eq!(
                snapshot.journal_entries().len(),
                0,
                "{case}: nothing may be journaled"
            );
        }
    }

    session.close()?;
    Ok(())
}
