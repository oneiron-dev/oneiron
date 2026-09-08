//! Habit check-in rules and derived streak counters.

use super::*;

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

    // The demotion is refused by the ONE tree gate, naming both roles of the
    // pair it would have left behind (`Task -> HabitCheckin`), and still
    // under the coarse kind sync replay classifies on.
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    match err {
        Error::TaskChildOfNesting {
            parent_role,
            child_role,
        } => {
            assert_eq!(parent_role, TaskRole::Task.role_byte());
            assert_eq!(child_role, TaskRole::HabitCheckin.role_byte());
        }
        other => panic!("expected a nesting rejection, got {other:?}"),
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
