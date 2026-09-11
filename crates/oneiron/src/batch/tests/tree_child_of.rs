//! Child-of tree shape and task-role pair validation.

use super::*;
use crate::error::RegistryError;

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
    assert_matches!(err, Error::Registry(RegistryError::CycleDetected));
    assert!(!vault.edge_exists(&goal, EdgeKind::ChildOf, &task)?);

    // Self-parent is the degenerate case and reports the same typed error.
    let self_err = vault
        .batch()
        .edge(&goal, EdgeKind::ChildOf, &goal, 1.0)
        .commit()
        .expect_err("a self-parent ChildOf commit must be rejected");
    assert_matches!(self_err, Error::Registry(RegistryError::CycleDetected));
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
        Error::Registry(RegistryError::ChildOfParentMissing { parent }) => {
            assert_eq!(parent, absent)
        }
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
        Error::Registry(RegistryError::ChildOfParentMissing { parent }) => {
            assert_eq!(parent, doomed_parent)
        }
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

/// A role flip carries NO edge op, and it re-judges exactly the pair the
/// matrix owns — from either endpoint. Triggering on edge ops alone would let
/// a `Milestone` become a `Task` under its `Goal` parent (or the parent
/// become a `Goal` over its `Task` child) and persist a forbidden pair.
///
/// The last arm is the counterweight: the TRIGGER widens, the RULE does not.
/// Both endpoints flipped in one batch to a legal pair still commits, which a
/// stored-state (rather than final-state) check would have false-rejected.
#[test]
fn role_only_put_cannot_persist_a_forbidden_pair() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    // Child side: `Goal -> Milestone` is legal; flipping the CHILD to `Task`
    // leaves the forbidden `Goal -> Task` behind.
    let goal = EntityId::now();
    let child = EntityId::now();
    let batch = put_task_role(vault.batch(), &goal, TaskRole::Goal, 1);
    put_task_role(batch, &child, TaskRole::Milestone, 3)
        .edge(&child, EdgeKind::ChildOf, &goal, 1.0)
        .commit()?;
    let stored_child = vault.get_raw(&child)?.expect("child row must be written");

    let err = put_task_role(vault.batch(), &child, TaskRole::Task, 5)
        .commit()
        .expect_err("a child role flip must be judged against the live edge");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    match err {
        Error::Registry(RegistryError::TaskChildOfNesting {
            parent_role,
            child_role,
        }) => {
            assert_eq!(parent_role, TaskRole::Goal.role_byte());
            assert_eq!(child_role, TaskRole::Task.role_byte());
        }
        other => panic!("expected a nesting rejection, got {other:?}"),
    }
    assert_eq!(vault.get_raw(&child)?, Some(stored_child));

    // Parent side: `Milestone -> Task` is legal; flipping the PARENT to
    // `Goal` leaves the same forbidden pair, still with no edge op.
    let parent = EntityId::now();
    let task = EntityId::now();
    let batch = put_task_role(vault.batch(), &parent, TaskRole::Milestone, 7);
    put_task_role(batch, &task, TaskRole::Task, 9)
        .edge(&task, EdgeKind::ChildOf, &parent, 1.0)
        .commit()?;
    let stored_parent = vault.get_raw(&parent)?.expect("parent row must be written");

    let err = put_task_role(vault.batch(), &parent, TaskRole::Goal, 11)
        .commit()
        .expect_err("a parent role flip must be judged against its live children");
    match err {
        Error::Registry(RegistryError::TaskChildOfNesting {
            parent_role,
            child_role,
        }) => {
            assert_eq!(parent_role, TaskRole::Goal.role_byte());
            assert_eq!(child_role, TaskRole::Task.role_byte());
        }
        other => panic!("expected a nesting rejection, got {other:?}"),
    }
    assert_eq!(vault.get_raw(&parent)?, Some(stored_parent));

    // Both endpoints flipped in ONE batch onto a pair the matrix allows:
    // final state is the only thing judged, so this commits.
    let batch = put_task_role(vault.batch(), &parent, TaskRole::Goal, 13);
    put_task_role(batch, &task, TaskRole::Milestone, 15).commit()?;
    assert!(vault.edge_exists(&task, EdgeKind::ChildOf, &parent)?);
    Ok(())
}

/// The check-in door obeys the same final-state law as every other pair: op
/// ORDER inside one batch may not decide whether a legal tree commits.
#[test]
fn habit_checkin_parent_put_after_the_edge_is_valid() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();

    let batch = put_task_role(vault.batch(), &checkin, TaskRole::HabitCheckin, 1).edge(
        &checkin,
        EdgeKind::ChildOf,
        &habit,
        1.0,
    );
    put_task_role(batch, &habit, TaskRole::Habit, 3).commit()?;
    assert!(vault.edge_exists(&checkin, EdgeKind::ChildOf, &habit)?);

    // Order-independence is not permissiveness: a check-in under a non-Habit
    // parent is still rejected wherever the parent put lands.
    let task_parent = EntityId::now();
    let stray = EntityId::now();
    let batch = put_task_role(vault.batch(), &stray, TaskRole::HabitCheckin, 5).edge(
        &stray,
        EdgeKind::ChildOf,
        &task_parent,
        1.0,
    );
    let err = put_task_role(batch, &task_parent, TaskRole::Task, 7)
        .commit()
        .expect_err("a check-in under a non-Habit parent is still rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert!(!vault.entity_exists(&stray)?);
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
                Error::Registry(RegistryError::TaskChildOfNesting {
                    parent_role: got_parent,
                    child_role: got_child,
                }) => {
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
        Error::Registry(RegistryError::TaskChildOfParentNotTask {
            child_role,
            parent_entity_type,
        }) => {
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
    assert_matches!(
        cardinality_err,
        Error::Registry(RegistryError::ChildOfCardinality)
    );

    let cycle_err = vault
        .batch()
        .edge(&root, EdgeKind::ChildOf, &leaf, 1.0)
        .commit()
        .expect_err("a non-TASK cycle is still rejected");
    assert_matches!(cycle_err, Error::Registry(RegistryError::CycleDetected));

    // And a missing parent is now rejected here too.
    let absent = EntityId::now();
    let orphan = EntityId::now();
    let dangling_err = put_plain_node(vault.batch(), &orphan, 9)
        .edge(&orphan, EdgeKind::ChildOf, &absent, 1.0)
        .commit()
        .expect_err("a non-TASK dangling parent is rejected");
    match dangling_err {
        Error::Registry(RegistryError::ChildOfParentMissing { parent }) => {
            assert_eq!(parent, absent)
        }
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
