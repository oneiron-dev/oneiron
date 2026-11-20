//! A refused second task assignment on the wire (FIX
//! [TASK-ASSIGNED-FORK-ON-CONCURRENT-AMENDED-SETTLES]): the approve answers
//! 409 INVALID_STATE with the task and both assignees as a typed
//! `task_assignment_conflict` block, through the facade.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --test task_assignment_conflict_wire`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_server::test_doors::refusal_wire::facade_refusal;
use serde_json::json;

const TASK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HELD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OFFERED: &str = "cccccccccccccccccccccccccccccccc";

fn refused() -> oneiron::MemoryError {
    oneiron::MemoryError::from(oneiron::Error::Record(
        oneiron::error::RecordError::TaskAssignmentConflict {
            task_ref: oneiron::EntityId::from_hex(TASK).expect("a task id parses"),
            held_assignee: oneiron::EntityId::from_hex(HELD).expect("an assignee parses"),
            offered_assignee: oneiron::EntityId::from_hex(OFFERED).expect("an assignee parses"),
        },
    ))
}

#[tokio::test]
async fn the_facade_answers_409_with_the_conflict_block() {
    let (status, body) = facade_refusal(refused()).await;
    assert_eq!(status, 409);
    let error = &body["error"];
    assert_eq!(error["code"], json!("INVALID_STATE"));
    assert_eq!(
        error["task_assignment_conflict"],
        json!({"task_ref": TASK, "held_assignee": HELD, "offered_assignee": OFFERED})
    );
}
