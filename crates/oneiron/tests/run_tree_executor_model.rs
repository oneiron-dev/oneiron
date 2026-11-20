//! A run tree node names the model its executor ran (UNBUILT3-41,
//! THREAD-PROVENANCE-READ; RULED THREAD-PROVENANCE-READER = C): the model id
//! and revision its lease stamped, and nothing about the seat or role that
//! configured it. The read goes through the run tree's serialized form, the
//! shape its readers get, so this file compiles on a base without the field:
//! `cargo test --locked -p oneiron --all-features --test run_tree_executor_model`.

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::run_tree::RunTreeAdapter;
use oneiron_model::model_binding::ModelRole;
use oneiron_testkit::{FixtureVault, fixture_cache};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KIND: &str = "test.run_tree_executor_model";
const WORKER: &str = "worker:run-tree-executor-model";
const RUN: &str = "run-tree-executor-model";
const MODEL: &str = "fixture/answering-model@1";
const SEAT: &str = "fixture-seat@1";

fn enqueue(
    queue: &AttemptQueue<'_>,
    now: u64,
) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let EnqueueOutcome::Enqueued(record) = queue.enqueue(EnqueueAttempt {
        kind: KIND.to_owned(),
        payload: b"run".to_vec(),
        dedupe_key: None,
        run_id: Some(RUN.to_owned()),
        now,
    })?
    else {
        return Err("a fresh row is enqueued".into());
    };
    Ok(record)
}

fn claim(queue: &AttemptQueue<'_>, now: u64) -> Result<AttemptRecord, Box<dyn std::error::Error>> {
    let ClaimOutcome::Claimed(record) = queue.claim_kind(
        KIND,
        ClaimAttempt {
            lease_owner: WORKER.to_owned(),
            now,
        },
    )?
    else {
        return Err("the ready row is claimed".into());
    };
    Ok(record)
}

/// The serialized node of `attempt` in the run's tree.
fn node_json(
    vault: &oneiron::Vault,
    attempt: &AttemptRecord,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let tree = serde_json::to_value(RunTreeAdapter::new(vault).read_run(RUN)?)?;
    let id: String = attempt
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    tree["nodes"]
        .as_array()
        .ok_or("the run tree serializes its node table")?
        .iter()
        .find(|node| node["job_id"].as_str() == Some(id.as_str()))
        .cloned()
        .ok_or_else(|| format!("the run tree holds attempt {id}: {tree}").into())
}

#[test]
fn a_run_tree_node_names_its_executor_model() -> TestResult {
    let copy = FixtureVault::empty(&fixture_cache!())?.copy()?;
    let vault = copy.open()?;
    let queue = AttemptQueue::new(&vault);
    let now = vault.now_recorded_at();
    let stamped = enqueue(&queue, now)?;
    let claimed = claim(&queue, now)?;
    assert_eq!(claimed.id, stamped.id, "the one ready row is claimed");
    queue.set_executor_stamp(
        claimed.id,
        WORKER,
        claimed.attempt_count,
        MODEL,
        SEAT,
        ModelRole::GenerativeReasoner,
    )?;

    let node = node_json(&vault, &claimed)?;
    assert_eq!(
        node["executor_model"].as_str(),
        Some(MODEL),
        "the node names the model its lease stamped: {node}"
    );
    let shown = node.to_string();
    assert!(
        !shown.contains(SEAT),
        "the seat that configured the executor stays off the node: {node}"
    );
    for key in ["executor_seat", "executor_role", "seat", "role"] {
        assert!(node.get(key).is_none(), "no {key} key on the node: {node}");
    }
    Ok(())
}

#[test]
fn a_run_tree_node_of_an_unstamped_attempt_names_no_model() -> TestResult {
    let copy = FixtureVault::empty(&fixture_cache!())?.copy()?;
    let vault = copy.open()?;
    let queue = AttemptQueue::new(&vault);
    let now = vault.now_recorded_at();
    enqueue(&queue, now)?;
    let claimed = claim(&queue, now)?;

    let node = node_json(&vault, &claimed)?;
    assert!(
        node.get("executor_model").is_none(),
        "an attempt no run stamped names no model: {node}"
    );
    Ok(())
}
