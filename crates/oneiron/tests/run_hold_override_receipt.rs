//! The attested record of a hold override (Engine call S65-B-R3). When a
//! generic Resume releases an engine hold that its own signal did not
//! release, the override's own transaction writes one `RunHoldOverride`
//! receipt naming the hold, the run, the actor and the time, and the receipt
//! family reads it. The vault owner's override and the engine's own generic
//! resumes alike write one. A hold its own signal releases writes none.
//!
//! Public paths only. The receipt kind is new, so on main this file does not
//! compile (no `ReceiptKind::RunHoldOverride`):
//! `cargo test --locked -p oneiron --all-features --test run_hold_override_receipt`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{
    HeldWave, KIND, WORKER, claim, claimed, enqueued, held_wave_planner, open, read, resume,
    unix_now,
};
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldLease};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptResumePoint, AttemptState, EnqueueAttempt,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::task_verb::run_control::{RunControlEffect, RunControlRequest};
use oneiron::{EdgeActorClass, Vault, VaultConfig};

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn overrides(vault: &Vault) -> Vec<ReceiptRecord> {
    let mut query = ReceiptQuery::new(10);
    query.kinds = [ReceiptKind::RunHoldOverride].into();
    vault.receipts(query).expect("receipts")
}

/// A leased row the spend cap parked, under its run's plan hold.
fn budget_held_row(vault: &Vault, queue: &AttemptQueue<'_>, now: u64) -> AttemptId {
    let row = enqueued(
        queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: b"run".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue"),
    );
    let leased = claimed(claim(queue, KIND, now + 1));
    AgentDispatcher::new(vault)
        .hold_for_budget(
            row.id,
            BudgetHoldLease {
                attempt: leased.id,
                lease_owner: WORKER.to_owned(),
                attempt_count: leased.attempt_count,
                resume_point: AttemptResumePoint::new("step-3", now + 2),
            },
            None,
            "spend cap",
            now + 2,
            None,
        )
        .expect("the budget hold is admitted");
    row.id
}

/// The vault owner's override through `vault.runs.resume` is recorded under
/// the owner. The vault holds its writer lease, as an embedded owner's does,
/// so the owner's door admits the owner.
#[test]
fn the_owners_override_leaves_a_receipt_naming_the_owner_and_the_hold() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open_owned(dir.path(), config).expect("vault opens");
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let held = budget_held_row(&vault, &queue, now);
    assert!(overrides(&vault).is_empty());

    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    assert_eq!(
        vault
            .memory(owner, EdgeActorClass::Human)
            .runs_resume(RunControlRequest {
                branch: hex(held),
                note: None,
            })
            .expect("the vault owner overrides the hold")
            .effect,
        RunControlEffect::Resumed
    );
    assert_eq!(read(&queue, held).state, AttemptState::Queued);

    let receipts = overrides(&vault);
    assert_eq!(receipts.len(), 1, "one override, one receipt");
    let receipt = &receipts[0];
    assert_eq!(receipt.actor.as_deref(), Some(owner.to_hex().as_str()));
    assert_eq!(receipt.outcome, "released");
    assert_eq!(
        receipt.fields.get("hold").map(String::as_str),
        Some("budget")
    );
    assert_eq!(receipt.fields.get("attempt"), Some(&hex(held)));
}

/// The engine's own generic Resume of a fan-out held planner is an override
/// too, recorded under its own actor with the launch it released from.
#[test]
fn an_engine_resume_of_a_fanout_hold_leaves_a_receipt_naming_the_launch() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let HeldWave { row, launch, .. } = held_wave_planner(&vault, &queue, now);

    resume(&queue, row.id, "runtime", now + 3);

    let receipts = overrides(&vault);
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.actor.as_deref(), Some("runtime"));
    assert_eq!(
        receipt.fields.get("hold").map(String::as_str),
        Some("fanout")
    );
    assert_eq!(receipt.fields.get("launch_ref"), Some(&launch.to_hex()));
}

/// A hold its own signal releases is no override and leaves no receipt.
#[test]
fn a_budget_hold_its_own_resume_releases_leaves_no_override_receipt() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let held = budget_held_row(&vault, &queue, now);

    AgentDispatcher::new(&vault)
        .resume_budget_hold(held, "owner:resume", now + 3)
        .expect("the hold's own resume");
    assert_eq!(read(&queue, held).state, AttemptState::Queued);
    assert!(overrides(&vault).is_empty());
}
