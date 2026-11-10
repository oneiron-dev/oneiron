//! Who releases a held run, keyed on the hold and the caller (Fable 5.2 item
//! 2; lead 06:5x; Engine calls S65-B-R1 and S65-B-R2 = A). The vault owner
//! overrides any hold. Every other caller (a TASK's owner, the host, an
//! agent) resumes only a person's pause it placed itself: an engine hold
//! (budget, fan-out, hook, annotation) or another caller's pause refuses it
//! and names the signal the run waits on, and its pause of an engine-held row
//! is refused the same way, so it cannot take the hold over and resume its
//! own pause. On main every one of these resumes goes through.
//!
//! The holds' fixtures and the caller's door build under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_hold_release`.
#![cfg(oneiron_test_support)]

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{
    HeldWave, KIND, WORKER, annotation_held_row, claim, claimed, enqueued, held_wave_planner, open,
    person, read, unix_now,
};
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldLease, BudgetHoldState};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue,
    AttemptResumePoint, AttemptState, EnqueueAttempt, PauseKind, RunState,
};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::task_verb::run_control::{RunControlEffect, RunControlRequest};
use oneiron::test_doors::run_hold;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// A caller's Resume or Pause of `id` through the door run control takes for
/// it, answering the refusal's reason code.
fn as_caller(
    vault: &Vault,
    id: AttemptId,
    kind: AttemptInterventionKind,
    actor: &str,
    now: u64,
) -> Result<AttemptInterventionEffect, &'static str> {
    run_hold::intervene_as_caller(vault, id, kind, actor, now)
        .expect("the door reads the row")
        .map(|outcome| outcome.effect)
}

/// A leased row the spend cap parked, under its run's plan hold.
fn budget_held_row(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    task_ref: Option<EntityId>,
    now: u64,
) -> AttemptId {
    let row = enqueued(
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: KIND.to_owned(),
                    payload: b"run".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now,
                },
                task_ref.map(|task| task.to_hex()),
            )
            .expect("enqueue"),
    );
    let leased = claimed(claim(queue, KIND, now + 1));
    assert_eq!(leased.id, row.id);
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
        )
        .expect("the budget hold is admitted");
    assert_eq!(
        RunState::of(&read(queue, row.id)),
        RunState::Paused(PauseKind::Budget)
    );
    row.id
}

#[test]
fn a_caller_is_refused_the_budget_hold_and_cannot_take_it_over() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let caller = person(&vault, now).to_hex();
    let row = budget_held_row(&vault, &queue, None, now);

    assert_eq!(
        as_caller(
            &vault,
            row,
            AttemptInterventionKind::Resume,
            &caller,
            now + 3
        ),
        Err("awaits:budget_resume")
    );
    // Its pause would take the hold over as its own pause, which it could
    // then resume.
    assert_eq!(
        as_caller(
            &vault,
            row,
            AttemptInterventionKind::Pause,
            &caller,
            now + 4
        ),
        Err("awaits:budget_resume")
    );
    assert_eq!(
        RunState::of(&read(&queue, row)),
        RunState::Paused(PauseKind::Budget),
        "the row stays held"
    );
    let hold = AgentDispatcher::new(&vault)
        .plan_hold(row)
        .expect("plan hold")
        .expect("the hold stands");
    assert_eq!(
        hold.state,
        BudgetHoldState::Held,
        "the hold record is unmoved"
    );
}

#[test]
fn a_caller_is_refused_the_hook_hold() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let caller = person(&vault, now).to_hex();
    let row = enqueued(
        queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: b"turn".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue"),
    );
    let leased = claimed(claim(&queue, KIND, now + 1));
    run_hold::hold_for_hook(
        &vault,
        leased.id,
        WORKER,
        leased.attempt_count,
        [0x7A; 16],
        AttemptResumePoint::new("turn-action:host-hook:1", now + 2),
        now + 2,
    )
    .expect("the hook hold is admitted");

    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &caller,
            now + 3
        ),
        Err("awaits:hook_answer")
    );
    assert_eq!(
        RunState::of(&read(&queue, row.id)),
        RunState::Paused(PauseKind::Hook)
    );
}

#[test]
fn a_caller_is_refused_the_fanout_hold() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let HeldWave {
        row, launch, actor, ..
    } = held_wave_planner(&vault, &queue, now);

    // The wave's own actor, who planned the cut, waits on the approval too.
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &actor.to_hex(),
            now + 3
        ),
        Err("awaits:fanout_approval")
    );
    assert!(read(&queue, row.id).fanout_hold_for(launch));
}

#[test]
fn a_caller_is_refused_the_annotation_hold() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let (row, author) = annotation_held_row(&vault, &queue, now);

    // The comment's own author waits on the thread's reattach too.
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &author.to_hex(),
            now + 6
        ),
        Err("awaits:annotation_reattach")
    );
    assert_eq!(
        RunState::of(&read(&queue, row.id)),
        RunState::Paused(PauseKind::Annotation)
    );
}

#[test]
fn a_caller_resumes_its_own_pause_and_no_one_elses() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let pauser = person(&vault, now).to_hex();
    let other = person(&vault, now).to_hex();
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

    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Pause,
            &pauser,
            now + 1
        ),
        Ok(AttemptInterventionEffect::Paused)
    );
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &other,
            now + 2
        ),
        Err("awaits:pauser")
    );
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &pauser,
            now + 3
        ),
        Ok(AttemptInterventionEffect::Resumed)
    );
}

/// A pause keeps its pauser however many notes follow it (review 6974 P1).
/// The row's event tail is bounded, and the pause's own event is the record
/// of who placed it, so it stays in the tail while the row is paused: after
/// more notes than the tail holds, another caller is still refused and the
/// pauser still resumes its own pause.
#[test]
fn a_pause_keeps_its_pauser_past_the_event_tail() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let pauser = person(&vault, now).to_hex();
    let other = person(&vault, now).to_hex();
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

    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Pause,
            &pauser,
            now + 1
        ),
        Ok(AttemptInterventionEffect::Paused)
    );
    // The tail holds 256 events; 300 notes rotate every older one out.
    for note in 0..300_u64 {
        assert_eq!(
            as_caller(
                &vault,
                row.id,
                AttemptInterventionKind::Interrupt,
                &other,
                now + 2 + note
            ),
            Ok(AttemptInterventionEffect::Interrupted)
        );
    }
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &other,
            now + 400
        ),
        Err("awaits:pauser")
    );
    assert_eq!(
        as_caller(
            &vault,
            row.id,
            AttemptInterventionKind::Resume,
            &pauser,
            now + 401
        ),
        Ok(AttemptInterventionEffect::Resumed)
    );
}

/// `vault.runs.resume` for a TASK's owner, through `Memory::runs_resume`:
/// it resumes its own pause on its branch and is refused the budget hold,
/// which the vault owner then overrides. The vault holds its writer lease,
/// as an embedded owner's does, so the owner's door admits the owner.
#[test]
fn the_task_owner_is_refused_the_budget_hold_and_the_vault_owner_overrides_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open_owned(dir.path(), config).expect("vault opens");
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    // The first-party actor the default manifest grants Auto mints the TASK
    // and names its owner.
    let creator = EntityId::from_bytes([0xE1; 16]).expect("creator id");
    vault
        .put_entity(
            &creator,
            oneiron::registry::ENTITY_TYPE_PERSON,
            fixture::at(now),
            now,
            b"creator",
        )
        .expect("put creator");
    let task_owner = person(&vault, now);
    let task = vault
        .memory(creator, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("a held run".to_owned()),
            Some(task_owner),
            None,
        ))
        .expect("the TASK is created")
        .task_ref
        .expect("the TASK is minted");
    let as_task_owner = vault.memory(task_owner, EdgeActorClass::Human);
    let control = |id: AttemptId| RunControlRequest {
        branch: id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        note: None,
    };

    // Its own pause on a branch of its TASK, it resumes.
    let free = enqueued(
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: "test.run_hold.free".to_owned(),
                    payload: b"free".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now,
                },
                Some(task.to_hex()),
            )
            .expect("enqueue"),
    );
    assert_eq!(
        as_task_owner
            .runs_pause(control(free.id))
            .expect("the TASK's owner pauses its branch")
            .effect,
        RunControlEffect::Paused
    );
    assert_eq!(
        as_task_owner
            .runs_resume(control(free.id))
            .expect("and resumes its own pause")
            .effect,
        RunControlEffect::Resumed
    );

    // The budget hold refuses it and names what the run waits on.
    let held = budget_held_row(&vault, &queue, Some(task), now);
    let refusal = as_task_owner
        .runs_resume(control(held))
        .expect_err("the budget hold refuses the TASK's owner");
    assert_eq!(refusal.code, "FORBIDDEN");
    assert_eq!(
        refusal.reason_codes,
        vec!["awaits:budget_resume".to_owned()]
    );
    assert_eq!(
        RunState::of(&read(&queue, held)),
        RunState::Paused(PauseKind::Budget)
    );

    // The vault owner overrides it.
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    assert_eq!(
        vault
            .memory(owner, EdgeActorClass::Human)
            .runs_resume(control(held))
            .expect("the vault owner overrides the hold")
            .effect,
        RunControlEffect::Resumed
    );
    assert_eq!(read(&queue, held).state, AttemptState::Queued);
}
