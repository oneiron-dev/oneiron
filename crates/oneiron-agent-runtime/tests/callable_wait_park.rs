//! ENGINE CALL SANDBOX-WAIT-PARK-SEMANTICS: a callable whose body finishes
//! after its `wait` was answered with the run's park did not finish. Its run
//! parks, and the body runs again once the wait's reply is delivered, as a
//! body the park unwound does: so a pinned program entry whose source does
//! `finish(await wait(...))` keeps its wait (`engine_executor/program_entry.rs`
//! reads the unfinished call as unfinished), and an inner callable stays open
//! (`ProgramResumeKind::OpenCallable`). The guest still reads the park, its
//! wait's row output (ENGINE CALL CODE-SANDBOX-WAIT-RESPONSE-FIELD). A body
//! whose wait answered with no park finishes as before.
//!
//! The callable runs through the public `oneiron::skill::execute_callable_skill`
//! door, on the pinned first-party QuickJS component and the real typed
//! bridge, under a leased attempt. It is stored through
//! `oneiron::test_doors::callable_skill`, so the test builds only under the
//! test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-agent-runtime --all-features --test callable_wait_park`.
#![cfg(all(oneiron_test_support, feature = "code-sandbox-wasmtime"))]

#[path = "wait_park/fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fixture::{WaitHost, first_party_factory, pending_ask_park};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::code_run::{CodeRunDeterminism, SelfCall, SelfDispatchOutcome};
use oneiron::skill::{CallableSkillAnswer, execute_callable_skill};
use oneiron::task_verb::{TaskAskHandle, TaskAskStatus};
use oneiron::test_doors::callable_skill;
use oneiron::{EntityId, Result, Vault, VaultConfig};
use serde_json::json;

const KIND: &str = "test.callable_wait_park";
const WORKER: &str = "worker:callable-wait-park";
const EXECUTOR: &str = "model-current@1";
/// The callable's body: it finishes with what its wait answered.
const SOURCE: &str = "finish(JSON.stringify(await wait({handle: {group_ref: skillArgs.group_ref}, \
                      step_key: 'sdk.wait'})));";
/// What the refusal of a finish on the run's park says (`skill/call.rs`).
const FINISHED_ON_PARK: &str = "callable skill finished on its run's park";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// A vault and a leased attempt for a callable to run under, at `now`.
fn leased_vault(now: u64) -> (tempfile::TempDir, Arc<Vault>, AttemptRecord) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault opens"));
    let leased = {
        let queue = AttemptQueue::new(&vault);
        let enqueued = queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue");
        assert!(matches!(enqueued, EnqueueOutcome::Enqueued(_)));
        let ClaimOutcome::Claimed(leased) = queue
            .claim_kind(
                KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: now + 1,
                },
            )
            .expect("claim")
        else {
            panic!("the ready attempt is leased");
        };
        leased
    };
    (dir, vault, leased)
}

/// Runs the callable `name`, which returns `returns`, on `group_ref`'s
/// wait, with `host` answering it.
fn run_callable(
    name: &str,
    returns: &serde_json::Value,
    group_ref: EntityId,
    host: &mut WaitHost,
) -> Result<CallableSkillAnswer> {
    let now = unix_now();
    let (_dir, vault, leased) = leased_vault(now);
    let skill = callable_skill::put_active_callable(
        &vault,
        name,
        SOURCE,
        &json!({"group_ref": "string"}),
        returns,
    )
    .expect("the callable is stored and active");
    let mut runtime = first_party_factory().runtime().expect("a guest runtime");
    execute_callable_skill(
        &vault,
        &leased,
        &skill,
        EXECUTOR,
        &json!({"group_ref": group_ref.to_hex()}),
        &mut runtime,
        host,
        EntityId::from_bytes([0x6B; 16]).expect("run id"),
        0,
        CodeRunDeterminism::new(1_700_000_000_000, [0x6C; 32]),
        now + 2,
    )
}

#[test]
fn a_callable_that_finishes_on_its_parked_wait_does_not_finish() {
    let handle = TaskAskHandle {
        group_ref: EntityId::from_bytes([0x6A; 16]).expect("ask group id"),
    };
    let mut host = WaitHost::parking(pending_ask_park(handle.group_ref));
    let ran = run_callable(
        "fixture.wait-park",
        &json!({"Park": "object"}),
        handle.group_ref,
        &mut host,
    );
    let Err(error) = ran else {
        panic!("a callable that finished on its run's park finished");
    };
    let error = error.to_string();
    assert!(
        error.contains(FINISHED_ON_PARK),
        "the body read the park as its wait's output, finished on it, and that finish was \
         refused: {error}"
    );
    assert_eq!(
        host.calls,
        [SelfCall::TasksWait(handle)],
        "the body's one host call is its wait on the ask"
    );
}

#[test]
fn a_callable_whose_wait_answered_no_park_finishes() {
    let handle = TaskAskHandle {
        group_ref: EntityId::from_bytes([0x6D; 16]).expect("ask group id"),
    };
    let mut host = WaitHost {
        answer: SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Changed {
            voided: Vec::new(),
            generation: 1,
        }),
        calls: Vec::new(),
    };
    let ran = run_callable(
        "fixture.wait-changed",
        &json!({"Changed": "object"}),
        handle.group_ref,
        &mut host,
    );
    if let Err(error) = ran {
        panic!("a callable whose wait answered no park did not finish: {error}");
    }
    assert_eq!(
        host.calls,
        [SelfCall::TasksWait(handle)],
        "the body's one host call is its wait on the ask"
    );
}
