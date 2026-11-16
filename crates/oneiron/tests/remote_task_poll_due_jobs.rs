//! DESIGN 15-setting-primitive, stage 5c-2: a pollable Deferred send's next poll is a row of
//! `outbound_intent_ledger.remote_task_poll`, a job its host drives (OPUS-SETTING's answer to ASK
//! SETTING-SCHEDULE-5C2-HOST-JOBS, point 3 = B):
//! - the deferral's write arms the row at the task's first poll, the provider's hint or the
//!   host's pass, on the recording clock, and the row wakes a stopped vault then;
//! - the served host's due list is the rows due now, read by the recording clock;
//! - a poll that found the task running re-arms the row after its backoff or the provider's
//!   hint, in whole seconds; an owner's answer to its question pulls it to now;
//! - the schedule's runner never runs the row, the owner's listing names its host as its driver,
//!   and the owner's "run now" of it is refused;
//! - a settled task's write disarms its row.
//!
//! Red before 5c-2: no poll row is ever armed, and the due list reads the poll table's own time,
//! which the deferral counts from the caller's clock.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test remote_task_poll_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::{
    REMOTE_TASK_POLL, defer_pollable_remote_task, due_at, remote_task_polled_now,
    remote_task_polls_due_now, remote_tasks_due_now, settle_remote_task_unconfirmed,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const LIST: &str = "vault.schedules.list";
const RUN: &str = "vault.schedules.run";

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            _dir: dir,
            owner,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    fn pass(&self) {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("the housekeeping pass");
    }

    /// When `intent`'s poll row is next due, or `None` when it is not armed.
    fn poll_due(&self, intent: &[u8; 32]) -> Option<u64> {
        due_at(&self.vault, REMOTE_TASK_POLL, Some(subject(intent))).expect("the due time")
    }

    fn wake(&self) -> Option<u64> {
        self.vault.housekeeping_wake_at().expect("the wake time")
    }

    /// The owner's view of `intent`'s poll row.
    fn listed(&self, intent: &[u8; 32]) -> Value {
        let listed = invoke(
            &self.as_owner(),
            LIST,
            json!({ "job": REMOTE_TASK_POLL, "subject": subject(intent).to_hex() }),
        )
        .expect("the owner lists the schedules");
        listed["schedules"][0].clone()
    }
}

/// The schedule subject of `intent`'s poll row: the id's first 16 bytes.
fn subject(intent: &[u8; 32]) -> EntityId {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&intent[..16]);
    EntityId::from_bytes(bytes).expect("subject")
}

#[test]
fn a_deferred_task_arms_its_first_poll_and_wakes_the_host_then() {
    let fx = Fixture::rooted();
    let task = defer_pollable_remote_task(&fx.vault, 0x51, None);
    assert_eq!(
        fx.poll_due(&task),
        Some(T0 + 30),
        "the host's pass after the deferral"
    );
    assert_eq!(
        fx.wake(),
        Some(T0 + 30),
        "the row wakes a stopped vault then"
    );
    let hinted = defer_pollable_remote_task(&fx.vault, 0x52, Some(300));
    assert_eq!(
        fx.poll_due(&hinted),
        Some(T0 + 300),
        "the provider's longer hint"
    );
}

#[test]
fn the_due_list_is_the_rows_due_on_the_recording_clock() {
    let fx = Fixture::rooted();
    let soon = defer_pollable_remote_task(&fx.vault, 0x53, None);
    let later = defer_pollable_remote_task(&fx.vault, 0x54, Some(300));
    fx.at(T0 + 29);
    assert!(
        remote_tasks_due_now(&fx.vault).is_empty(),
        "nothing is due yet"
    );
    fx.at(T0 + 30);
    assert_eq!(remote_tasks_due_now(&fx.vault), vec![soon]);
    fx.at(T0 + 300);
    let mut due = remote_tasks_due_now(&fx.vault);
    due.sort_unstable();
    let mut both = vec![soon, later];
    both.sort_unstable();
    assert_eq!(due, both);
}

#[test]
fn a_running_poll_arms_the_next_after_its_backoff_or_the_hint() {
    let fx = Fixture::rooted();
    let task = defer_pollable_remote_task(&fx.vault, 0x55, None);
    fx.at(T0 + 30);
    remote_task_polled_now(&fx.vault, &task, None);
    assert_eq!(
        fx.poll_due(&task),
        Some(T0 + 30 + 60),
        "the first poll doubles the pass"
    );
    fx.at(T0 + 90);
    remote_task_polled_now(&fx.vault, &task, Some(500_500));
    assert_eq!(
        fx.poll_due(&task),
        Some(T0 + 90 + 501),
        "a longer hint, rounded up to its second"
    );
    assert!(remote_tasks_due_now(&fx.vault).is_empty());
}

#[test]
fn an_answered_question_makes_its_poll_due_now() {
    let fx = Fixture::rooted();
    let task = defer_pollable_remote_task(&fx.vault, 0x56, None);
    fx.at(T0 + 30);
    remote_task_polled_now(&fx.vault, &task, None);
    fx.at(T0 + 40);
    assert!(remote_tasks_due_now(&fx.vault).is_empty());
    remote_task_polls_due_now(&fx.vault, &[task]);
    assert_eq!(fx.poll_due(&task), Some(T0 + 40));
    assert_eq!(remote_tasks_due_now(&fx.vault), vec![task]);
}

#[test]
fn the_runner_never_runs_a_poll_row_and_the_owner_sees_its_host_drives_it() {
    let fx = Fixture::rooted();
    let task = defer_pollable_remote_task(&fx.vault, 0x57, None);
    fx.at(T0 + 100);
    fx.pass();
    assert_eq!(fx.poll_due(&task), Some(T0 + 30), "no run moved it");
    let view = fx.listed(&task);
    assert_eq!(view["drive"], json!("host"), "{view}");
    assert_eq!(view["finished_at"], json!(0), "{view}");
    assert_eq!(view["running"], json!(false), "{view}");
    invoke(
        &fx.as_owner(),
        RUN,
        json!({ "job": REMOTE_TASK_POLL, "subject": subject(&task).to_hex() }),
    )
    .expect_err("no run now is asked of a row its host drives");
    assert_eq!(fx.poll_due(&task), Some(T0 + 30));
    assert_eq!(
        remote_tasks_due_now(&fx.vault),
        vec![task],
        "the host polls it"
    );
}

#[test]
fn a_settled_task_disarms_its_poll_row() {
    let fx = Fixture::rooted();
    let task = defer_pollable_remote_task(&fx.vault, 0x58, None);
    let other = defer_pollable_remote_task(&fx.vault, 0x59, None);
    assert_eq!(fx.poll_due(&task), Some(T0 + 30));
    settle_remote_task_unconfirmed(&fx.vault, &task);
    assert_eq!(fx.poll_due(&task), None, "its row went with its poll");
    assert_eq!(
        fx.poll_due(&other),
        Some(T0 + 30),
        "another task keeps its own"
    );
}
