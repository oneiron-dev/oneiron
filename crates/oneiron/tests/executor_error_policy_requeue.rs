//! FIX 23347 part 2 (Engine ruling 06:28, 13 Nov): an executor-error park that waits on owner
//! policy is requeued once by the owner's policy-manifest write that changes that policy, in the
//! write's own transaction. A `SourceNotTrustedForAuto` park waits on the `source_trust` section; a
//! `FamilyRequiresAutoGrant` park waits on the sections the gate reads for an Auto answer. A write
//! that changes neither leaves the park parked, and every other owner-act refusal stays
//! owner-released. The pass, the park and the notice read go through the WAKE-D1 doors
//! (`oneiron::test_doors::wake_d1_park_release`), built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_runner::{
    DREAMER_SERVER_PARK_OWNER, DreamerAttemptStatus, DreamerParkedAttemptRecord,
    EnqueueDreamerConsolidationAttempt,
};
use oneiron::error::GateError;
use oneiron::test_doors::wake_d1_park_release as doors;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerConsolidationScope, DreamerParkCause, DreamerRunnerStore, DreamerWakeDriver,
    EnqueueDreamerAttemptOutcome, EntityId, Error, ErrorKind, Result, RunWakePass, Vault,
    VaultConfig, WakeAttemptContext, WakeCancellation, WakePassDeadline, WakePassReport,
    WakeTrigger,
};
use oneiron_store::ports::manual_clock::ManualClock;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The pass self-wakes and pends once per attempt boundary, so polling
    // again immediately is correct; the bound catches a future pending on
    // anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("wake-pass future pending on something other than an attempt-boundary yield");
}

/// A temporary vault on `clock`, with a process-memory device keystore and its embedded owner,
/// as the WAKE-D1 fixture opens one.
fn open_vault(clock: &ManualClock) -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The owner exists before any park, so a park's notice has its owner to name.
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn embedded_owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn enqueue_micro(
    store: &DreamerRunnerStore<'_>,
    tag: &str,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("unexpected enqueue outcome {other:?}"),
    }
}

/// The owner refusal a try meets on its refused runs.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    /// The source-trust ceiling does not trust the claim's source for Auto.
    SourceTrust,
    /// The gate would not answer the family's write Auto.
    AutoGrant,
    /// A consent grant the write named is gone.
    ConsentGrant,
}

impl Refusal {
    fn error(self) -> Error {
        Error::Gate(match self {
            Self::SourceTrust => GateError::SourceNotTrustedForAuto {
                claim_source: "generated",
            },
            Self::AutoGrant => GateError::FamilyRequiresAutoGrant {
                family: "expression preference",
            },
            Self::ConsentGrant => GateError::ConsentGrantNotFound,
        })
    }

    fn kind(self) -> ErrorKind {
        self.error().kind()
    }
}

/// Refuses each listed try on its first `runs` runs and completes every later run; counts each
/// try's runs.
#[derive(Default)]
struct RefusingExecutor {
    refusals: HashMap<AttemptId, (Refusal, u32)>,
    runs: HashMap<AttemptId, u32>,
}

impl RefusingExecutor {
    fn refuse(&mut self, attempt: AttemptId, refusal: Refusal, runs: u32) {
        self.refusals.insert(attempt, (refusal, runs));
    }

    fn runs(&self, attempt: AttemptId) -> u32 {
        self.runs.get(&attempt).copied().unwrap_or(0)
    }
}

impl DreamerAttemptExecutor for RefusingExecutor {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let id = attempt.status.attempt.id;
        let run = self.runs.entry(id).or_insert(0);
        *run += 1;
        if let Some((refusal, refused_runs)) = self.refusals.get(&id)
            && *run <= *refused_runs
        {
            return Err(refusal.error());
        }
        Ok(DreamerAttemptExecution::Completed {
            completed_units: 25,
            step_bindings: Vec::new(),
        })
    }
}

fn frozen_deadline() -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(0));
    WakePassDeadline::with_clock(180_000, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

/// One wake pass of the server's Dreamer at `now`: it leases each try under the server's park
/// owner, so a parked try keeps its lease, as on a running server.
fn run_pass(
    vault: &Vault,
    clock: &ManualClock,
    executor: &mut RefusingExecutor,
    now: u64,
) -> Result<WakePassReport> {
    clock.set(now);
    let local_node_id = doors::load_or_mint_client_id(vault)?;
    let mut driver = DreamerWakeDriver::new(vault, "wake", frozen_deadline());
    block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
            local_node_id,
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now,
            host_scope: None,
            destination_bound: None,
        },
        executor,
        &WakeCancellation::new(),
    ))
}

/// Runs a pass at `now` in which `queued` meets `refusal`: the pass ends on it, and the try parks
/// as an ExecutorError under the server's owner with the owner's notice raised. Returns the park.
fn park_on_refusal(
    vault: &Vault,
    clock: &ManualClock,
    executor: &mut RefusingExecutor,
    queued: &DreamerAttemptStatus,
    refusal: Refusal,
    now: u64,
) -> Result<DreamerParkedAttemptRecord> {
    let ended = run_pass(vault, clock, executor, now).expect_err("the pass ends on the refusal");
    assert_eq!(ended.kind(), refusal.kind(), "the pass ends on {refusal:?}");
    let parked = DreamerRunnerStore::new(vault)
        .parked_attempt(queued.attempt.id)?
        .expect("the refused try parks");
    assert_eq!(parked.cause, DreamerParkCause::ExecutorError);
    assert_eq!(parked.park_owner, DREAMER_SERVER_PARK_OWNER);
    assert_eq!(
        doors::park_notice_seen(vault, &parked)?,
        Some(false),
        "the owner's notice of the {refusal:?} park is raised"
    );
    Ok(parked)
}

/// The test's own policy manifest: one Auto actor ceiling for an agent that is not in the vault,
/// and, when given, a vault-wide `source_trust` row for the Generated source at that maximum
/// sensitivity.
fn policy_manifest(generated_max_auto_sensitivity: Option<u64>) -> Vec<u8> {
    let mut policy = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "executor-error-policy-requeue",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{
            "actor_class": "agent",
            "actor_ref": "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
            "ceiling": "auto",
        }],
    });
    if let Some(sensitivity) = generated_max_auto_sensitivity {
        policy["source_trust"] = serde_json::json!({
            "generated": {
                "max_auto_sensitivity": sensitivity,
                "receipted": true,
                "warned": true,
            },
        });
    }
    rmp_serde::to_vec_named(&policy).expect("policy manifest encodes")
}

/// The test manifest's id: beside the shipped default policy, never replacing it.
fn manifest_id() -> EntityId {
    EntityId::from_bytes([0x5e; 16]).expect("manifest id")
}

/// The ruling's case: a try refused `SourceNotTrustedForAuto` parks; an owner policy write that
/// changes no source trust leaves it parked; the owner's write that changes the `source_trust`
/// section requeues it once, in its own write, and resolves its notice, so the next pass runs it
/// as the same try. Refused again, it parks again, and only a further source-trust change
/// requeues it: a rewrite with the same sections does not.
#[test]
fn a_source_trust_park_requeues_once_per_owner_write_that_changes_the_source_trust_ceiling()
-> Result<()> {
    let clock = ManualClock::new(10);
    let (_dir, vault) = open_vault(&clock)?;
    let store = DreamerRunnerStore::new(&vault);
    let owner = embedded_owner_proof(&vault);
    let mut executor = RefusingExecutor::default();
    let queued = enqueue_micro(&store, "source trust", 10)?;
    let id = queued.attempt.id;
    executor.refuse(id, Refusal::SourceTrust, 2);
    let first = park_on_refusal(
        &vault,
        &clock,
        &mut executor,
        &queued,
        Refusal::SourceTrust,
        20,
    )?;

    // An owner write of the actor ceilings, with no source-trust section: another policy.
    clock.set(30);
    vault.install_owner_policy_manifest(&owner, manifest_id(), policy_manifest(None), 30)?;
    assert!(
        store.parked_attempt(id)?.is_some(),
        "an owner write that changes no source trust leaves the source-trust park parked"
    );
    run_pass(&vault, &clock, &mut executor, 40)?;
    assert_eq!(executor.runs(id), 1, "no pass runs the parked try");

    // The owner raises the Generated source's trust: the write requeues the park in its own
    // transaction and resolves its notice.
    clock.set(50);
    vault.install_owner_policy_manifest(&owner, manifest_id(), policy_manifest(Some(2)), 50)?;
    assert!(
        store.parked_attempt(id)?.is_none(),
        "FAILBEFORE 23347: the owner's source-trust write requeues the try parked on source trust"
    );
    assert_eq!(
        doors::park_notice_seen(&vault, &first)?,
        Some(true),
        "the requeue resolves the park's notice"
    );

    // The next pass runs it as the same try; refused again, it parks again.
    let second = park_on_refusal(
        &vault,
        &clock,
        &mut executor,
        &queued,
        Refusal::SourceTrust,
        60,
    )?;
    assert_eq!(
        executor.runs(id),
        2,
        "the next pass runs the requeued try once"
    );

    // The same sections again: nothing changed, so nothing is requeued.
    clock.set(70);
    vault.install_owner_policy_manifest(&owner, manifest_id(), policy_manifest(Some(2)), 70)?;
    assert_eq!(
        store.parked_attempt(id)?,
        Some(second.clone()),
        "a rewrite with the same source trust leaves the park as it was"
    );
    assert_eq!(doors::park_notice_seen(&vault, &second)?, Some(false));

    // A further source-trust change requeues it once more, and the next pass completes it.
    clock.set(80);
    vault.install_owner_policy_manifest(&owner, manifest_id(), policy_manifest(Some(3)), 80)?;
    assert!(
        store.parked_attempt(id)?.is_none(),
        "a further source-trust change requeues the park again"
    );
    let report = run_pass(&vault, &clock, &mut executor, 90)?;
    assert_eq!(report.completed, 1, "the requeued try completes");
    assert_eq!(executor.runs(id), 3);
    assert!(store.parked_attempt(id)?.is_none());
    Ok(())
}

/// An owner write that changes an Auto approval row requeues the try parked on the family's Auto
/// grant, and not a try parked on a missing consent grant: that refusal has no policy wait and
/// stays owner-released, its notice raised.
#[test]
fn an_auto_approval_write_requeues_the_auto_grant_park_and_not_a_consent_refusal() -> Result<()> {
    let clock = ManualClock::new(10);
    let (_dir, vault) = open_vault(&clock)?;
    let store = DreamerRunnerStore::new(&vault);
    let owner = embedded_owner_proof(&vault);
    let mut executor = RefusingExecutor::default();

    let family = enqueue_micro(&store, "auto grant", 10)?;
    executor.refuse(family.attempt.id, Refusal::AutoGrant, 1);
    let family_park = park_on_refusal(
        &vault,
        &clock,
        &mut executor,
        &family,
        Refusal::AutoGrant,
        20,
    )?;
    let consent = enqueue_micro(&store, "consent grant", 30)?;
    executor.refuse(consent.attempt.id, Refusal::ConsentGrant, 1);
    let consent_park = park_on_refusal(
        &vault,
        &clock,
        &mut executor,
        &consent,
        Refusal::ConsentGrant,
        40,
    )?;

    // The owner's write of an Auto actor ceiling.
    clock.set(50);
    vault.install_owner_policy_manifest(&owner, manifest_id(), policy_manifest(None), 50)?;
    assert!(
        store.parked_attempt(family.attempt.id)?.is_none(),
        "FAILBEFORE 23347: the owner's Auto approval write requeues the try parked on the family's Auto grant"
    );
    assert_eq!(
        doors::park_notice_seen(&vault, &family_park)?,
        Some(true),
        "the requeue resolves the Auto-grant park's notice"
    );
    assert_eq!(
        store.parked_attempt(consent.attempt.id)?,
        Some(consent_park.clone()),
        "a consent refusal stays parked for the owner's release"
    );

    let report = run_pass(&vault, &clock, &mut executor, 60)?;
    assert_eq!(
        report.completed, 1,
        "the next pass completes the requeued try"
    );
    assert_eq!(executor.runs(family.attempt.id), 2);
    assert_eq!(
        executor.runs(consent.attempt.id),
        1,
        "no pass runs the consent-refused try"
    );
    assert_eq!(
        store.parked_attempt(consent.attempt.id)?,
        Some(consent_park.clone()),
        "the consent park stays as it was"
    );
    assert_eq!(
        doors::park_notice_seen(&vault, &consent_park)?,
        Some(false),
        "the consent park's notice stands"
    );
    Ok(())
}
