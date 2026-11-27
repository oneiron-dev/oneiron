//! CG-2 row 9 (owner COMPUTE-CG = AA, 25 Nov 22:56): "A drained machine clears itself once its
//! readiness check passes; you hear only when the check keeps failing." These tests cover the
//! issuer's half (FIX CG2-ROW9-ISSUER-HALF-NOT-WIRED).
//!
//! The issuer reads a node's `Node` answer on a schedule, and `ReadinessReads` reads the
//! answer's readiness fact:
//! - A passed check clears the issuer's drain under `machines.drain.clear_by =
//!   after_readiness_check` (the default) and under no other value. The baseline is the newest
//!   check in the first answer after the issuer read its guard row. The first check the node
//!   settles after it may have started before the drain, so it clears nothing. Only a check the
//!   node dates later still counts, on its own clock, and only while the row is unchanged. The
//!   two machines' clocks are never compared (REVIEW-10518 rounds 1 and 2; EM-22 R4 should-fix
//!   1 and 2).
//! - A run of failed checks raises the owner's one ask for the run once it reaches
//!   `machines.readiness.escalate_after` (default 3).
//! - Every machine read in the last `ReadinessReads::IDLE_MS` is kept, however many answer, and
//!   a machine idle for longer is dropped.
//! - Only the vault's issuer of vault machine jobs acts on the readings (round 2).
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! cargo test --locked -p oneiron-server --all-features --test issuer_readiness_drain
//! ```

use oneiron::consent::AuthenticatedOwner;
use oneiron::job_dispatch::machine_records::{MachineDrain, MachineJobGuard, MachineJobOutcome};
use oneiron::machine_readiness::ReadinessEscalation;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::gpu_execution_node::issuer::guard::{ReadinessObserved, ReadinessReads};
use oneiron_server::gpu_execution_node::wire::{
    NodeReadiness, ReadinessCheck, ReadinessResult, ReadinessState,
};
use serde_json::json;

/// 25 Nov 2026 10:00 UTC: when the issuer drained the machine, on its own clock.
const DRAINED_AT_MS: u64 = 1_795_600_800_000;
/// `jobs.readiness.every_secs`, its default, in milliseconds.
const PERIOD_MS: u64 = 900_000;
/// When the issuer first reads the answers in these tests: a day after the drain.
const READ_AT_MS: u64 = DRAINED_AT_MS + 86_400_000;
/// The node's newest check in the first answer after the drain. On the node's clock it reads
/// ten periods after the drain: this node's clock runs ahead, or the check ran before the drain.
/// The issuer cannot tell which, so this check is only the baseline.
const FIRST_SEEN_MS: u64 = DRAINED_AT_MS + 10 * PERIOD_MS;
const NODE_DRAINED: &str = "readiness devices: driver not answering";

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open(dir.path(), config).expect("vault opens");
    (dir, vault)
}

/// The vault's embedded owner, and his proof.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// Counts one of the machine's own failures at `at_ms`.
fn fail(vault: &Vault, machine: EntityId, n: u32, at_ms: u64) {
    vault
        .count_machine_job_outcome(
            machine,
            &MachineJobOutcome::MachineFailure {
                why: format!("lost: node_reset {n}"),
            },
            at_ms,
        )
        .expect("count the failure");
}

/// Three of the machine's own failures in a row at `DRAINED_AT_MS`: the issuer drains it
/// (`jobs.drain.after_failures`, default 3).
fn drain(vault: &Vault, machine: EntityId) -> MachineDrain {
    for n in 1..=3 {
        fail(vault, machine, n, DRAINED_AT_MS);
    }
    drained(vault, machine).expect("three failures in a row drain the machine")
}

fn drained(vault: &Vault, machine: EntityId) -> Option<MachineDrain> {
    vault.machine_job_drained(machine).expect("read the drain")
}

/// The issuer's guard row of `machine`, as the pass reads it before it sends `Node`.
fn guard(vault: &Vault, machine: EntityId) -> MachineJobGuard {
    vault
        .machine_job_guard(machine)
        .expect("read the guard")
        .expect("the machine's guard")
}

/// The node's fact after a passed check at `at_ms`, on its own clock.
fn passed(at_ms: u64) -> NodeReadiness {
    NodeReadiness {
        state: ReadinessState::Ready,
        checked_at_ms: Some(at_ms),
        failed_in_a_row: 0,
        failing_since_ms: None,
        results: vec![ReadinessResult {
            at_ms,
            state: ReadinessState::Ready,
        }],
    }
}

/// The node's fact at the `failed`th failed check of the run that began at `since_ms`.
fn failing(since_ms: u64, failed: u32) -> NodeReadiness {
    let not_ready = ReadinessState::NotReady {
        check: ReadinessCheck::Devices,
        why: "driver not answering".to_owned(),
    };
    let at = |index: u32| since_ms + u64::from(index) * PERIOD_MS;
    NodeReadiness {
        state: not_ready.clone(),
        checked_at_ms: Some(at(failed - 1)),
        failed_in_a_row: failed,
        failing_since_ms: Some(since_ms),
        results: (0..failed)
            .map(|index| ReadinessResult {
                at_ms: at(index),
                state: not_ready.clone(),
            })
            .collect(),
    }
}

/// One reading that is acted on (not a repeat of the last sample).
fn read(
    reads: &mut ReadinessReads,
    vault: &Vault,
    machine: EntityId,
    guard_before: &MachineJobGuard,
    node_drained: Option<&str>,
    readiness: &NodeReadiness,
    now_ms: u64,
) -> ReadinessObserved {
    reads
        .observe(
            vault,
            machine,
            Some(guard_before),
            node_drained,
            readiness,
            now_ms,
        )
        .expect("a new sample is acted on")
}

/// Under the default `after_readiness_check`, the first answer after the issuer read its drain
/// only sets the baseline, however late the node dates its check. Then only a passed check the
/// node dates later than that baseline clears the issuer's drain and its count, once, and only in
/// an answer that shows the node's own drain cleared. A newer failed check clears nothing.
#[test]
fn a_passed_check_newer_than_the_baseline_clears_the_issuers_drain_under_the_default() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);
    let before = guard(&vault, machine);
    let mut reads = ReadinessReads::default();

    let first = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS),
        READ_AT_MS,
    );
    assert_eq!(
        first.cleared, None,
        "the newest check in the first answer after the read may have run before the drain"
    );
    assert_eq!(
        reads.observe(
            &vault,
            machine,
            Some(&before),
            None,
            &passed(FIRST_SEEN_MS),
            READ_AT_MS + 1,
        ),
        None,
        "the same sample again is not acted on"
    );

    let node_still_drained = read(
        &mut reads,
        &vault,
        machine,
        &before,
        Some(NODE_DRAINED),
        &passed(FIRST_SEEN_MS + PERIOD_MS),
        READ_AT_MS + 2,
    );
    assert_eq!(
        node_still_drained.cleared, None,
        "the node's own drain still stands in the same answer"
    );
    let newer_failure = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &failing(FIRST_SEEN_MS + 2 * PERIOD_MS, 1),
        READ_AT_MS + 3,
    );
    assert_eq!(newer_failure.cleared, None, "a failed check clears nothing");
    assert_eq!(
        drained(&vault, machine),
        Some(was.clone()),
        "the drain stands"
    );

    let observed = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS + 3 * PERIOD_MS),
        READ_AT_MS + 4,
    );
    assert_eq!(
        observed.cleared,
        Some(was),
        "a passed check newer than the baseline clears it"
    );
    assert_eq!(observed.escalation, None, "a passed check raises no ask");
    assert!(!observed.store_failed);
    assert_eq!(
        drained(&vault, machine),
        None,
        "the start gate admits the machine again"
    );
    let cleared = guard(&vault, machine);
    assert_eq!(cleared.failures_in_a_row, 0, "the count starts again");
    assert_eq!(cleared.last_failure, None);
    assert_eq!(
        cleared.updated_at_ms,
        READ_AT_MS + 4,
        "written at the issuer's read"
    );

    let again = read(
        &mut reads,
        &vault,
        machine,
        &cleared,
        None,
        &passed(FIRST_SEEN_MS + 4 * PERIOD_MS),
        READ_AT_MS + PERIOD_MS,
    );
    assert_eq!(again.cleared, None, "nothing is left to clear");
}

/// A failure counted after the issuer read the guard row (a late terminal receipt of a key sent
/// before the drain) changes the row. A passed check read against the old row clears nothing,
/// and the fresh failure stands. The next answer, read with the new row, is the new baseline,
/// and only a check newer than that one clears (EM-22 R4 should-fix 1).
#[test]
fn a_failure_counted_after_the_read_keeps_the_drain_until_a_check_newer_than_a_new_baseline() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    drain(&vault, machine);
    let before = guard(&vault, machine);
    let mut reads = ReadinessReads::default();
    read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS),
        READ_AT_MS,
    );

    fail(&vault, machine, 4, READ_AT_MS + 1);
    let stale = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS + PERIOD_MS),
        READ_AT_MS + 2,
    );
    assert_eq!(
        stale.cleared, None,
        "the row changed after the read that came before this request"
    );
    let after = guard(&vault, machine);
    assert_eq!(after.failures_in_a_row, 4, "the late failure stands");
    let still = after.drained.clone();
    assert!(still.is_some(), "the drain stands");

    let new_baseline = read(
        &mut reads,
        &vault,
        machine,
        &after,
        None,
        &passed(FIRST_SEEN_MS + PERIOD_MS),
        READ_AT_MS + 3,
    );
    assert_eq!(
        new_baseline.cleared, None,
        "the first answer after the new read is only its baseline"
    );
    assert_eq!(drained(&vault, machine), still);
    let settled = read(
        &mut reads,
        &vault,
        machine,
        &after,
        None,
        &passed(FIRST_SEEN_MS + 2 * PERIOD_MS),
        READ_AT_MS + 4,
    );
    assert_eq!(
        settled.cleared, None,
        "the first check settled after the new baseline may have begun before the read"
    );

    let observed = read(
        &mut reads,
        &vault,
        machine,
        &after,
        None,
        &passed(FIRST_SEEN_MS + 3 * PERIOD_MS),
        READ_AT_MS + 5,
    );
    assert_eq!(
        observed.cleared, still,
        "a check newer than the new baseline clears"
    );
    assert_eq!(drained(&vault, machine), None);
}

/// Any `machines.drain.clear_by` but `after_readiness_check` keeps the issuer's drain: `owner`
/// leaves it to door 12, and `person_at_box` to no verb at all (`resume` at the box clears only
/// the node's own drain). A passed check newer than the baseline clears nothing.
#[test]
fn a_passed_check_clears_nothing_under_any_other_clear_by() {
    let (_dir, vault) = open();
    let owner = owner_proof(&vault);
    for (n, by) in ["owner", "person_at_box"].into_iter().enumerate() {
        let machine = EntityId::now();
        let outcome = vault
            .set_setting(
                SettingCaller::Owner(&owner),
                SetSetting {
                    item: Some(machine.to_hex()),
                    ..SetSetting::vault_value("machines.drain.clear_by", json!({ "by": by }))
                },
            )
            .expect("the owner sets who clears the drain");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "{n}: {outcome:?}"
        );
        let was = drain(&vault, machine);
        let before = guard(&vault, machine);
        let mut reads = ReadinessReads::default();
        read(
            &mut reads,
            &vault,
            machine,
            &before,
            None,
            &passed(FIRST_SEEN_MS),
            READ_AT_MS,
        );
        let observed = read(
            &mut reads,
            &vault,
            machine,
            &before,
            None,
            &passed(FIRST_SEEN_MS + PERIOD_MS),
            READ_AT_MS + PERIOD_MS,
        );
        assert_eq!(observed.cleared, None, "clear_by {by}: no check clears it");
        assert_eq!(
            drained(&vault, machine),
            Some(was),
            "clear_by {by}: the drain stands"
        );
    }
}

/// A run of failed checks reaches the owner once it is `escalate_after` (3) long, as one ask.
/// Later readings of the same run raise nothing more, after a restart of the readings too, and
/// a failing check clears no drain.
#[test]
fn a_run_of_failed_checks_raises_one_ask_at_escalate_after() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);
    let before = guard(&vault, machine);
    let since = FIRST_SEEN_MS;
    let mut reads = ReadinessReads::default();

    for failed in [1, 2] {
        let observed = read(
            &mut reads,
            &vault,
            machine,
            &before,
            None,
            &failing(since, failed),
            READ_AT_MS,
        );
        assert_eq!(
            observed.escalation,
            Some(ReadinessEscalation::BelowThreshold { escalate_after: 3 }),
            "{failed} failed checks reach no one"
        );
        assert_eq!(observed.cleared, None);
    }

    let third = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &failing(since, 3),
        READ_AT_MS,
    );
    let Some(ReadinessEscalation::Asked {
        seq,
        queued_now: true,
    }) = third.escalation
    else {
        panic!("the third failed check asks the owner: {third:?}");
    };

    let restarted = ReadinessReads::default().observe(
        &vault,
        machine,
        Some(&before),
        None,
        &failing(since, 3),
        READ_AT_MS + PERIOD_MS,
    );
    let fourth = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &failing(since, 4),
        READ_AT_MS + PERIOD_MS,
    );
    for later in [
        restarted.map(|observed| observed.escalation),
        Some(fourth.escalation),
    ] {
        assert_eq!(
            later,
            Some(Some(ReadinessEscalation::Asked {
                seq,
                queued_now: false,
            })),
            "a later reading of the same run finds its ask"
        );
    }
    assert_eq!(
        drained(&vault, machine),
        Some(was),
        "a failing check clears nothing"
    );
}

/// A check the node settled after the baseline's answer may have started, and run its probes,
/// before the issuer drained the machine: the node can pause between its probes and settling
/// them. It clears nothing. The node runs one check at a time, so the next check it dates later
/// began after that one settled, after the drain, and it clears (REVIEW-10518 round 2 P1).
#[test]
fn a_check_settled_after_the_baseline_clears_nothing_and_the_next_one_clears() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);
    let before = guard(&vault, machine);
    let mut reads = ReadinessReads::default();
    read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS),
        READ_AT_MS,
    );

    let in_flight = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS + PERIOD_MS / 2),
        READ_AT_MS + 1,
    );
    assert_eq!(
        in_flight.cleared, None,
        "the check in flight at the drain may have run its probes before it"
    );
    assert_eq!(drained(&vault, machine), Some(was.clone()));

    let next = read(
        &mut reads,
        &vault,
        machine,
        &before,
        None,
        &passed(FIRST_SEEN_MS + PERIOD_MS),
        READ_AT_MS + 2,
    );
    assert_eq!(next.cleared, Some(was), "the next passed check clears");
    assert_eq!(drained(&vault, machine), None);
}

/// Every machine read in the last `IDLE_MS` is kept, however many the worker reads in a pass. A
/// drained machine read after more than a thousand others in each pass keeps its baseline, and
/// its passed checks clear it (REVIEW-10518 round 2 P1). A machine not read for `IDLE_MS` is
/// dropped.
#[test]
fn the_readings_keep_every_machine_read_within_a_day_and_drop_idle_ones() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);
    let before = guard(&vault, machine);
    let others: Vec<EntityId> = (0..1_100).map(|_| EntityId::now()).collect();
    let mut reads = ReadinessReads::default();
    for (pass, cleared) in [(0, None), (1, None), (2, Some(was))] {
        let at = READ_AT_MS + pass * PERIOD_MS;
        let check = passed(FIRST_SEEN_MS + pass * PERIOD_MS);
        for other in &others {
            reads.observe(&vault, *other, None, None, &check, at);
        }
        let observed = read(&mut reads, &vault, machine, &before, None, &check, at);
        assert_eq!(observed.cleared, cleared, "pass {pass}");
    }
    assert_eq!(
        reads.len(),
        others.len() + 1,
        "no machine read today is dropped"
    );

    reads.observe(
        &vault,
        EntityId::now(),
        None,
        None,
        &passed(FIRST_SEEN_MS),
        READ_AT_MS + 2 * PERIOD_MS + ReadinessReads::IDLE_MS,
    );
    assert_eq!(reads.len(), 1, "every idle machine is dropped");
}

/// Only the vault's issuer of vault machine jobs (`[gpu_jobs.vault_machine] issuer` names this
/// install's MACHINE) acts on the readiness facts its worker's pass reads. On any other replica
/// the pass reads a node's answers and acts on none, so it neither clears the issuer's drain nor
/// queues the owner's ask (REVIEW-10518 round 2 P1).
#[cfg(oneiron_test_support)]
#[test]
fn only_the_issuer_acts_on_the_readiness_facts_it_reads() {
    use std::sync::Arc;

    use oneiron_server::config::gpu_jobs::VaultMachineSettings;
    use oneiron_server::config::{GpuJobsSettings, SyncServerConfig};
    use oneiron_server::server::SyncServer;
    use oneiron_server::test_doors::work_order_host::worker_pass_observes;

    let (_dir, vault) = open();
    vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let vault = Arc::new(vault);
    let server = |issuer: Option<EntityId>| {
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("issuer-readiness-drain-secret".to_owned()),
                gpu_jobs: GpuJobsSettings {
                    vault_machine: VaultMachineSettings {
                        enabled: true,
                        issuer,
                        ..VaultMachineSettings::default()
                    },
                    ..GpuJobsSettings::default()
                },
                ..SyncServerConfig::default()
            },
        )
        .expect("the server boots")
    };

    let unnamed = server(None);
    assert!(
        !worker_pass_observes(&unnamed),
        "no issuer named: the pass acts on nothing"
    );
    drop(unnamed);
    let local = vault
        .local_machine()
        .expect("read this install's MACHINE")
        .expect("a serving start enrols this install")
        .id;
    let elsewhere = server(Some(EntityId::now()));
    assert!(
        !worker_pass_observes(&elsewhere),
        "another MACHINE is the issuer: the pass acts on nothing"
    );
    drop(elsewhere);
    let issuer = server(Some(local));
    assert!(
        worker_pass_observes(&issuer),
        "the issuer's pass acts on its readings"
    );
}
