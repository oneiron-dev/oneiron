//! CG-2 row 9 (owner COMPUTE-CG = AA, 25 Nov 22:56): "A drained machine clears itself once its
//! readiness check passes; you hear only when the check keeps failing." These tests cover the
//! issuer's half (FIX CG2-ROW9-ISSUER-HALF-NOT-WIRED).
//!
//! On the issuer's scheduled read of a node's `Node` answer, `observe_node_readiness` reads the
//! answer's readiness fact:
//! - a passed check that ran after the issuer's drain clears that drain, under
//!   `machines.drain.clear_by = after_readiness_check` (the default) and under no other value;
//! - a run of failed checks raises the owner's one ask for the run once it reaches
//!   `machines.readiness.escalate_after` (default 3).
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! cargo test --locked -p oneiron-server --all-features --test issuer_readiness_drain
//! ```

use oneiron::consent::AuthenticatedOwner;
use oneiron::job_dispatch::machine_records::{MachineDrain, MachineJobOutcome};
use oneiron::machine_readiness::ReadinessEscalation;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::gpu_execution_node::issuer::guard::observe_node_readiness;
use oneiron_server::gpu_execution_node::wire::{
    NodeReadiness, ReadinessCheck, ReadinessResult, ReadinessState,
};
use serde_json::json;

/// 25 Nov 2026 10:00 UTC: when the issuer drained the machine, on its own clock.
const DRAINED_AT_MS: u64 = 1_795_600_800_000;
/// `jobs.readiness.every_secs`, its default, in milliseconds.
const PERIOD_MS: u64 = 900_000;
/// When the issuer reads the answers in these tests: a day after the drain.
const READ_AT_MS: u64 = DRAINED_AT_MS + 86_400_000;

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

/// Three of the machine's own failures in a row at `DRAINED_AT_MS`: the issuer drains it
/// (`jobs.drain.after_failures`, default 3).
fn drain(vault: &Vault, machine: EntityId) -> MachineDrain {
    for n in 1..=3 {
        vault
            .count_machine_job_outcome(
                machine,
                &MachineJobOutcome::MachineFailure {
                    why: format!("lost: node_reset {n}"),
                },
                DRAINED_AT_MS,
            )
            .expect("count the failure");
    }
    vault
        .machine_job_drained(machine)
        .expect("read the drain")
        .expect("three failures in a row drain the machine")
}

fn drained(vault: &Vault, machine: EntityId) -> Option<MachineDrain> {
    vault.machine_job_drained(machine).expect("read the drain")
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

/// Under the default `after_readiness_check`, only a passed check that ran after the drain
/// clears the issuer's drain and its count, once. A check that ran before it, or at the same
/// millisecond, changes nothing.
#[test]
fn a_passed_check_after_the_drain_clears_the_issuers_drain_under_the_default() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);

    for before in [DRAINED_AT_MS - PERIOD_MS, DRAINED_AT_MS] {
        let observed = observe_node_readiness(&vault, machine, &passed(before), READ_AT_MS);
        assert_eq!(
            observed.cleared, None,
            "a check at {before} ran before the drain"
        );
        assert_eq!(
            drained(&vault, machine),
            Some(was.clone()),
            "the drain stands"
        );
    }

    let observed = observe_node_readiness(
        &vault,
        machine,
        &passed(DRAINED_AT_MS + PERIOD_MS),
        READ_AT_MS,
    );
    assert_eq!(
        observed.cleared,
        Some(was),
        "a check after the drain clears it"
    );
    assert_eq!(observed.escalation, None, "a passed check raises no ask");
    assert_eq!(
        drained(&vault, machine),
        None,
        "the start gate admits the machine again"
    );
    let guard = vault
        .machine_job_guard(machine)
        .expect("read the guard")
        .expect("the machine's guard");
    assert_eq!(guard.failures_in_a_row, 0, "the count starts again");
    assert_eq!(guard.last_failure, None);
    assert_eq!(
        guard.updated_at_ms, READ_AT_MS,
        "written at the issuer's read"
    );

    let again = observe_node_readiness(
        &vault,
        machine,
        &passed(DRAINED_AT_MS + 2 * PERIOD_MS),
        READ_AT_MS + PERIOD_MS,
    );
    assert_eq!(again.cleared, None, "nothing is left to clear");
}

/// `machines.drain.clear_by` other than `after_readiness_check` keeps the drain for door 12 or
/// the box: a passed check clears nothing.
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
        let observed = observe_node_readiness(
            &vault,
            machine,
            &passed(DRAINED_AT_MS + PERIOD_MS),
            READ_AT_MS,
        );
        assert_eq!(observed.cleared, None, "clear_by {by}: no check clears it");
        assert_eq!(
            drained(&vault, machine),
            Some(was),
            "clear_by {by}: the drain stands"
        );
    }
}

/// A run of failed checks reaches the owner once it is `escalate_after` (3) long, as one ask;
/// later reads of the same run raise nothing more, and a failing check clears no drain.
#[test]
fn a_run_of_failed_checks_raises_one_ask_at_escalate_after() {
    let (_dir, vault) = open();
    let machine = EntityId::now();
    let was = drain(&vault, machine);
    let since = DRAINED_AT_MS + PERIOD_MS;

    for failed in [1, 2] {
        let observed = observe_node_readiness(&vault, machine, &failing(since, failed), READ_AT_MS);
        assert_eq!(
            observed.escalation,
            Some(ReadinessEscalation::BelowThreshold { escalate_after: 3 }),
            "{failed} failed checks reach no one"
        );
        assert_eq!(observed.cleared, None);
    }

    let third = observe_node_readiness(&vault, machine, &failing(since, 3), READ_AT_MS);
    let Some(ReadinessEscalation::Asked {
        seq,
        queued_now: true,
    }) = third.escalation
    else {
        panic!("the third failed check asks the owner: {third:?}");
    };

    for failed in [3, 4] {
        let later = observe_node_readiness(
            &vault,
            machine,
            &failing(since, failed),
            READ_AT_MS + PERIOD_MS,
        );
        assert_eq!(
            later.escalation,
            Some(ReadinessEscalation::Asked {
                seq,
                queued_now: false,
            }),
            "a later read of the same run finds its ask"
        );
    }
    assert_eq!(
        drained(&vault, machine),
        Some(was),
        "a failing check clears nothing"
    );
}
