//! Pass 34 row Q4, the issuer's half (`34-compute-general/DESIGN.md` 16,
//! practice 6; Engine ANSWER Q4-ESCALATION-SIDE = B): a machine whose
//! readiness check keeps failing reaches the owner as ONE decision ask per
//! run of failed checks, once the run reaches the machine's
//! `machines.readiness.escalate_after` (default 3). Through the built queue
//! as it is: the open asks list, and the owner's answer.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test machine_readiness_ask`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{AnswerContract, DecisionAnswer, DecisionAsk};
use oneiron::machine_readiness::{
    CLEAR_THE_DRAIN, KEEP_IT_DRAINED, MACHINE_READINESS_QUEUE, ReadinessEscalation,
    ReadinessStreak, TAKE_THE_MACHINE_OUT,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

/// 25 Nov 2026 10:00 UTC, on the machine's clock.
const SINCE_MS: u64 = 1_795_600_800_000;
const PERIOD_MS: u64 = 900_000;

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

/// Every machine-readiness ask, open or answered, oldest first.
fn readiness_asks(vault: &Vault) -> Vec<DecisionAsk> {
    vault
        .decision_asks(None, 10_000, false)
        .expect("the decision asks")
        .into_iter()
        .filter(|ask| ask.queue_pin.model == MACHINE_READINESS_QUEUE)
        .collect()
}

/// `machine`'s run that began at `since`, at its `failed`th failed check.
fn streak(machine: EntityId, since: u64, failed: u32) -> ReadinessStreak {
    ReadinessStreak {
        machine,
        failed_in_a_row: failed,
        failing_since_ms: since,
        check: "devices".to_owned(),
        why: format!("driver not answering ({failed})"),
        results: (0..failed)
            .map(|index| format!("devices: driver not answering ({index})"))
            .collect(),
    }
}

fn asked(escalation: ReadinessEscalation) -> (u64, bool) {
    match escalation {
        ReadinessEscalation::Asked { seq, queued_now } => (seq, queued_now),
        other => panic!("expected an ask, got {other:?}"),
    }
}

/// Section 16, practice 6: below the threshold nothing reaches the owner; at
/// it, one ask with three choices and a recommendation; later reads of the
/// same run, open or answered, queue nothing; a new run is a new ask.
#[test]
fn a_readiness_check_that_keeps_failing_asks_the_owner_once_per_run() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let machine = EntityId::now();

    for failed in 1..3 {
        assert_eq!(
            vault
                .raise_machine_readiness_ask(&streak(machine, SINCE_MS, failed))
                .expect("the read"),
            ReadinessEscalation::BelowThreshold { escalate_after: 3 }
        );
    }
    assert!(readiness_asks(&vault).is_empty());

    let (seq, queued_now) = asked(
        vault
            .raise_machine_readiness_ask(&streak(machine, SINCE_MS, 3))
            .expect("the third failed check"),
    );
    assert!(queued_now);
    let asks = readiness_asks(&vault);
    assert_eq!(asks.len(), 1);
    let ask = &asks[0];
    assert_eq!(ask.seq, seq);
    assert!(ask.is_open());
    assert_eq!(
        ask.question.contract,
        AnswerContract::Choice {
            options: vec![
                CLEAR_THE_DRAIN.to_owned(),
                KEEP_IT_DRAINED.to_owned(),
                TAKE_THE_MACHINE_OUT.to_owned(),
            ],
        }
    );
    assert!(ask.question.text.contains(&machine.to_hex()));
    assert!(ask.question.text.contains("2026-11-25T10:00:00.000Z"));
    assert!(ask.question.text.contains("Recommended: keep it drained"));
    let state = ask.pack_state.as_ref().expect("the ask's details");
    assert_eq!(state["failed_in_a_row"], json!(3));
    assert_eq!(state["check"], json!("devices"));
    assert_eq!(state["recommendation"], json!(KEEP_IT_DRAINED));

    // The same run, read again with newer results: the same ask.
    assert_eq!(
        vault
            .raise_machine_readiness_ask(&streak(machine, SINCE_MS, 4))
            .expect("the fourth failed check"),
        ReadinessEscalation::Asked {
            seq,
            queued_now: false
        }
    );
    // The owner answers; the run's next read still finds that ask.
    vault
        .answer_decision_ask(
            &proof,
            seq,
            DecisionAnswer::Choice(KEEP_IT_DRAINED.to_owned()),
        )
        .expect("the owner's answer");
    assert_eq!(
        vault
            .raise_machine_readiness_ask(&streak(machine, SINCE_MS, 5))
            .expect("the fifth failed check"),
        ReadinessEscalation::Asked {
            seq,
            queued_now: false
        }
    );
    assert_eq!(readiness_asks(&vault).len(), 1);

    // A check passed, and a new run failed three times: a new ask.
    let (second, queued_now) = asked(
        vault
            .raise_machine_readiness_ask(&streak(machine, SINCE_MS + 10 * PERIOD_MS, 3))
            .expect("the new run"),
    );
    assert!(queued_now);
    assert_ne!(second, seq);
    assert_eq!(readiness_asks(&vault).len(), 2);
}

/// `machines.readiness.escalate_after` is the owner's, per machine: one
/// machine set to one asks at its first failed check, and another keeps the
/// default.
#[test]
fn the_owner_sets_per_machine_how_many_failed_checks_reach_them() {
    let (_dir, vault) = open();
    let proof = owner_proof(&vault);
    let watched = EntityId::now();
    let other = EntityId::now();
    let change = SetSetting {
        item: Some(watched.to_hex()),
        ..SetSetting::vault_value("machines.readiness.escalate_after", json!(1))
    };
    let outcome = vault
        .set_setting(SettingCaller::Owner(&proof), change)
        .expect("the owner's setting");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "fewer is tighter, so the owner's change applies at once: {outcome:?}"
    );

    let (_, queued_now) = asked(
        vault
            .raise_machine_readiness_ask(&streak(watched, SINCE_MS, 1))
            .expect("the watched machine"),
    );
    assert!(queued_now);
    assert_eq!(
        vault
            .raise_machine_readiness_ask(&streak(other, SINCE_MS, 1))
            .expect("the other machine"),
        ReadinessEscalation::BelowThreshold { escalate_after: 3 }
    );
    assert_eq!(readiness_asks(&vault).len(), 1);
}
