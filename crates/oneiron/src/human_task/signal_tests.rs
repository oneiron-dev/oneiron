//! cfg(test) C9 wait/signal, idempotency, interleave and reopen tests.

use super::followup_tests::*;
use super::*;

use crate::config::VaultConfig;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::llm::{TrapRef, consume_trap_signal};

// ── C9 wait binding + response signal ───────────────────────────────────

/// A response from the wrong actor, for a different task, or against a
/// stale step hash signals NOTHING — and leaves the step parked.
#[test]
fn wrong_responder_task_or_step_hash_never_signals() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let (attempt_id, _trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let other_person = crate::test_util::entity(0x6D);
    put_person(&fixture.vault, other_person);

    let wrong_responder = HumanResponseSignal {
        responder_ref: other_person,
        ..response(&fixture, task_ref, 0x6E)
    };
    let wrong_task = HumanResponseSignal {
        task_ref: crate::test_util::entity(0x6F),
        ..response(&fixture, task_ref, 0x7A)
    };
    let stale_step = HumanTaskWaitBinding {
        step_hash: [0x99; 32],
        ..binding
    };

    for (case, error) in [
        (
            "wrong responder",
            signal_human_response(&fixture.vault, &binding, fixture.person, &wrong_responder),
        ),
        (
            "wrong task",
            signal_human_response(&fixture.vault, &binding, fixture.person, &wrong_task),
        ),
        (
            "stale step hash",
            signal_human_response(
                &fixture.vault,
                &stale_step,
                fixture.person,
                &response(&fixture, task_ref, 0x8A),
            ),
        ),
    ] {
        assert!(
            matches!(error, Err(HumanTaskError::UnboundResponse)),
            "{case} must be refused"
        );
    }
    assert!(
        runner
            .parked_attempt(attempt_id)
            .expect("read parked row")
            .is_some(),
        "no refused response may resume the branch"
    );
}

#[test]
fn forged_caller_identity_cannot_signal_a_bound_human_wait() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let (_, _, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
    let intruder = crate::test_util::entity(0x91);
    put_person(&fixture.vault, intruder);
    let signal = response(&fixture, task_ref, 0x92);

    let error = signal_human_response(&fixture.vault, &binding, intruder, &signal)
        .expect_err("a forged caller token must not signal");

    assert!(matches!(error, HumanTaskError::UnboundResponse));
    assert!(
        wait_signal_marker(&fixture.vault, binding.trap_claim_id)
            .expect("read signal marker")
            .is_none(),
        "the payload's responder field cannot substitute for verified caller identity"
    );
}

#[test]
fn inactive_persisted_binding_cannot_signal() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let (_, _, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
    assert!(release_human_wait(&fixture.vault, task_ref).expect("release wait"));
    let stored = stored_human_wait_binding(&fixture.vault, task_ref)
        .expect("read retired binding")
        .expect("release persists a tombstone");

    assert!(!stored.is_active);
    assert!(matches!(
        signal_human_response(
            &fixture.vault,
            &binding,
            fixture.person,
            &response(&fixture, task_ref, 0x93),
        ),
        Err(HumanTaskError::UnboundResponse)
    ));
}

/// Re-delivery of the SAME response is idempotent, and the trap consumes
/// once: the second consume finds no sent signal to absorb.
#[test]
fn duplicate_delivery_of_one_response_resumes_once() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
    let runner = DreamerRunnerStore::new(&fixture.vault);
    let signal = response(&fixture, task_ref, 0x8B);

    let first =
        signal_human_response(&fixture.vault, &binding, fixture.person, &signal).expect("first");
    let replay =
        signal_human_response(&fixture.vault, &binding, fixture.person, &signal).expect("replay");

    assert_eq!(first, replay, "a re-delivered response returns its signal");
    assert_eq!(
        consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 11).expect("consume"),
        attempt_id
    );
    assert!(consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 12).is_err());
    assert!(
        runner
            .parked_attempt(attempt_id)
            .expect("read parked row")
            .is_none()
    );
}

#[test]
fn signal_refuses_a_binding_over_a_persisted_non_human_trap() {
    let fixture = HumanFixture::open();
    let task_ref = fixture.create_human_task();
    let consent_trap = open_test_trap(&fixture, DreamerTrapKind::Consent, STEP_HASH);
    let forged_human_ref = TrapRef {
        kind: DreamerTrapKind::HumanResponse,
        ..consent_trap
    };
    let binding = bind_human_wait(&fixture.vault, task_ref, fixture.person, &forged_human_ref)
        .expect("the forged handle passes the caller-side kind check");

    let error = signal_human_response(
        &fixture.vault,
        &binding,
        fixture.person,
        &response(&fixture, task_ref, 0x70),
    )
    .expect_err("the persisted consent trap must refuse a human response");

    assert!(matches!(error, HumanTaskError::UnboundResponse));
}

/// Both durable halves survive a REAL restart — the vault is dropped and
/// reopened, so only what LMDB persisted can carry them across — and the
/// answer that arrives afterwards resumes the ORIGINAL branch.
#[test]
fn parked_wait_and_cursor_survive_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (task_ref, person, attempt_id, trap, binding) = {
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let (owner, person) = seed_human_vault(&vault, true);
        let fixture = HumanFixture {
            _dir: tempfile::tempdir().expect("placeholder tempdir"),
            vault,
            owner,
            person,
        };
        let task_ref = fixture.create_human_task();
        let (attempt_id, trap, binding) = park_on_human(&fixture, task_ref, STEP_HASH);
        (task_ref, person, attempt_id, trap, binding)
    };

    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen vault");
    let runner = DreamerRunnerStore::new(&vault);
    let cursor = human_followup_record(&vault, task_ref)
        .expect("read cursor")
        .expect("the cursor survives reopen");

    assert_eq!(cursor.stage, HumanFollowupStage::Tracking);
    assert_eq!(
        human_wait_binding(&vault, task_ref).expect("read binding"),
        Some(binding)
    );
    assert!(
        runner
            .parked_attempt(attempt_id)
            .expect("read parked row")
            .is_some()
    );

    signal_human_response(
        &vault,
        &binding,
        person,
        &HumanResponseSignal {
            task_ref,
            responder_ref: person,
            surface_event_ref: crate::test_util::entity(0x8E),
            occurred_at: NOW + 30,
        },
    )
    .expect("the person answers after the restart");

    assert_eq!(
        consume_trap_signal(&vault, &runner, &trap, NOW + 31).expect("consume"),
        attempt_id
    );
    assert!(release_human_wait(&vault, task_ref).expect("release"));
    assert!(
        human_wait_binding(&vault, task_ref)
            .expect("read binding")
            .is_none()
    );
}
