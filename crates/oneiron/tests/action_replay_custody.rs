//! FIX REPLAY-COMPARE-KNOWN-MATCHER (Engine RULING FIX-2329-REPLAY-KNOWN =
//! C, then A, 15 Nov 22:05): the side-row wall gives a value base custody
//! holds its record's handle in a code run's replay row, a value no shape
//! rule places too (a passphrase). The call made again with that value meets
//! its row: the replay compare plans the offered request with the values base
//! custody holds, as the wall planned the row. Before, it planned the request
//! with none of them, so the identical call drifted from its own row ("code-run
//! replay request mismatch"). An agent's action made again under its
//! idempotency key is one such replay.
//!
//! FIX ACTION-REPLAY-FAILED-ANSWERS-TRAP (Engine ANSWER 20 Nov 09:10 = A): an
//! action made again under its idempotency key whose first making failed
//! answers that failure again, as the first making answered it. Before, it
//! answered the replay trap a guest program's replay raises ("replayed failed
//! self trap"), which reads as a corrupt artifact. A guest program's replay
//! keeps its trap. Red on the base: both action cases, whose fixture agent's
//! first making fails. Guard (green on both): the guest program's trap.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test action_replay_custody`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::code_run::actions::ActionDispatch;
use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, SelfFailedResult, SelfMemoryPutClaimCall,
};
use oneiron::test_doors::action_replay_custody::remember_twice;
use oneiron::{ClaimCandidate, ClaimSubject, EntityId, Error, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";

/// The replay cursor's refusal of a call that drifted from its row.
const REQUEST_MISMATCH: &str = "code-run replay request mismatch";

/// The trap the replay cursor raises for a row whose call failed
/// (`code_run::payload::replay_failed_trap_error`).
const REPLAYED_FAILED_TRAP: &str = "replayed failed self trap";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// Checks that the action's second making answered from the row its first
/// making recorded: as the first answered, a failed call's failure too; or,
/// for a first making a gate refused, with that refusal again. Never a drift
/// from the row.
///
/// The fixture's agent reads under a deny-all scope, so its claim's subject
/// does not resolve for it and the first making's call fails
/// (INVENTED_REFERENCE). The second making meets the row, which a drift never
/// does, and answers that failure again (FIX
/// ACTION-REPLAY-FAILED-ANSWERS-TRAP).
fn answered_from_row(answers: [oneiron::Result<ActionDispatch>; 2]) -> TestResult {
    let [first, second] = answers;
    let second = second.map_err(|error| format!("{error:?}"));
    if let Err(error) = &second {
        assert!(
            !error.contains(REQUEST_MISMATCH),
            "the action made again drifted from its own row: {error}"
        );
    }
    match first {
        Ok(first) => assert_eq!(
            second,
            Ok(first),
            "the action made again answers as its first making did"
        ),
        Err(refusal @ Error::Gate(_)) => assert_eq!(
            second,
            Err(format!("{refusal:?}")),
            "a first making the gate refused answers that refusal again"
        ),
        Err(other) => {
            return Err(format!("the action's first making did not run: {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn an_action_made_again_with_a_passphrase_custody_holds_answers_from_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;

    answered_from_row(remember_twice(&vault, HELD_PASSPHRASE, "held-passphrase")?)
}

/// The same action with a passphrase no custody record holds keeps it as
/// written in its row, and answers from that row.
#[test]
fn an_action_made_again_with_a_passphrase_no_custody_holds_answers_from_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;

    answered_from_row(remember_twice(
        &vault,
        UNHELD_PASSPHRASE,
        "unheld-passphrase",
    )?)
}

/// Guard: a guest program's replay keeps its trap. The replay cursor answers
/// a row whose call failed with the replay trap, on the base and the head;
/// only an action made again under its key answers the failure itself.
#[test]
fn a_guest_programs_replay_of_a_failed_call_keeps_its_trap() -> TestResult {
    let agent = EntityId::now();
    let note = ClaimCandidate::new(
        "note.text",
        ClaimSubject::Entity(agent),
        rmpv::Value::from("plain words"),
        1.0,
    );
    let call = SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        agent,
        note,
        TimeRange { start: 1, end: 1 },
        1,
    ));
    let failed = SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: call.effect(),
        error: "INVENTED_REFERENCE".to_owned(),
        code: None,
        disk_floor: None,
    });
    let mut record = CodeRunReplayRecord::new(EntityId::now(), CodeRunDeterminism::new(1, [7; 32]));
    record
        .bridge_calls
        .push(CodeRunBridgeCall::record(0, &call, &failed, 1, 1)?);
    let answer = record
        .replay_cursor()
        .dispatch(call)
        .map_err(|error| format!("{error:?}"));
    assert!(
        answer
            .as_ref()
            .is_err_and(|error| error.contains(REPLAYED_FAILED_TRAP)),
        "a guest program's replay answers a failed call with its trap: {answer:?}"
    );
    Ok(())
}
