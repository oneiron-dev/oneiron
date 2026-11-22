//! A turn program's outbound step settles at the intent ledger's own time,
//! Unix seconds, on both paths that settle one: a send its provider
//! acknowledges, and a send its provider's own record reads back as
//! delivered (FIX TURN-PROGRAM-OUTBOUND-STEP-TIME-UNTESTED). Review round 1
//! of #10289 found both settle sites dividing that time by 1,000 a second
//! time, by reading alone; these tests pin it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_outbound_step_time`.

#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::{
    ProgramRunRequest, ProgramStepIssueView, ProgramStepState, program_run,
};
use oneiron::test_doors::held_program::{
    ProgramCallPass, complete_program_call_by_read_back_at, plant_held_turn_program_for_test,
    send_program_call_acked_at,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The call sequence of the one call each test sends.
const CALL_SEQ: u64 = 1;

/// A vault with a planted held program try whose waking actor is the
/// vault's owner: the vault, the owner and the try's hex.
fn planted_program()
-> Result<(tempfile::TempDir, Vault, EntityId, String), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let (attempt, _reason, _parked_at) =
        plant_held_turn_program_for_test(&vault, owner, EdgeActorClass::Human)?;
    Ok((dir, vault, owner, attempt))
}

/// The state and time of the outbound step `pass`'s call settled, as the
/// program's waking actor reads its run.
fn outbound_step(
    vault: &Vault,
    owner: EntityId,
    attempt: &str,
    pass: &ProgramCallPass,
) -> Result<(ProgramStepState, u64), Box<dyn std::error::Error>> {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let run = program_run(
        &memory,
        &ProgramRunRequest {
            root: attempt.to_owned(),
            cursor: None,
            limit: None,
        },
    )?
    .ok_or("the waking actor reads the planted program's run")?;
    let step = run
        .steps
        .iter()
        .find(|step| {
            matches!(
                &step.issue,
                ProgramStepIssueView::Outbound { intent, call_seq }
                    if *intent == pass.intent && *call_seq == CALL_SEQ
            )
        })
        .ok_or("the call settled an outbound step of the program")?;
    Ok((step.state, step.at))
}

#[test]
fn acknowledged_program_send_settles_its_step_at_the_ledger_second() -> TestResult {
    let (_dir, vault, owner, attempt) = planted_program()?;
    let sent_at = vault.now_recorded_at() + 7;

    let pass = send_program_call_acked_at(&vault, &attempt, CALL_SEQ, sent_at);
    assert_eq!(
        pass.sends, 1,
        "the resumed call is sent once and acknowledged"
    );

    let (state, at) = outbound_step(&vault, owner, &attempt, &pass)?;
    assert!(
        matches!(state, ProgramStepState::Settled),
        "the acknowledged send settles its step: {state:?}"
    );
    assert_eq!(
        at, sent_at,
        "the step settles at the ledger's Unix second, not a thousandth of it"
    );
    Ok(())
}

#[test]
fn read_back_program_send_settles_its_step_at_the_ledger_second() -> TestResult {
    let (_dir, vault, owner, attempt) = planted_program()?;
    let read_back_at = vault.now_recorded_at() + 7;

    let pass = complete_program_call_by_read_back_at(&vault, &attempt, CALL_SEQ, read_back_at);
    assert_eq!(
        pass.sends, 0,
        "a call read back as delivered is never sent again"
    );

    let (state, at) = outbound_step(&vault, owner, &attempt, &pass)?;
    assert!(
        matches!(state, ProgramStepState::Settled),
        "the read-back delivery settles its step: {state:?}"
    );
    assert_eq!(
        at, read_back_at,
        "the step settles at the ledger's Unix second, not a thousandth of it"
    );
    Ok(())
}
