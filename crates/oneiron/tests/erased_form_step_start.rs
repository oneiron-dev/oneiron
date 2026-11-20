//! FIX ERASED-FORM-UNFENCED-REPLAY-PUTS: a step's capture reads the run's
//! stored row again before it keeps the step's start. It had the side-row
//! wall read that row whole, the erase's own words in each part held in an
//! erased form too, and put back what the wall made of it; the start's body
//! then had the wall read the row again inside it. A value base custody
//! holds equal to one of those words took a handle inside the erased form:
//! the row no longer read erased, or the wall refused the copy and the
//! step kept no start.
//!
//! The capture now has the wall read the row, and the prefix in the start's
//! body, as a fenced put has it read a row: without the erase's fixed words
//! in each part held in its erased form. Everything else is still read and
//! still takes its handle.
//!
//! Each case makes a new agent that stays live and puts the record of a new
//! run of that agent making one call, which the row holds as written; then
//! custody takes a value, and a step of the run is captured with its start.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test erased_form_step_start`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::erased_request_identity::custody_handle;
use oneiron::test_doors::fenced_erase_form::{
    FencedCall, capture_start_after_custody_takes, start_spawn_intent, start_spawn_reads,
    stored_failure_reads, stored_spawn_intent, stored_spawn_reads,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The error an erased outcome holds.
const RESPONSE_ERASED: &str = "response_erased";

/// The state of a spawn's answer, and the cause of its ask's marker, once an
/// erase took the spawn's target.
const TARGET_ERASED: &str = "target_erased";

/// The intent key the fixture's spawn call holds.
const SPAWN_INTENT: &str = "fence fixture spawn";

/// A vault whose custody can take values, holding none yet.
fn custody_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// Whether `text` is custody record `record`'s handle, bare or in its
/// secret marker.
fn is_handle_of(vault: &Vault, record: EntityId, text: &str) -> TestResult<bool> {
    let handle = custody_handle(vault, record)?.ok_or("custody gives its record no handle")?;
    Ok(text == format!("[secret {handle}]") || text == handle)
}

/// Custody takes `target_erased`; a live run's spawn, whose host answered
/// it, so its row holds the erased ask marker too, is captured with its
/// start: the step keeps its start, and the row and the start's prefix both
/// still read erased. Red on the base: the wall placed the value's handle
/// over the answer's state, the masked copy no longer decoded as a spawn
/// answer, the wall refused it, and the step kept no start.
#[test]
fn a_live_spawns_erased_answer_keeps_its_step_start_when_custody_holds_its_state() -> TestResult {
    let (_directory, vault) = custody_vault()?;
    let [run, _] = capture_start_after_custody_takes(
        &vault,
        FencedCall::SpawnTargetErased,
        TARGET_ERASED.as_bytes(),
    )?;
    assert_eq!(
        start_spawn_reads(&vault, run)?,
        Some((true, true)),
        "the step keeps its start, whose prefix reads erased"
    );
    assert_eq!(stored_spawn_reads(&vault, run)?, (true, true));
    Ok(())
}

/// Custody takes `response_erased`; a live run's fold answer, which the
/// fold fence took when the run's row was put (its fold's source is gone),
/// is captured with its start: the row still reads the erased failure. (Its
/// prefix records withdrawn fold words, so the step keeps no start.) Red on
/// the base: the wall placed the value's handle over the failure's error,
/// and the capture put that copy back as the run's row.
#[test]
fn a_withdrawn_fold_answer_stays_erased_through_a_step_capture_when_custody_holds_its_error()
-> TestResult {
    let (_directory, vault) = custody_vault()?;
    let [run, _] = capture_start_after_custody_takes(
        &vault,
        FencedCall::WithdrawnFoldAnswer,
        RESPONSE_ERASED.as_bytes(),
    )?;
    assert_eq!(
        stored_failure_reads(&vault, run)?,
        Some((RESPONSE_ERASED.to_owned(), None))
    );
    Ok(())
}

/// Guard: the wall still reads what the erased form leaves. Custody takes
/// the intent key of a live run's spawn whose ask and answer are erased; the
/// capture puts the row back with that key as the handle custody gives it,
/// and the start's prefix holds the same handle, beside the erased ask and
/// answer. Green on the base and the head; red on a head that took a spawn's
/// whole request out of the wall's reading.
#[test]
fn a_held_spawn_intent_takes_its_handle_through_a_step_capture() -> TestResult {
    let (_directory, vault) = custody_vault()?;
    let [run, record] = capture_start_after_custody_takes(
        &vault,
        FencedCall::SpawnTargetErased,
        SPAWN_INTENT.as_bytes(),
    )?;
    let stored = stored_spawn_intent(&vault, run)?.ok_or("the stored spawn keeps its intent")?;
    assert!(
        is_handle_of(&vault, record, &stored)?,
        "the stored intent takes custody's handle: {stored}"
    );
    let started = start_spawn_intent(&vault, run)?
        .ok_or("the step keeps its start")?
        .ok_or("the start's spawn keeps its intent")?;
    assert_eq!(started, stored, "the start's prefix is the row as stored");
    assert_eq!(start_spawn_reads(&vault, run)?, Some((true, true)));
    assert_eq!(stored_spawn_reads(&vault, run)?, (true, true));
    Ok(())
}
