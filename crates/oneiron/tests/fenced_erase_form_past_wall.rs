//! FIX FENCE-ERASED-FORM-THROUGH-WALL: a put fence erases, in its writer,
//! the record of a run whose actor is gone, and the record then went
//! through the side-row wall whole. The wall read the erase's own words too:
//! an erased request's `state`, `cause` and `identity`, and an erased
//! outcome's `failed` tag and `response_erased` error. Its known-value
//! sweep reads map keys and any span of a text, so a value base custody
//! holds equal to one of those words took a handle inside the erased form:
//! the row landed no longer reading erased, or was refused.
//!
//! A fenced put now has the wall read all of the record but the erase's
//! fixed words in each part it holds in its exact erased form, whoever
//! wrote that part: the fence's erase, the fold fence or the spawn fence
//! before it, a spawn's host, or an earlier put. Everything else is still
//! read and still takes its handle: an outcome the erase keeps, a failure
//! naming the erase's cause beside a code of its own, the identity an
//! erased request keeps, and every output preview, one reading the erased
//! preview's text too.
//!
//! Each case registers a custody value, makes a new agent, deletes it, and
//! puts the record of a new run of that agent making one call, in the
//! vault or on a room's route; the held cases put the record once while
//! the agent is live, before custody takes the value, and again after; the
//! live cases keep the agent.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fenced_erase_form_past_wall`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::erased_request_identity::custody_handle;
use oneiron::test_doors::fenced_erase_form::{
    FencedCall, HELD_CODE, HELD_NAME, put_call_after_delete, put_call_again_after_delete,
    put_call_live, put_output_live, stored_call_reads, stored_failure_reads, stored_preview,
    stored_request_custody_names, stored_spawn_reads,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_verb_wire::code_run::storage::replay_bodies::CODE_RUN_OUTPUT_PREVIEW_ERASED;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The error an erased outcome holds, and the cause an erased request names.
const RESPONSE_ERASED: &str = "response_erased";

/// The state of a spawn's answer, and the cause of its ask's marker, once an
/// erase took the spawn's target.
const TARGET_ERASED: &str = "target_erased";

/// A vault whose custody can take values, holding none yet.
fn custody_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// A vault whose custody holds `value` in one record: the vault and that
/// record.
fn vault_holding(value: &[u8]) -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let (directory, vault) = custody_vault()?;
    let record = vault.register_test_secret("erase word", value, Vec::new(), 1)?;
    Ok((directory, vault, record))
}

/// Whether `text` is custody record `record`'s handle, bare or in its
/// secret marker.
fn is_handle_of(vault: &Vault, record: EntityId, text: &str) -> TestResult<bool> {
    let handle = custody_handle(vault, record)?.ok_or("custody gives its record no handle")?;
    Ok(text == format!("[secret {handle}]") || text == handle)
}

/// What a fenced call whose reply an erase took reads: its request erased,
/// its outcome the erase's failure.
fn erased_call() -> (bool, Option<String>) {
    (true, Some(RESPONSE_ERASED.to_owned()))
}

/// Custody holds `response_erased`; the vault's fenced search call still
/// reads erased. Red on the base: the wall placed the value's handle over
/// the request's cause and the outcome's error, so the stored request no
/// longer read erased and its outcome failed with the handle.
#[test]
fn a_vault_fenced_call_reads_erased_when_custody_holds_the_erase_cause() -> TestResult {
    let (_directory, vault, _) = vault_holding(RESPONSE_ERASED.as_bytes())?;
    let [_, run] = put_call_after_delete(&vault, None, FencedCall::Search)?;
    assert_eq!(stored_call_reads(&vault, None, run)?, erased_call());
    Ok(())
}

/// As above, on a room's route: the room's fence erases the record in the
/// overlay's writer. Red on the base, as above.
#[test]
fn a_rooms_fenced_call_reads_erased_when_custody_holds_the_erase_cause() -> TestResult {
    let (_directory, vault, _) = vault_holding(RESPONSE_ERASED.as_bytes())?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-fenced-erase-cause", OffRecordBackendClass::Local)?;
    let [_, run] = put_call_after_delete(&vault, Some(&session), FencedCall::Search)?;
    assert_eq!(
        stored_call_reads(&vault, Some(&session), run)?,
        erased_call()
    );
    Ok(())
}

/// Custody holds `failed`, the erased outcome's tag; the fenced put lands
/// and reads erased. Red on the base: the wall placed the value's handle
/// over the tag, the masked copy's outcome no longer read as a dispatch
/// outcome, and the wall refused the put.
#[test]
fn a_fenced_call_lands_when_custody_holds_the_erased_outcome_tag() -> TestResult {
    let (_directory, vault, _) = vault_holding(b"failed")?;
    let [_, run] = put_call_after_delete(&vault, None, FencedCall::Search)?;
    assert_eq!(stored_call_reads(&vault, None, run)?, erased_call());
    Ok(())
}

/// Custody holds `failed`; a fold answer whose fold's source is gone takes
/// the erased failure from the fold fence, before the erase, which keeps a
/// failure; the fenced put lands and the call reads erased. Red on the
/// base, as above, and on a head that took out only the parts the fence's
/// own erase wrote (blind review round 1 of #9715).
#[test]
fn a_fold_fenced_answer_lands_when_custody_holds_the_erased_outcome_tag() -> TestResult {
    let (_directory, vault, _) = vault_holding(b"failed")?;
    let [_, run] = put_call_after_delete(&vault, None, FencedCall::WithdrawnFoldAnswer)?;
    assert_eq!(stored_call_reads(&vault, None, run)?, erased_call());
    Ok(())
}

/// Guard: the wall still reads what the erase keeps. A failed note write
/// keeps its outcome past the erase; custody holds that outcome's error, so
/// the stored error is the handle custody gives it, and the request is
/// erased. Green on the base and the head.
#[test]
fn a_fenced_calls_kept_outcome_still_takes_its_handle() -> TestResult {
    let (_directory, vault, record) = vault_holding(b"note not written")?;
    let [_, run] = put_call_after_delete(&vault, None, FencedCall::FailedNote)?;
    let (request_erased, error) = stored_call_reads(&vault, None, run)?;
    assert!(request_erased, "the erase takes the note's request");
    let error = error.ok_or("the kept outcome is a failure")?;
    assert!(
        is_handle_of(&vault, record, &error)?,
        "the kept error takes custody's handle: {error}"
    );
    Ok(())
}

/// Guard: a failure naming the erase's cause beside a code of its own is no
/// failure an erase writes, so the wall reads all of it, the stored row's
/// equal copy too. The row holds it as written; custody then takes the
/// code, the agent is deleted and the same record put again: the stored
/// code is the handle custody gives it. Green on the base; red on a head
/// that took a stored row's equal outcome out whole (blind review round 1
/// of #9715).
#[test]
fn a_held_failure_naming_the_erase_cause_keeps_its_code_under_the_wall() -> TestResult {
    let (_directory, vault) = custody_vault()?;
    let [run, record] = put_call_again_after_delete(
        &vault,
        FencedCall::FailedNoteNamingErasure,
        HELD_CODE.as_bytes(),
    )?;
    let (error, code) = stored_failure_reads(&vault, run)?.ok_or("the outcome is a failure")?;
    assert_eq!(error, RESPONSE_ERASED);
    let code = code.ok_or("the failure keeps its code")?;
    assert!(
        is_handle_of(&vault, record, &code)?,
        "the held code takes custody's handle: {code}"
    );
    Ok(())
}

/// Guard: the identity an erased request keeps is read by the wall, the
/// stored row's equal copy too. The row holds a request in the erased form
/// whose identity names a custody record as written; custody then takes
/// that name, the agent is deleted and the same record put again: the
/// stored request is still erased, and its identity holds the handle
/// custody gives the name. Green on the base; red on a head that took a
/// stored row's equal request out whole.
#[test]
fn a_held_erased_requests_identity_stays_under_the_wall() -> TestResult {
    let (_directory, vault) = custody_vault()?;
    let [run, record] =
        put_call_again_after_delete(&vault, FencedCall::SearchErasedNaming, HELD_NAME.as_bytes())?;
    let names = stored_request_custody_names(&vault, run)?.ok_or("the stored request is erased")?;
    let [name] = names.as_slice() else {
        return Err(format!("the identity names one record: {names:?}").into());
    };
    assert!(
        is_handle_of(&vault, record, name)?,
        "the held name takes custody's handle: {name}"
    );
    Ok(())
}

/// Custody holds `target_erased`; a spawn whose host answered it, so its
/// row holds the erased ask marker too, is put after its run's agent is
/// deleted: the put fence erases the request, which keeps the marker, and
/// keeps the typed answer. The put lands and both read erased. Red on the
/// round-2 head 59986842b22: the wall placed the value's handle over the
/// answer's `state`, the masked copy no longer decoded as a spawn answer,
/// and the wall refused the put (blind review round 2 of #9715).
#[test]
fn a_fenced_spawns_erased_answer_lands_when_custody_holds_its_state() -> TestResult {
    let (_directory, vault, _) = vault_holding(TARGET_ERASED.as_bytes())?;
    let [_, run] = put_call_after_delete(&vault, None, FencedCall::SpawnTargetErased)?;
    assert!(
        stored_call_reads(&vault, None, run)?.0,
        "the erase takes the spawn's request"
    );
    assert_eq!(stored_spawn_reads(&vault, run)?, (true, true));
    Ok(())
}

/// As above, with the run's agent live: the spawn's request keeps its
/// fields beside the erased ask marker, and the put lands with the marker
/// and the typed answer as written. Red on the round-2 head 59986842b22:
/// no part read as erased, so the wall read all of the record and refused
/// it, as above.
#[test]
fn a_live_spawns_erased_ask_and_answer_land_when_custody_holds_their_cause() -> TestResult {
    let (_directory, vault, _) = vault_holding(TARGET_ERASED.as_bytes())?;
    let run = put_call_live(&vault, FencedCall::SpawnTargetErased)?;
    assert!(
        !stored_call_reads(&vault, None, run)?.0,
        "a live run's request keeps its fields"
    );
    assert_eq!(stored_spawn_reads(&vault, run)?, (true, true));
    Ok(())
}

/// Custody holds the erased preview's text; a live run writes an output
/// whose body is that text, so its preview reads it, and no fence erases
/// it: the stored preview is the handle custody gives it. Red on the
/// round-2 head 59986842b22: the projection took every preview reading the
/// erased text out of the wall, and the row held the value as written
/// (blind review round 2 of #9715).
#[test]
fn a_live_preview_reading_the_erased_text_takes_custodys_handle() -> TestResult {
    let (_directory, vault, record) = vault_holding(CODE_RUN_OUTPUT_PREVIEW_ERASED.as_bytes())?;
    let run = put_output_live(&vault, CODE_RUN_OUTPUT_PREVIEW_ERASED.as_bytes())?;
    let preview = stored_preview(&vault, run)?.ok_or("the run holds its output")?;
    assert!(
        is_handle_of(&vault, record, &preview)?,
        "the preview takes custody's handle: {preview}"
    );
    Ok(())
}
