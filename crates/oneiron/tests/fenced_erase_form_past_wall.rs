//! FIX FENCE-ERASED-FORM-THROUGH-WALL: a put fence erases, in its writer,
//! the record of a run whose actor is gone, and the record then went
//! through the side-row wall whole. The wall read the erase's own words too:
//! an erased request's `state`, `cause` and `identity`, and an erased
//! outcome's `failed` tag and `response_erased` error. Its known-value
//! sweep reads map keys and any span of a text, so a value base custody
//! holds equal to one of those words took a handle inside the erased form:
//! the row landed no longer reading erased, or was refused.
//!
//! A fenced put now has the wall read every part of the record but the
//! erase's own, which land as the erase wrote them. A part the erase keeps
//! is still read, and still takes its handle.
//!
//! Each case registers one custody value, makes a new agent, deletes it,
//! and puts the record of a new run of that agent making one call, in the
//! vault or on a room's route.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fenced_erase_form_past_wall`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::erased_request_identity::custody_handle;
use oneiron::test_doors::fenced_erase_form::{
    FencedCall, put_call_after_delete, stored_call_reads,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The error an erased outcome holds, and the cause an erased request names.
const RESPONSE_ERASED: &str = "response_erased";

/// A vault whose custody holds `value` in one record: the vault and that
/// record.
fn vault_holding(value: &[u8]) -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let record = vault.register_test_secret("erase word", value, Vec::new(), 1)?;
    Ok((directory, vault, record))
}

/// What a fenced search call reads: its request erased, its outcome the
/// erase's failure.
fn erased_search() -> (bool, Option<String>) {
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
    assert_eq!(stored_call_reads(&vault, None, run)?, erased_search());
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
        erased_search()
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
    assert_eq!(stored_call_reads(&vault, None, run)?, erased_search());
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
    let handle = custody_handle(&vault, record)?.ok_or("custody gives its record no handle")?;
    let (request_erased, error) = stored_call_reads(&vault, None, run)?;
    assert!(request_erased, "the erase takes the note's request");
    let error = error.ok_or("the kept outcome is a failure")?;
    assert!(
        error == format!("[secret {handle}]") || error == handle,
        "the kept error takes custody's handle {handle}: {error}"
    );
    Ok(())
}
