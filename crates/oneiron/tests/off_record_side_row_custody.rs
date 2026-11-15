//! FIX 2329 (OF-067 B; Engine RULING FIX-2329-ROOM-CUSTODY = C): an
//! off-record room holds no custody of its own, and no off-record byte
//! enters base, so the side-row wall refuses a code run's row there that
//! holds a fresh key. The refusal names that case and its remedy with
//! `gate.secret_scan.off_record_fresh_key`: put the value in vault custody
//! first, or run on record. A bare store, which also holds no custody door,
//! is no room, and its refusal names no room remedy.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test off_record_side_row_custody`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::error::GateError;
use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::off_record_side_row::{put_bare_store_replay_row, put_room_replay_row};
use oneiron::{EntityId, Error, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OFF_RECORD_FRESH_KEY: &str = "gate.secret_scan.off_record_fresh_key";

/// A replay row's bytes holding a GitHub token no custody record holds.
const FRESH_KEY_ROW: &[u8] = b"step output: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// The gate reason codes of a refused write, or why it is no gate refusal.
fn reason_codes(written: oneiron::Result<()>) -> TestResult<Vec<&'static str>> {
    match written {
        Ok(()) => Err("the row holding a fresh key was written".into()),
        Err(Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        })) => {
            assert_eq!(outcome, "deny");
            Ok(reason_codes)
        }
        Err(other) => Err(format!("refused, but not by the gate: {other:?}").into()),
    }
}

#[test]
fn a_fresh_key_in_a_rooms_side_row_names_the_off_record_remedy() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-side-row-fresh-key", OffRecordBackendClass::Local)?;

    // FIXTURE: the room's route takes a row that holds no secret.
    put_room_replay_row(&session, EntityId::now(), b"step output: 42\n")?;

    let codes = reason_codes(put_room_replay_row(
        &session,
        EntityId::now(),
        FRESH_KEY_ROW,
    ))?;
    assert_eq!(
        codes.first().copied(),
        Some("gate.secret_scan.detected"),
        "{codes:?}"
    );
    assert_eq!(
        codes.last().copied(),
        Some(OFF_RECORD_FRESH_KEY),
        "the room's refusal names the fresh key and its remedy: {codes:?}"
    );
    assert!(
        codes.len() >= 3,
        "the detector's own reason stays between them: {codes:?}"
    );
    Ok(())
}

#[test]
fn a_fresh_key_through_a_bare_store_names_no_room_remedy() -> TestResult {
    let (_directory, vault) = vault()?;

    let codes = reason_codes(put_bare_store_replay_row(
        &vault,
        EntityId::now(),
        FRESH_KEY_ROW,
    ))?;
    assert_eq!(
        codes.first().copied(),
        Some("gate.secret_scan.detected"),
        "{codes:?}"
    );
    assert!(
        !codes.contains(&OFF_RECORD_FRESH_KEY),
        "a bare store is no room: {codes:?}"
    );
    Ok(())
}
