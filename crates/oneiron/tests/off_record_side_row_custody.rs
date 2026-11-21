//! ROOM-LOCAL-CUSTODY (the lead's ruling of 21 Nov, "fingerprint only on
//! save"; it replaces FIX 2329's refusal): an off-record room keeps a fresh
//! key a code run's row there holds in its own custody, in memory only, and
//! the row holds its room handle. Nothing reaches base: no custody record,
//! no known-value fingerprint. The same value takes the same handle, and the
//! room's close wipes every value it kept. A value vault custody holds still
//! takes its vault handle in the room's row, as in a reply published there
//! (FIX 2329, FIX 6647). A bare store holds no custody door, and still
//! refuses a fresh key.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test off_record_side_row_custody`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::error::GateError;
use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::off_record_side_row::{
    RoomCustody, base_replay_row, put_bare_store_replay_row, put_room_replay_row,
    put_vault_replay_row, room_replay_row, vault_custody_record_count, vault_knows_value,
};
use oneiron::{EntityId, Error, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A GitHub token, in a shape the side-row wall reads as a secret.
const KEY: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A replay row's bytes holding [`KEY`], which no custody record holds.
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

/// The one handle `row` holds: `[secret …]` up to its bracket.
fn handle_in(row: &str) -> TestResult<&str> {
    let start = row.find("[secret ").ok_or("the row holds no handle")?;
    let len = row[start..].find(']').ok_or("the handle has no bracket")?;
    Ok(&row[start..=start + len])
}

#[test]
fn a_fresh_key_in_a_rooms_side_row_is_kept_in_the_rooms_own_custody() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-side-row-fresh-key", OffRecordBackendClass::Local)?;
    let room = RoomCustody::of(&session);

    let run = EntityId::now();
    put_room_replay_row(&session, run, FRESH_KEY_ROW)
        .map_err(|error| format!("the room refused a fresh key: {error:?}"))?;
    let stored = room_replay_row(&session, run)?.ok_or("the room keeps the row")?;
    let stored = String::from_utf8(stored)?;
    assert!(
        !stored.contains(KEY),
        "the room's row holds the handle, never the value: {stored}"
    );
    let handle = handle_in(&stored)?;
    assert!(
        handle.starts_with("[secret r"),
        "the value reads as a room handle: {stored}"
    );
    assert_eq!(
        room.secret(handle)?.as_deref(),
        Some(KEY.as_bytes()),
        "the room keeps the value under its handle"
    );

    // The same value written again in the room takes the same handle.
    let again = EntityId::now();
    put_room_replay_row(&session, again, FRESH_KEY_ROW)?;
    let stored_again = room_replay_row(&session, again)?.ok_or("the room keeps the row")?;
    assert_eq!(handle_in(&String::from_utf8(stored_again)?)?, handle);
    assert_eq!(room.count()?, 1, "one value, one room secret");

    // Nothing reached base.
    assert_eq!(
        vault_custody_record_count(&vault)?,
        0,
        "no base custody record"
    );
    assert!(
        !vault_knows_value(&vault, KEY.as_bytes())?,
        "base's known-value index learns no fingerprint before a save"
    );
    assert!(base_replay_row(&vault, run)?.is_none(), "no base row");
    Ok(())
}

#[test]
fn the_rooms_close_wipes_its_own_custody_and_leaves_nothing() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-side-row-close", OffRecordBackendClass::Local)?;
    let room = RoomCustody::of(&session);
    let run = EntityId::now();
    put_room_replay_row(&session, run, FRESH_KEY_ROW)
        .map_err(|error| format!("the room refused a fresh key: {error:?}"))?;
    let stored =
        String::from_utf8(room_replay_row(&session, run)?.ok_or("the room keeps the row")?)?;
    let handle = handle_in(&stored)?.to_owned();
    assert_eq!(room.count()?, 1, "FIXTURE: the room keeps the value");

    session.close()?;

    assert_eq!(room.count()?, 0, "the close wipes the room's custody");
    assert!(
        room.secret(&handle)?.is_none(),
        "the handle names nothing once the room is closed"
    );
    assert_eq!(
        vault_custody_record_count(&vault)?,
        0,
        "a closed unsaved room leaves no base custody record"
    );
    assert!(
        !vault_knows_value(&vault, KEY.as_bytes())?,
        "a closed unsaved room leaves no fingerprint"
    );
    assert!(
        base_replay_row(&vault, run)?.is_none(),
        "a closed unsaved room leaves no base row"
    );
    Ok(())
}

#[test]
fn a_fresh_key_through_a_bare_store_is_still_refused() -> TestResult {
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
    assert_eq!(vault_custody_record_count(&vault)?, 0);
    Ok(())
}

#[test]
fn a_value_in_vault_custody_first_takes_its_handle_in_a_rooms_side_row() -> TestResult {
    let (_directory, vault) = vault()?;
    assert!(
        std::str::from_utf8(FRESH_KEY_ROW)?.contains(KEY),
        "FIXTURE: the row holds the key"
    );

    // The value goes into vault custody first: an on-record row through the
    // vault, whose custody door mints its record and leaves its handle.
    put_vault_replay_row(&vault, EntityId::now(), FRESH_KEY_ROW)?;

    let session = vault
        .off_record_session_vault()
        .enter("sess-side-row-custody-first", OffRecordBackendClass::Local)?;
    let room = RoomCustody::of(&session);
    let run = EntityId::now();
    put_room_replay_row(&session, run, FRESH_KEY_ROW)
        .map_err(|error| format!("a value custody holds is refused in the room: {error:?}"))?;
    let stored = room_replay_row(&session, run)?.ok_or("the room keeps the row")?;
    let stored = String::from_utf8(stored)?;
    assert!(
        !stored.contains(KEY),
        "the room's row holds the handle, never the value: {stored}"
    );
    assert!(
        stored.contains("[secret sc"),
        "the value reads as its vault custody handle: {stored}"
    );
    assert_eq!(room.count()?, 0, "the room keeps no copy of a vault value");
    Ok(())
}

/// A second GitHub token, which only the fixture puts in vault custody.
const OTHER_KEY: &str = "ghp_zyxwvutsrqponmlkjihgfedcba9876543210";

/// A replay row's JSON document that holds [`KEY`] under a credential name
/// as byte values: no span of the door's text rules places it, so the
/// side-row wall seals the array whole (L7-30) and mints a record for it.
fn sealed_key_row() -> TestResult<Vec<u8>> {
    let token = format!("TOKEN={KEY}");
    Ok(serde_json::to_vec(&serde_json::json!({
        "step": "output",
        "notes": token.as_bytes(),
    }))?)
}

#[test]
fn a_sealed_fresh_key_in_a_rooms_side_row_names_the_off_record_remedy() -> TestResult {
    let (_directory, vault) = vault()?;
    // FIXTURE: vault custody holds another value, so the room's base holds
    // a known-value index and the wall seals in the room's row.
    put_vault_replay_row(
        &vault,
        EntityId::now(),
        format!("step output: {OTHER_KEY}\n").as_bytes(),
    )?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-side-row-sealed-key", OffRecordBackendClass::Local)?;

    let codes = reason_codes(put_room_replay_row(
        &session,
        EntityId::now(),
        &sealed_key_row()?,
    ))?;
    assert!(
        codes
            .first()
            .is_some_and(|code| code.starts_with("gate.secret_scan.")),
        "the scan's own reason comes first: {codes:?}"
    );
    assert_eq!(
        codes.last().copied(),
        Some(OFF_RECORD_FRESH_KEY),
        "a value the room's row would seal names the remedy too: {codes:?}"
    );
    Ok(())
}
