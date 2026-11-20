//! ROOM-LOCAL-CUSTODY (the lead's ruling of 21 Nov): a room handle works
//! only in its room. A run bound to the room reads a row it holds against
//! the call it makes again with the values base custody holds and the
//! values the room keeps in its own custody, so a room handle meets the
//! value the room keeps under it, and no other value of its shape. Outside
//! the room it names nothing: a base door refuses it at its parse, base
//! custody holds no record of it, and another room reads the same handle
//! text as its own, never as this room's value.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_custody_handle_scope`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::OffRecordBackendClass;
use oneiron::secret_custody::parse_secret_handle;
use oneiron::test_doors::erased_request_identity::{
    put_room_record_again, room_stored_call_erased, room_stored_call_holds, room_stored_call_is,
    room_stored_fields_call_is, store_fields_call_in_room, store_note_call_in_room,
};
use oneiron::test_doors::off_record_side_row::{
    RoomCustody, base_replay_row, put_room_replay_row, release_scan_whole_and_streamed,
    room_replay_row, vault_custody_record_count, vault_knows_value,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A key of a shape the wall reads, which no custody record holds.
const KEY: &str = "AKIA1234567890123456";
/// Another key of the same shape.
const OTHER_KEY: &str = "AKIA1234567890123457";
/// A third key of the same shape.
const THIRD_KEY: &str = "AKIA1234567890123458";
/// A password, which the wall lifts whole from a `password` field.
const PASSWORD: &str = "cobalt-otter-871!";
/// Another password.
const OTHER_PASSWORD: &str = "cobalt-otter-872!";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

fn words(value: &str) -> String {
    format!("archive with {value}")
}

/// The room handle the room's replay row of `run` holds, as written.
fn room_handle(row: &[u8]) -> TestResult<String> {
    let row = std::str::from_utf8(row)?;
    let start = row
        .find("[secret r")
        .ok_or("the row holds no room handle")?;
    let len = row[start..].find(']').ok_or("the handle has no bracket")?;
    Ok(row[start..=start + len].to_owned())
}

#[test]
fn a_room_handle_meets_its_own_value_when_the_rooms_run_calls_again() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-handle-replay", OffRecordBackendClass::Local)?;
    let call = store_note_call_in_room(&vault, &session, &words(KEY), false)?;
    assert!(
        room_stored_call_holds(&session, call[1], "[secret r")?,
        "FIXTURE: the room stores the call with a room handle"
    );
    assert!(
        !room_stored_call_holds(&session, call[1], KEY)?,
        "FIXTURE: the room's row holds no key"
    );

    assert!(
        room_stored_call_is(&vault, &session, call, &words(KEY), true)?,
        "the call made again with the key the room keeps meets its row"
    );
    assert!(
        !room_stored_call_is(&vault, &session, call, &words(OTHER_KEY), true)?,
        "another key of the same shape is another call"
    );
    assert_eq!(vault_custody_record_count(&vault)?, 0);
    assert!(
        !vault_knows_value(&vault, KEY.as_bytes())?,
        "the room's compare teaches base's known-value index nothing"
    );
    Ok(())
}

#[test]
fn a_base_door_refuses_a_room_handle() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-handle-base", OffRecordBackendClass::Local)?;
    let run = EntityId::now();
    put_room_replay_row(&session, run, format!("step output: {KEY}\n").as_bytes())?;
    let handle = room_handle(&room_replay_row(&session, run)?.ok_or("the room keeps the row")?)?;
    assert!(
        parse_secret_handle(&handle).is_err(),
        "a base door refuses {handle} at its parse"
    );
    let bare = handle
        .strip_prefix("[secret ")
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("a bracketed handle")?;
    assert!(
        parse_secret_handle(bare).is_err(),
        "a base door refuses {bare} at its parse"
    );
    assert_eq!(
        vault_custody_record_count(&vault)?,
        0,
        "base custody holds no record a room handle could name"
    );
    Ok(())
}

#[test]
fn a_room_handle_names_nothing_of_its_room_in_another_room() -> TestResult {
    let (_directory, vault) = vault()?;
    let first = vault
        .off_record_session_vault()
        .enter("sess-room-handle-first", OffRecordBackendClass::Local)?;
    let second = vault
        .off_record_session_vault()
        .enter("sess-room-handle-second", OffRecordBackendClass::Local)?;
    let run = EntityId::now();
    put_room_replay_row(&first, run, format!("step output: {KEY}\n").as_bytes())?;
    let handle = room_handle(&room_replay_row(&first, run)?.ok_or("the room keeps the row")?)?;
    assert_eq!(
        RoomCustody::of(&first).secret(&handle)?.as_deref(),
        Some(KEY.as_bytes()),
        "FIXTURE: the first room keeps the key"
    );

    assert!(
        RoomCustody::of(&second).secret(&handle)?.is_none(),
        "{handle} names nothing in a room that keeps nothing"
    );
    assert!(
        room_replay_row(&second, run)?.is_none(),
        "the second room reads none of the first room's rows"
    );
    let other = EntityId::now();
    put_room_replay_row(
        &second,
        other,
        format!("step output: {OTHER_KEY}\n").as_bytes(),
    )?;
    let second_handle =
        room_handle(&room_replay_row(&second, other)?.ok_or("the room keeps the row")?)?;
    assert_eq!(
        RoomCustody::of(&second).secret(&second_handle)?.as_deref(),
        Some(OTHER_KEY.as_bytes()),
        "the second room keeps its own key under its own handle"
    );
    assert_ne!(
        RoomCustody::of(&second).secret(&handle)?.as_deref(),
        Some(KEY.as_bytes()),
        "no handle text reads the first room's key in the second room"
    );
    Ok(())
}

/// REVIEW-10003 (P1 text.rs:257): a field the wall lifts whole holds the
/// bare room handle. The room's run calling again with the password the room
/// keeps meets its row; another password does not.
#[test]
fn a_whole_field_room_handle_meets_its_own_value_when_the_rooms_run_calls_again() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-handle-field", OffRecordBackendClass::Local)?;
    let call = store_fields_call_in_room(&vault, &session, &[("password", PASSWORD)])?;
    assert!(
        !room_stored_call_holds(&session, call[1], PASSWORD)?,
        "FIXTURE: the wall lifts the field whole"
    );

    assert!(
        room_stored_fields_call_is(&session, call, &[("password", PASSWORD)], true)?,
        "the call made again with the password the room keeps meets its row"
    );
    assert!(
        !room_stored_fields_call_is(&session, call, &[("password", OTHER_PASSWORD)], true)?,
        "another password is another call"
    );
    Ok(())
}

/// REVIEW-10003 (P1 room_secrets.rs:117): two rooms never spell a handle
/// alike, so a handle the first room gave, offered in a call of the second
/// room, meets none of the second room's rows.
#[test]
fn a_handle_another_room_gave_meets_no_call_of_this_room() -> TestResult {
    let (_directory, vault) = vault()?;
    let first = vault
        .off_record_session_vault()
        .enter("sess-room-handle-gave", OffRecordBackendClass::Local)?;
    let second = vault
        .off_record_session_vault()
        .enter("sess-room-handle-offered", OffRecordBackendClass::Local)?;
    let run = EntityId::now();
    put_room_replay_row(&first, run, format!("step output: {KEY}\n").as_bytes())?;
    let handle = room_handle(&room_replay_row(&first, run)?.ok_or("the room keeps the row")?)?;
    let call = store_note_call_in_room(&vault, &second, &words(OTHER_KEY), false)?;
    assert!(
        room_stored_call_is(&vault, &second, call, &words(OTHER_KEY), true)?,
        "FIXTURE: the second room's run meets its own row"
    );

    assert!(
        !room_stored_call_holds(&second, call[1], &handle)?,
        "the second room's row spells no handle the first room gave ({handle})"
    );
    assert!(
        !room_stored_call_is(&vault, &second, call, &words(&handle), true)?,
        "{handle}, the first room's, offered in the second room meets nothing"
    );
    Ok(())
}

/// REVIEW-10003 (P1 overlay_erase.rs:208): a room's erase of a gone actor's
/// call, in its put fence and in its sweep, keeps the identity of the room
/// value the request names: the call made again with that key meets the
/// erased row, and another key of the same shape does not.
#[test]
fn a_rooms_erase_keeps_the_identity_of_the_room_value_a_request_names() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-handle-erase", OffRecordBackendClass::Local)?;
    let fenced = store_note_call_in_room(&vault, &session, &words(KEY), true)?;
    let swept = store_note_call_in_room(&vault, &session, &words(KEY), false)?;
    vault.delete_entity(&swept[0])?;
    for (call, how) in [(fenced, "put fence"), (swept, "sweep")] {
        assert!(
            room_stored_call_erased(&session, call[1])?,
            "FIXTURE: the room's {how} erased the call"
        );
        assert!(
            room_stored_call_is(&vault, &session, call, &words(KEY), true)?,
            "the call made again with the key meets the row its {how} erased"
        );
        assert!(
            !room_stored_call_is(&vault, &session, call, &words(OTHER_KEY), true)?,
            "another key of the same shape is another call after the {how}"
        );
    }
    Ok(())
}

/// REVIEW-10003 round 2 (P1 routing/replay.rs:215): a run the room began
/// holds a room handle in its record. Once the stretch is on record, its
/// next append would write that record to base, where no custody holds the
/// value the handle names and the room's close leaves the record unreplayable.
/// The append is refused: nothing lands in base and the room keeps its row.
#[test]
fn a_record_holding_a_room_handle_does_not_move_to_base_on_record() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-handle-on-record", OffRecordBackendClass::Local)?;
    let call = store_note_call_in_room(&vault, &session, &words(KEY), false)?;
    assert!(
        room_stored_call_holds(&session, call[1], "[secret r")?,
        "FIXTURE: the room stores the call with a room handle"
    );
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    session.flip_on_record_as(&owner)?;

    assert!(
        put_room_record_again(&session, call).is_err(),
        "an on-record append of a record holding a room handle is refused"
    );
    assert!(
        base_replay_row(&vault, call[1])?.is_none(),
        "base holds no record of the room's run"
    );
    assert!(
        room_stored_call_holds(&session, call[1], "[secret r")?,
        "the room keeps its row"
    );
    Ok(())
}

/// REVIEW-10003 round 2 (P1 side_row.rs:765): a compare with no custody in
/// reach (a record read in memory) reads a room handle as written, so a row
/// holding one room's handle never meets a call offering another room's.
#[test]
fn a_compare_with_no_custody_reads_a_room_handle_as_written() -> TestResult {
    let (_directory, vault) = vault()?;
    let first = vault.off_record_session_vault().enter(
        "sess-room-handle-memory-first",
        OffRecordBackendClass::Local,
    )?;
    let second = vault.off_record_session_vault().enter(
        "sess-room-handle-memory-second",
        OffRecordBackendClass::Local,
    )?;
    let call = store_note_call_in_room(&vault, &first, &words(KEY), false)?;
    let run = EntityId::now();
    put_room_replay_row(
        &second,
        run,
        format!("step output: {OTHER_KEY}\n").as_bytes(),
    )?;
    let other = room_handle(&room_replay_row(&second, run)?.ok_or("the room keeps the row")?)?;
    assert!(
        room_stored_call_holds(&first, call[1], "[secret r")?
            && !room_stored_call_holds(&first, call[1], &other)?,
        "FIXTURE: the first room's row holds its own handle, not {other}"
    );

    assert!(
        !room_stored_call_is(&vault, &first, call, &words(&other), false)?,
        "{other}, another room's handle, meets no row of this room in a compare with no custody"
    );
    Ok(())
}

/// The budget of the room in [`a_refused_room_write_keeps_no_secret`].
const SMALL_ROOM_BUDGET: usize = 64 * 1024;

/// REVIEW-10003 round 2 (P1 room_secrets.rs:138): a room write its budget
/// refuses keeps none of the secrets the wall lifted from it, however often
/// it is tried with a fresh one; a write that fits keeps its own.
#[test]
fn a_refused_room_write_keeps_no_secret() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault.off_record_session_vault().enter_with_budget(
        "sess-room-handle-budget",
        OffRecordBackendClass::Local,
        SMALL_ROOM_BUDGET,
    )?;
    let custody = RoomCustody::of(&session);
    let padding = "x".repeat(2 * SMALL_ROOM_BUDGET);
    for key in [KEY, OTHER_KEY, THIRD_KEY] {
        let body = format!("step output: {key}\n{padding}\n");
        assert!(
            put_room_replay_row(&session, EntityId::now(), body.as_bytes()).is_err(),
            "FIXTURE: the room's budget refuses the row"
        );
    }
    assert_eq!(
        custody.count()?,
        0,
        "no refused write leaves a secret in the room"
    );

    put_room_replay_row(
        &session,
        EntityId::now(),
        format!("step output: {KEY}\n").as_bytes(),
    )?;
    assert_eq!(
        custody.count()?,
        1,
        "a write that fits keeps its own secret"
    );
    Ok(())
}

/// REVIEW-10003 round 2 (P1 assignment.rs:423): the release scan reads a
/// room handle as a body streams as it reads it whole: the bracketed and the
/// bare spelling a room gives are handles, and `[secret r1]` is none.
#[test]
fn the_streamed_release_scan_reads_a_room_handle_as_the_whole_scan_does() -> TestResult {
    for (body, handle) in [
        ("password=[secret r0123456789abcdef.1]\n", true),
        ("password=r0123456789abcdef.1\n", true),
        ("password=[secret r1]\n", false),
    ] {
        let (whole, streamed) = release_scan_whole_and_streamed(body.as_bytes())?;
        assert_eq!(
            whole.is_none(),
            handle,
            "FIXTURE: the whole scan reads {body:?}"
        );
        assert_eq!(
            streamed, whole,
            "the streamed scan reads {body:?} as the whole scan does"
        );
    }
    Ok(())
}
