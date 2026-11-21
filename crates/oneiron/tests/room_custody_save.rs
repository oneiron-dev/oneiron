//! ROOM-LOCAL-CUSTODY (the lead's ruling of 21 Nov, "fingerprint only on
//! save"): saving the room moves each secret a saved row names into the
//! vault's normal custody, and only then does the known-value index learn
//! its fingerprint. A participant's message quotes the room handle of a key
//! the room keeps; the owner saves the turn. The saved MESSAGE names the
//! handle of a base custody record that holds the key, never the room
//! handle or the key, and base's known-value index knows the key from then
//! on. A second save that names the same room handle takes the same base
//! record. A save that names no room handle moves nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_custody_save`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::off_record_side_row::{
    base_custody_handle_in_rows, base_rows_hold, put_room_replay_row, room_replay_row, say_in_room,
    vault_custody_record_count, vault_custody_value, vault_knows_value,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A GitHub token, in a shape the side-row wall reads as a secret.
const KEY: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// An owned vault, its embedded owner PERSON and that owner's proof
/// (tests/it/authority/gate_pins_authority_custody_grants.rs).
struct Owned {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn owned() -> TestResult<Owned> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    Ok(Owned {
        _dir: dir,
        vault,
        actor,
        owner,
    })
}

/// The room handle the room keeps [`KEY`] under: a code run's row there
/// holds the key, which the room keeps in its own custody.
fn room_keeps_key(session: &OffRecordSession<'_>) -> TestResult<String> {
    let run = EntityId::now();
    put_room_replay_row(session, run, format!("step output: {KEY}\n").as_bytes())?;
    let row = room_replay_row(session, run)?.ok_or("the room keeps the row")?;
    let row = String::from_utf8(row)?;
    let start = row
        .find("[secret r")
        .ok_or("the row holds no room handle")?;
    let len = row[start..].find(']').ok_or("the handle has no bracket")?;
    Ok(row[start..=start + len].to_owned())
}

#[test]
fn a_save_moves_a_room_secret_into_vault_custody_and_only_then_fingerprints_it() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-custody-save", OffRecordBackendClass::Local)?;
    let handle = room_keeps_key(&session)?;
    let turn = say_in_room(
        vault,
        &session,
        owned.actor,
        &format!("the key is {handle}"),
    )?;
    assert_eq!(
        vault_custody_record_count(vault)?,
        0,
        "FIXTURE: before the save"
    );
    assert!(
        !vault_knows_value(vault, KEY.as_bytes())?,
        "FIXTURE: base knows no fingerprint before the save"
    );

    let saved = session.promote_turn_as(&owned.owner, &turn)?.replayed;

    assert!(
        !base_rows_hold(vault, &saved, &handle)?,
        "no saved row keeps the room handle {handle}"
    );
    assert!(
        !base_rows_hold(vault, &saved, KEY)?,
        "no saved row holds the key"
    );
    let base = base_custody_handle_in_rows(vault, &saved)?
        .ok_or("the saved message names a vault custody handle")?;
    assert_eq!(
        vault_custody_value(vault, &base)?.as_deref(),
        Some(KEY.as_bytes()),
        "{base} holds the key the room kept under {handle}"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    assert!(
        vault_knows_value(vault, KEY.as_bytes())?,
        "the save teaches base's known-value index the fingerprint"
    );

    // A later save naming the same room handle takes the same base record.
    let again = say_in_room(vault, &session, owned.actor, &format!("again: {handle}"))?;
    let saved_again = session.promote_turn_as(&owned.owner, &again)?.replayed;
    assert_eq!(
        base_custody_handle_in_rows(vault, &saved_again)?.as_deref(),
        Some(base.as_str()),
        "the value keeps its one base record"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    Ok(())
}

#[test]
fn a_save_naming_no_room_handle_moves_nothing() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-custody-save-none", OffRecordBackendClass::Local)?;
    room_keeps_key(&session)?;
    let turn = say_in_room(vault, &session, owned.actor, "nothing secret here")?;

    session.promote_turn_as(&owned.owner, &turn)?;

    assert_eq!(
        vault_custody_record_count(vault)?,
        0,
        "a room secret no saved row names stays in the room"
    );
    assert!(
        !vault_knows_value(vault, KEY.as_bytes())?,
        "base learns no fingerprint of a room secret no saved row names"
    );
    Ok(())
}
