//! ROOM-CUSTODY-REPLY-BODIES (the lead's ruling ROOM-LOCAL-CUSTODY = A of
//! 21 Nov, "fingerprint only on save"): a code run's reply in an off-record
//! room that holds a fresh key keeps the key in the room's own custody and
//! holds its room handle, where the reply was withheld before. Saving the
//! turn that says the run's result moves the key into the vault's custody:
//! the saved MESSAGE names a body in base that holds the base handle, with
//! that body's length and lines, never the room handle or the key, and its
//! result reads in base; base's known-value index knows the key from then
//! on. A reply past the inline bound is carried the same way, into a base
//! body file.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_custody_reply_bodies`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::off_record_reply_body::{
    RoomResult, SavedResult, room_result_body, saved_result, say_room_result,
};
use oneiron::test_doors::off_record_side_row::{
    vault_custody_record_count, vault_custody_value, vault_knows_value,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A GitHub token, in a shape the side-row wall reads as a secret.
const KEY: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// The default inline bound of a result body (`[limits]
/// code_result_inline_bytes`): one past it spills to a file.
const INLINE_BOUND: usize = 1 << 20;

/// An owned vault, its embedded owner PERSON and that owner's proof
/// (tests/room_custody_save.rs).
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

/// A run in `session`, acting as `actor`, answers `body` and says it as
/// its result; the room keeps the reply, holding its room handle.
fn room_says(
    session: &OffRecordSession<'_>,
    actor: EntityId,
    body: &str,
) -> TestResult<RoomResult> {
    Ok(say_room_result(session, actor, body.as_bytes())?
        .map_err(|unavailable| format!("the room withheld the reply: {unavailable}"))?)
}

/// The first vault custody handle (`[secret sc12]`) in `text`.
fn base_handle(text: &str) -> Option<String> {
    let start = text.find("[secret sc")?;
    let len = text[start..].find(']')?;
    Some(text[start..=start + len].to_owned())
}

/// The saved result's body holds the base handle of a record that holds
/// [`KEY`], and neither a room handle nor the key; its attachment's length
/// and lines are the body's; its preview holds no room handle; its result
/// reads in base; base knows the key's fingerprint.
fn assert_carried(owned: &Owned, saved: &SavedResult) -> TestResult {
    let vault = &owned.vault;
    let body = String::from_utf8(saved.body.clone())?;
    assert!(
        !body.contains("[secret r"),
        "the saved body keeps no room handle"
    );
    assert!(!body.contains(KEY), "the saved body holds no key");
    let base = base_handle(&body).ok_or("the saved body names a vault custody handle")?;
    assert_eq!(
        vault_custody_value(vault, &base)?.as_deref(),
        Some(KEY.as_bytes()),
        "{base} holds the key the room kept"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    assert_eq!(
        saved.bytes,
        saved.body.len() as u64,
        "the attachment names the saved body's length"
    );
    assert_eq!(
        saved.lines,
        body.lines().count() as u64,
        "the attachment names the saved body's lines"
    );
    assert!(
        !saved.preview.contains("[secret r"),
        "the saved preview keeps no room handle: {}",
        saved.preview
    );
    assert!(
        vault_knows_value(vault, KEY.as_bytes())?,
        "the save teaches base's known-value index the fingerprint"
    );
    let card = vault
        .memory(owned.actor, EdgeActorClass::Human)
        .read_message_result(&saved.message, None, serde_json::Value::Null)
        .map_err(|error| format!("the saved result does not read in base: {error:?}"))?;
    assert!(
        !card.to_string().contains("[secret r"),
        "the saved result's card keeps no room handle"
    );
    Ok(())
}

#[test]
fn a_room_reply_holding_a_fresh_key_keeps_it_in_the_room() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-reply-body-kept", OffRecordBackendClass::Local)?;

    let said = room_says(&session, owned.actor, &format!("token: {KEY}\n"))?;

    let body = room_result_body(vault, &session, &said.handle)?
        .ok_or("the room keeps the reply's body")?;
    let body = String::from_utf8(body)?;
    assert!(
        body.contains("[secret r"),
        "the reply holds its room handle: {body}"
    );
    assert!(!body.contains(KEY), "the reply holds no key");
    assert_eq!(
        vault_custody_record_count(vault)?,
        0,
        "no base custody record"
    );
    assert!(
        !vault_knows_value(vault, KEY.as_bytes())?,
        "base knows no fingerprint while the room is unsaved"
    );
    Ok(())
}

#[test]
fn a_saved_result_message_names_a_base_body_holding_the_base_handle() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-reply-body-saved", OffRecordBackendClass::Local)?;
    let said = room_says(&session, owned.actor, &format!("token: {KEY}\nnext line\n"))?;

    let saved = session.promote_turn_as(&owned.owner, &said.turn)?.replayed;

    let saved = saved_result(vault, &saved)?.ok_or("the saved MESSAGE carries its result")?;
    assert_ne!(
        saved.handle, said.handle,
        "the saved MESSAGE names the carried body, not the room's"
    );
    assert_carried(&owned, &saved)
}

#[test]
fn a_spilled_room_reply_is_carried_into_a_base_body_file() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-reply-body-spilled", OffRecordBackendClass::Local)?;
    let mut body = format!("token: {KEY}\n");
    while body.len() <= INLINE_BOUND + 4096 {
        body.push_str("a line of the run's long answer\n");
    }
    let said = room_says(&session, owned.actor, &body)?;

    let saved = session.promote_turn_as(&owned.owner, &said.turn)?.replayed;

    let saved = saved_result(vault, &saved)?.ok_or("the saved MESSAGE carries its result")?;
    assert!(
        saved.body.len() > INLINE_BOUND,
        "FIXTURE: the carried body still spills"
    );
    assert_carried(&owned, &saved)
}
