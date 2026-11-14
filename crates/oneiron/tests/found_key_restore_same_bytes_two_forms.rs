//! FIX [SEALED-SAME-BYTES-RAW-AND-ENCODED-ONE-HANDLE] (Engine RULING 14 Nov
//! 14:55, NEXT-ROW-22 D): one write that holds the same bytes twice, written
//! two ways, lifts each into a custody record of its own. The text "7" and
//! the number 55, whose MessagePack encoding is the same byte, under two
//! credential names; a recovery phrase as text and as an array of its words.
//! Each key records how its field was written, so the owner's "not a secret"
//! or "kept as text" answer on each puts back its own field as written: the
//! number as a number, the array as an array.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_restore_same_bytes_two_forms`.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// How a test reads a stored body back.
type ReadBody = fn(&[u8]) -> Result<Value, Box<dyn std::error::Error>>;

/// A public BIP39 test vector, as a recovery phrase's words (the
/// `split_phrase_mask_on_write.rs` phrase).
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// [`PHRASE`]'s words, one string item each.
fn words() -> Value {
    json!(PHRASE.split(' ').collect::<Vec<_>>())
}

/// A vault on an install with a device keystore and a live machine profile,
/// so a ruling's revoke is carried at once, with its data key held, and its
/// embedded owner's proof (the `found_key_restore_whole_value.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key restore same bytes host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_vault_key()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

/// A JSON body read back.
fn json_body(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(bytes)?)
}

/// A MessagePack body read back.
fn messagepack_body(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let body = rmpv::decode::read_value(&mut &bytes[..])?;
    Ok(serde_json::to_value(&body)?)
}

fn stored(vault: &Vault, id: &EntityId) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(vault.get(id)?.ok_or("FIXTURE: the record is stored")?)
}

/// The handles of every key the mask lifted out of `record`.
fn found_handles(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .filter(|notice| notice.record == *record)
        .flat_map(|notice| notice.keys)
        .map(|key| key.handle)
        .collect())
}

/// Writes `body` as a new record of the owner's batch and answers every key
/// the mask lifted out of it, "not a secret" and "kept as text" in turn.
/// The record's body as `read` reads it once every key is answered, the
/// handles answered, and the body as it was stored masked.
fn answered_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    body: &[u8],
    read: ReadBody,
) -> Result<(Value, Vec<String>, Value), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()?;
    let masked = read(&stored(vault, &id)?)?;
    let handles = found_handles(vault, owner, &id)?;
    if handles.is_empty() {
        return Err(format!("FIXTURE: the mask lifted a key out of the record: {masked}").into());
    }
    for (at, handle) in handles.iter().enumerate() {
        if at % 2 == 0 {
            vault.rule_found_key_not_a_secret(owner, ActSurface::ThisInstall, handle)?;
        } else {
            vault.keep_found_key_as_text(owner, ActSurface::ThisInstall, handle)?;
        }
    }
    Ok((read(&stored(vault, &id)?)?, handles, masked))
}

/// Asserts the record took one key per way it wrote the value, each with a
/// handle of its own.
fn assert_two_keys(handles: &[String], masked: &Value) {
    assert!(
        matches!(handles, [first, second] if first != second),
        "one key per form the record wrote the value in: {handles:?}, stored {masked}"
    );
}

/// The text "7" and the number 55 under two credential names, in the body
/// `encode` writes and `read` reads: both hold the byte 0x37, the text as
/// its own bytes and the number as its MessagePack encoding.
fn text_and_number_come_back_as_written(
    encode: fn(&Value) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
    read: ReadBody,
) -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let body = encode(&json!({ "name": "deploy", "password": "7", "secret": 55 }))?;
    let (restored, handles, masked) = answered_record(&vault, &owner, &body, read)?;

    assert_eq!(
        restored["password"],
        json!("7"),
        "the text comes back as the text: {restored}, stored {masked}"
    );
    assert_eq!(
        restored["secret"],
        json!(55),
        "the number comes back as the number, not the text of its encoding: {restored}, \
         stored {masked}"
    );
    assert_eq!(restored["name"], "deploy", "{restored}");
    assert_two_keys(&handles, &masked);
    Ok(())
}

fn json_encoded(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec(value)?)
}

fn messagepack_encoded(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(rmp_serde::to_vec_named(value)?)
}

#[test]
fn a_text_and_a_number_of_one_byte_in_a_json_body_each_come_back_as_written() -> TestResult {
    text_and_number_come_back_as_written(json_encoded, json_body)
}

#[test]
fn a_text_and_a_number_of_one_byte_in_a_messagepack_body_each_come_back_as_written() -> TestResult {
    text_and_number_come_back_as_written(messagepack_encoded, messagepack_body)
}

#[test]
fn a_phrase_as_text_and_as_its_words_in_one_body_each_come_back_as_written() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let body = json_encoded(&json!({ "name": "owen", "notes": PHRASE, "words": words() }))?;
    let (restored, handles, masked) = answered_record(&vault, &owner, &body, json_body)?;

    assert_eq!(
        restored["notes"],
        json!(PHRASE),
        "the text comes back as the text: {restored}, stored {masked}"
    );
    assert_eq!(
        restored["words"],
        words(),
        "the array of words comes back as the array, not one string: {restored}, \
         stored {masked}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    assert_two_keys(&handles, &masked);
    Ok(())
}

#[test]
fn a_phrase_under_a_credential_name_and_as_its_words_each_come_back_as_written() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let body = json_encoded(&json!({ "mnemonic": PHRASE, "name": "owen", "words": words() }))?;
    let (restored, handles, masked) = answered_record(&vault, &owner, &body, json_body)?;

    assert_eq!(
        restored["mnemonic"],
        json!(PHRASE),
        "the credential field's text comes back as the text: {restored}, stored {masked}"
    );
    assert_eq!(
        restored["words"],
        words(),
        "the array of words comes back as the array, not one string: {restored}, \
         stored {masked}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    assert_two_keys(&handles, &masked);
    Ok(())
}
