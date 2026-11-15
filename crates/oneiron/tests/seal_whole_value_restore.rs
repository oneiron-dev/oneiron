//! FIX [SEAL-WHOLE-VALUE-HELD-RAW] (Engine RULING 14 Nov 14:55, NEXT-ROW-22
//! A): a hit no span places seals the smallest value that reads as it alone
//! (`seal_whole`). When that value is an array, a map or a number, custody
//! holds it in the encoding of the body that held it, and the found key
//! records that encoding. The owner's "not a secret" or "kept as text"
//! answer puts back the value itself, in the body's own form (JSON or
//! MessagePack), not a string or a byte string of its encoding.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test seal_whole_value_restore`.

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

/// A private key block one line per item: no line reads as a key alone,
/// and the lines read one per line do, so the array is sealed whole. The
/// body lines are filler, no key (the `secret_scan_seal_whole.rs` block).
const KEY_LINES: [&str; 4] = [
    "-----BEGIN PRIVATE KEY-----",
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC",
    "-----END PRIVATE KEY-----",
];

/// A provider token under a credential name: written as a body's byte
/// values, only the door's whole read finds it, so the array of numbers
/// is sealed whole.
const TOKEN: &str = "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault on an install with a device keystore and a live machine profile,
/// so a ruling's revoke is carried at once, with its data key held, and its
/// embedded owner's proof (the `found_key_restore_whole_value.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"seal whole value restore host")?;
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

/// A MessagePack body read back; a byte string reads as its byte values.
fn messagepack_body(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let body = rmpv::decode::read_value(&mut &bytes[..])?;
    Ok(serde_json::to_value(&body)?)
}

fn stored(vault: &Vault, id: &EntityId) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(vault.get(id)?.ok_or("FIXTURE: the record is stored")?)
}

/// The handle of the one key the seal lifted out of `record`.
fn found_handle(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    let keys: Vec<String> = vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .filter(|notice| notice.record == *record)
        .flat_map(|notice| notice.keys)
        .map(|key| key.handle)
        .collect();
    match keys.as_slice() {
        [handle] => Ok(handle.clone()),
        _ => Err(format!("FIXTURE: the seal lifted one key out of the record: {keys:?}").into()),
    }
}

/// A new record of `body`, as the owner's batch writes it, whose `field`
/// the seal took whole: the field now holds only the key's handle. The
/// record and that handle.
fn sealed_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    body: &[u8],
    read: ReadBody,
    field: &str,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
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
    let handle = found_handle(vault, owner, &id)?;
    let sealed = read(&stored(vault, &id)?)?;
    assert_eq!(
        sealed[field],
        Value::from(handle.as_str()),
        "FIXTURE: the seal took the field's value whole: {sealed}"
    );
    Ok((id, handle))
}

#[test]
fn a_key_array_sealed_whole_comes_back_as_the_array() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!(KEY_LINES);
    let body = serde_json::to_vec(&json!({ "name": "owen", "key": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, json_body, "key")?;

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["key"], written,
        "not a secret puts the array back as written, not its JSON text: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}

#[test]
fn a_key_array_sealed_whole_in_a_messagepack_body_comes_back_as_the_array() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!(KEY_LINES);
    let body = rmp_serde::to_vec_named(&json!({ "name": "owen", "key": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, messagepack_body, "key")?;

    vault.keep_found_key_as_text(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = messagepack_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["key"], written,
        "kept as text puts the array back as written, in the MessagePack body: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}

#[test]
fn byte_values_sealed_whole_come_back_as_the_byte_values() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!(TOKEN.as_bytes());
    let body = serde_json::to_vec(&json!({ "name": "owen", "notes": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, json_body, "notes")?;

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["notes"], written,
        "not a secret puts the numbers back as numbers: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}
