//! FIX [SEALED-VALUE-RESTORE-KEEPS-ENCODED-TEXT] (Engine RULING 14 Nov 13:01,
//! NEXT-ROW-21 D): a credential field's value that is neither text nor bytes
//! (an array, a map, a number) is sealed whole, and its custody record holds
//! the value's MessagePack encoding. The owner's "not a secret" or "kept as
//! text" answer puts back the value itself, in the body's own form (JSON or
//! MessagePack), not a string or a byte string of its encoding.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_restore_whole_value`.

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

/// A vault on an install with a device keystore and a live machine profile,
/// so a ruling's revoke is carried at once, with its data key held, and its
/// embedded owner's proof (the `found_key_ruled_screen.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key restore whole value host")?;
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

/// The handle of the key the mask lifted out of `record`.
fn found_handle(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the field into a found key")?)
}

/// A new record of `body`, as the owner's batch writes it, whose `field`
/// the mask sealed whole: the field now holds only the key's handle. The
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
        "FIXTURE: the mask sealed the field whole: {sealed}"
    );
    Ok((id, handle))
}

#[test]
fn a_sealed_array_comes_back_as_the_array() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!(["cobalt", "argon"]);
    let body = serde_json::to_vec(&json!({ "name": "deploy", "password": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, json_body, "password")?;

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["password"], written,
        "not a secret puts the array back as written, not its encoding: {restored}"
    );
    assert_eq!(restored["name"], "deploy", "{restored}");
    Ok(())
}

#[test]
fn a_sealed_map_comes_back_as_the_map_in_a_messagepack_body() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!({ "user": "owen", "pin": "4321" });
    let body = rmp_serde::to_vec_named(&json!({ "name": "deploy", "api_key": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, messagepack_body, "api_key")?;

    vault.keep_found_key_as_text(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = messagepack_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["api_key"], written,
        "kept as text puts the map back as written, in the MessagePack body: {restored}"
    );
    assert_eq!(restored["name"], "deploy", "{restored}");
    Ok(())
}

#[test]
fn a_sealed_number_comes_back_as_the_number() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    // The encoding of 7 is one byte that is also valid text, so only the
    // key's record of how custody holds it tells the two apart.
    let written = json!(7);
    let body = serde_json::to_vec(&json!({ "name": "deploy", "secret": written }))?;
    let (id, handle) = sealed_record(&vault, &owner, &body, json_body, "secret")?;

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["secret"], written,
        "not a secret puts the number back as written: {restored}"
    );
    Ok(())
}
