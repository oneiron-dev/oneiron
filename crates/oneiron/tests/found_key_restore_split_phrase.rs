//! FIX [SEALED-PHRASE-ARRAY-RESTORE-AS-TEXT] (Engine RULING 14 Nov 14:55,
//! NEXT-ROW-22 B): a recovery phrase written one word per array item, or as
//! an array of its byte values, is lifted whole (LABEL-04): one custody
//! record holds the phrase, its words one space apart, and one handle takes
//! the place of the array, or of the run of items that holds it. The
//! owner's "not a secret" or "kept as text" answer puts back the array, or
//! the items, as written, not one string of the phrase.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_restore_split_phrase`.

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
    let issuer = HostSlipIssuer::from_secret(b"found key restore split phrase host")?;
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

/// The handle of the one key the mask lifted out of `record`.
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
        _ => Err(format!("FIXTURE: the mask lifted one key out of the record: {keys:?}").into()),
    }
}

/// A new record of `body`, as the owner's batch writes it, out of which the
/// mask lifted one key, the phrase. The record, that key's handle and the
/// stored body as `read` reads it.
fn masked_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    body: &[u8],
    read: ReadBody,
) -> Result<(EntityId, String, Value), Box<dyn std::error::Error>> {
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
    Ok((id, handle, read(&stored(vault, &id)?)?))
}

/// Asserts the mask took the phrase out of `field` whole: it now holds only
/// the key's handle.
fn assert_held_whole(masked: &Value, field: &str, handle: &str) {
    assert_eq!(
        masked[field],
        Value::from(handle),
        "FIXTURE: the mask lifted the field's value whole: {masked}"
    );
}

#[test]
fn a_phrase_one_word_per_item_comes_back_as_the_array() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = words();
    let body = serde_json::to_vec(&json!({ "name": "owen", "words": written }))?;
    let (id, handle, masked) = masked_record(&vault, &owner, &body, json_body)?;
    assert_held_whole(&masked, "words", &handle);

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["words"], written,
        "not a secret puts the array of words back, not one string: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}

#[test]
fn a_phrase_one_word_per_item_in_a_messagepack_body_comes_back_as_the_array() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = words();
    let body = rmp_serde::to_vec_named(&json!({ "name": "owen", "words": written }))?;
    let (id, handle, masked) = masked_record(&vault, &owner, &body, messagepack_body)?;
    assert_held_whole(&masked, "words", &handle);

    vault.keep_found_key_as_text(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = messagepack_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["words"], written,
        "kept as text puts the array of words back, in the MessagePack body: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}

#[test]
fn a_phrase_run_among_other_items_comes_back_as_its_items() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let items: Vec<&str> = ["zzzz"]
        .into_iter()
        .chain(PHRASE.split(' '))
        .chain(["qqqq"])
        .collect();
    let written = json!(items);
    let body = serde_json::to_vec(&json!({ "name": "owen", "lines": written }))?;
    let (id, handle, masked) = masked_record(&vault, &owner, &body, json_body)?;
    assert_eq!(
        masked["lines"],
        json!(["zzzz", handle, "qqqq"]),
        "FIXTURE: one item holding the handle took the place of the phrase's words: {masked}"
    );

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["lines"], written,
        "not a secret puts each word back as its own item, between the others: {restored}"
    );
    Ok(())
}

#[test]
fn a_phrase_as_byte_values_comes_back_as_the_byte_values() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let written = json!(PHRASE.as_bytes());
    let body = serde_json::to_vec(&json!({ "name": "owen", "notes": written }))?;
    let (id, handle, masked) = masked_record(&vault, &owner, &body, json_body)?;
    assert_held_whole(&masked, "notes", &handle);

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let restored = json_body(&stored(&vault, &id)?)?;
    assert_eq!(
        restored["notes"], written,
        "not a secret puts the byte values back as numbers: {restored}"
    );
    assert_eq!(restored["name"], "owen", "{restored}");
    Ok(())
}
