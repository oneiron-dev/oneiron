//! L7-30 (ARCH-0038 #secret-scan-target, ARCH-0040 #content-check; owner,
//! 2026-10-07 and 2026-10-17: "why does it assume it would be
//! impossible?"): the secret scan never refuses a write. A hit no span
//! places seals the smallest value that reads as that hit on its own into
//! custody whole; its handle takes the value's place, and the rest of the
//! write is kept. The owner hears of it as of any lifted key.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A provider token under a credential name: as text the door's rules
/// place it; as a body's byte values only the door's whole read finds it.
const TOKEN: &str = "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A private key block one line per item: no line reads as a key alone,
/// and the lines read one per line do. The body lines are filler, no key.
const KEY_LINES: [&str; 4] = [
    "-----BEGIN PRIVATE KEY-----",
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC",
    "-----END PRIVATE KEY-----",
];

/// A vault with the owner's scan switch at its default (on), a device
/// keystore, a serving install profile and the authenticated owner, who
/// reads the found-key notices.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"secret scan seal whole host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn put(vault: &Vault, body: &[u8]) -> oneiron::Result<EntityId> {
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
    Ok(id)
}

fn custody_records(vault: &Vault) -> oneiron::Result<usize> {
    vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)
}

fn stored_json(
    vault: &Vault,
    id: &EntityId,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let body = vault.get(id)?.ok_or("the record is stored")?;
    Ok(serde_json::from_slice(&body)?)
}

/// Whether `value` is one custody handle whole, as a credential field's
/// value keeps it: `sc` and the record's short id.
fn is_handle(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.strip_prefix("sc")
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Each place the owner's found-key notice names for `record`.
fn notice_places(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> oneiron::Result<Vec<String>> {
    Ok(vault
        .found_keys(owner, false, 100)?
        .into_iter()
        .filter(|notice| notice.record == *record)
        .flat_map(|notice| notice.keys)
        .map(|key| key.place)
        .collect())
}

/// A token written as a body's byte values: no span places it, so the
/// array that holds it is sealed whole. Before, the write was refused.
#[test]
fn a_token_as_byte_values_seals_the_array_and_the_write_lands() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let body = serde_json::to_vec(&serde_json::json!({
        "name": "owen",
        "notes": TOKEN.as_bytes(),
    }))?;
    let before = custody_records(&vault)?;
    let id = put(&vault, &body)
        .unwrap_or_else(|error| panic!("a hit no span places no longer refuses: {error:?}"));
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the sealed value"
    );
    let stored = stored_json(&vault, &id)?;
    assert_eq!(stored["name"], "owen", "the rest of the write is kept");
    assert!(
        is_handle(&stored["notes"]),
        "the byte values take one handle whole: {stored}"
    );
    assert_eq!(
        notice_places(&vault, &owner, &id)?,
        vec!["body".to_owned()],
        "the owner hears of the sealed value"
    );
    Ok(())
}

/// A key block split one line per item: no line reads as a key alone, so
/// the array that holds all of it is sealed whole, never one line whose
/// stand-in only breaks the block's pattern.
#[test]
fn a_key_split_one_line_per_item_seals_the_array_that_holds_it() -> TestResult {
    let (_dir, vault, _owner) = open_vault()?;
    let body = serde_json::to_vec(&serde_json::json!({ "name": "owen", "key": KEY_LINES }))?;
    let before = custody_records(&vault)?;
    let id = put(&vault, &body)
        .unwrap_or_else(|error| panic!("a key split over items no longer refuses: {error:?}"));
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the whole block"
    );
    let stored = stored_json(&vault, &id)?;
    assert_eq!(stored["name"], "owen", "the rest of the write is kept");
    assert!(
        is_handle(&stored["key"]),
        "the array takes one handle whole: {stored}"
    );
    let text = stored.to_string();
    for line in &KEY_LINES[1..3] {
        assert!(
            !text.contains(line),
            "no line of the key body is stored: {text}"
        );
    }
    Ok(())
}

/// A text field whose hit no span places (a token as JSON byte values) is
/// sealed whole and keeps one handle. Before, the batch was refused.
#[test]
fn a_text_field_hit_no_span_places_is_sealed_whole() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let id = EntityId::now();
    let notes = serde_json::to_string(TOKEN.as_bytes())?;
    let before = custody_records(&vault)?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            br#"{"name":"owen"}"#,
        )
        .text(&id, &[("notes", notes.as_str())])
        .commit()
        .unwrap_or_else(|error| panic!("a text field's hit no longer refuses: {error:?}"));
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the field's text"
    );
    assert_eq!(
        notice_places(&vault, &owner, &id)?,
        vec!["text:notes".to_owned()],
        "the owner hears of the sealed field"
    );
    Ok(())
}

/// Control: a hit a span places keeps its span's handle, and the text
/// before it stays as written; nothing is sealed whole.
#[test]
fn a_placed_span_keeps_the_rest_of_its_text() -> TestResult {
    let (_dir, vault, _owner) = open_vault()?;
    let body = serde_json::to_vec(&serde_json::json!({
        "name": "owen",
        "notes": format!("call owen back. {TOKEN}"),
    }))?;
    let id = put(&vault, &body)?;
    let stored = stored_json(&vault, &id)?;
    let notes = stored["notes"].as_str().ok_or("notes stay text")?;
    assert!(
        notes.starts_with("call owen back. "),
        "the text before the span is kept: {notes}"
    );
    assert!(
        notes.contains("[secret sc") && !notes.contains("ghp_"),
        "the span takes its handle: {notes}"
    );
    Ok(())
}
