//! Engine RULING 14 Nov 08:35 (NEXT-ROW-15 = A, L6-03-RULED-SCREEN-LOCAL): a
//! found key the owner ruled no secret, or kept as text, stays text on all
//! of the owner's machines. The ruling's revoke carries a value-free screen
//! of the ruled value to each of them, and the write door reads that screen
//! before it masks. While the vault key is locked, a ruling waits, because
//! it would not reach the owner's other machines.
//!
//! Engine RULING 14 Nov 10:27 (row C, L6-03-RULED-SCREEN-MERGED-SPAN): a ruled
//! value stays as written where the text rules place it next to another
//! span, on the ruling install and on the others: a key beside it is masked
//! on its own, and a word the rules read around it is no hit once the ruled
//! value is filled. RULING 11:28 (RULED-SCREEN-MERGED-SPAN-SCOPE = A): a
//! ruled value written inside a longer token stays masked with that token.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_ruled_screen`.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::found_key_forget::forget_found_keys_of;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault on an install with a device keystore and a live machine profile,
/// so a ruling's revoke is carried at once, with its data key held, and its
/// embedded owner's proof.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key ruled screen host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_vault_key()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

/// A record body whose notes hold the token.
fn body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "notes": format!("deploy with token={TOKEN}"),
    }))
    .expect("FIXTURE: the body encodes")
}

/// A record body with a credential-named field: the mask lifts its value
/// whatever it is, and no text rule places a span on it.
fn credential_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "password": "cobalt" }))
        .expect("FIXTURE: the body encodes")
}

/// Writes `body` as record `id` at `version`, as the owner's batch does.
fn put(vault: &Vault, id: &EntityId, version: u64, body: &[u8]) -> oneiron::Result<()> {
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            version,
            body,
        )
        .commit()?;
    Ok(())
}

fn stored(vault: &Vault, id: &EntityId) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(vault.get(id)?.ok_or("FIXTURE: the record is stored")?)
}

fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn holds_token(bytes: &[u8]) -> bool {
    holds(bytes, TOKEN.as_bytes())
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
        .ok_or("FIXTURE: the mask lifted the token into a found key")?)
}

/// A record of `body` whose `value` the mask lifted, and that key's handle.
fn masked_record_of(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    body: &[u8],
    value: &[u8],
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    put(vault, &id, 1, body)?;
    assert!(
        !holds(&stored(vault, &id)?, value),
        "FIXTURE: the mask lifted the value"
    );
    let handle = found_handle(vault, owner, &id)?;
    Ok((id, handle))
}

/// A record whose token the mask lifted, and that key's handle.
fn masked_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    masked_record_of(vault, owner, &body(), TOKEN.as_bytes())
}

#[test]
fn a_ruling_holds_where_only_its_carried_revoke_reaches() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, handle) = masked_record(&vault, &owner)?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert!(
        holds_token(&stored(&vault, &id)?),
        "FIXTURE: the ruling put the value back"
    );

    // The owner's other machine: none of the record's found keys, no kept
    // value; only the ruling's revoke, folded by its owner work drain.
    forget_found_keys_of(&vault, id)?;
    vault.run_pending_owner_work(|| true)?;

    let body = body();
    put(&vault, &id, 2, &body)
        .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
    assert_eq!(
        stored(&vault, &id)?,
        body,
        "a value ruled no secret stays text where only the ruling's revoke reached"
    );
    Ok(())
}

#[test]
fn a_ruled_credential_field_holds_where_only_its_carried_revoke_reaches() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let body = credential_body();
    let (id, handle) = masked_record_of(&vault, &owner, &body, b"cobalt")?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert!(
        holds(&stored(&vault, &id)?, b"cobalt"),
        "FIXTURE: the ruling put the value back"
    );

    forget_found_keys_of(&vault, id)?;
    vault.run_pending_owner_work(|| true)?;

    put(&vault, &id, 2, &body)
        .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
    assert_eq!(
        stored(&vault, &id)?,
        body,
        "a credential field's value ruled no secret stays as written where only the \
         ruling's revoke reached"
    );
    Ok(())
}

#[test]
fn a_ruling_waits_while_the_vault_key_is_locked() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, handle) = masked_record(&vault, &owner)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(vault.lock_vault_key());

    let refused = vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle);
    assert!(
        refused.is_err(),
        "a ruling made while the vault key is locked would not reach the owner's other \
         machines, so it waits: {refused:?}"
    );
    assert!(
        !holds_token(&stored(&vault, &id)?),
        "the waiting ruling put nothing back"
    );

    vault.unlock_vault_key()?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert!(
        holds_token(&stored(&vault, &id)?),
        "with the key unlocked, the ruling stands"
    );
    Ok(())
}

/// An AWS access key id the door's provider rule places by its own span.
const OTHER_KEY: &str = "AKIA0123456789ABCDEF";

/// A record body whose notes hold `notes`.
fn notes_body(notes: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "notes": notes })).expect("FIXTURE: the body encodes")
}

/// The stored notes of record `id`.
fn stored_notes(vault: &Vault, id: &EntityId) -> Result<String, Box<dyn std::error::Error>> {
    let body: serde_json::Value = serde_json::from_slice(&stored(vault, id)?)?;
    Ok(body["notes"]
        .as_str()
        .ok_or("FIXTURE: the stored body keeps its notes")?
        .to_owned())
}

/// A record whose token the owner ruled no secret, on this install, or, with
/// `screen_only`, as the owner's other machine holds it: the ruling's
/// carried revoke folded, none of the record's found keys.
fn ruled_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    screen_only: bool,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    ruled_record_of(vault, owner, &body(), TOKEN.as_bytes(), screen_only)
}

/// A record of `body` whose `value` the owner ruled no secret, on this
/// install or, with `screen_only`, as the owner's other machine holds it.
fn ruled_record_of(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    body: &[u8],
    value: &[u8],
    screen_only: bool,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let (id, handle) = masked_record_of(vault, owner, body, value)?;
    vault.rule_found_key_not_a_secret(owner, ActSurface::ThisInstall, &handle)?;
    assert!(
        holds(&stored(vault, &id)?, value),
        "FIXTURE: the ruling put the value back"
    );
    if screen_only {
        forget_found_keys_of(vault, id)?;
        vault.run_pending_owner_work(|| true)?;
    }
    Ok(id)
}

/// The ruled token and a key next to it in one assigned word: the
/// credential rule spans the word, each provider rule its own token.
fn ruled_value_next_to_a_key(screen_only: bool) -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let id = ruled_record(&vault, &owner, screen_only)?;
    let body = notes_body(&format!("password={TOKEN}/{OTHER_KEY}"));
    put(&vault, &id, 2, &body)
        .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
    let notes = stored_notes(&vault, &id)?;
    assert!(
        notes.starts_with(&format!("password={TOKEN}/[secret sc")),
        "the ruled value stays as written next to the key beside it: {notes}"
    );
    assert!(
        !notes.contains(OTHER_KEY),
        "the key beside the ruled value is masked on its own: {notes}"
    );
    Ok(())
}

#[test]
fn a_ruled_value_next_to_a_key_stays_text_on_the_ruling_install() -> TestResult {
    ruled_value_next_to_a_key(false)
}

#[test]
fn a_ruled_value_next_to_a_key_stays_text_where_only_its_carried_revoke_reaches() -> TestResult {
    ruled_value_next_to_a_key(true)
}

#[test]
fn a_ruled_value_inside_an_assigned_word_stays_text_where_only_its_carried_revoke_reaches()
-> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let id = ruled_record(&vault, &owner, true)?;
    // The credential rule reads the whole word, in the body's bytes too (the
    // comma opens its own segment there); with the ruled token filled, as the
    // ruling install fills it, the word is no secret.
    let body = notes_body(&format!("deploy, token={TOKEN}:v2"));
    put(&vault, &id, 2, &body)
        .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
    assert_eq!(
        stored(&vault, &id)?,
        body,
        "a ruled value inside a word the rules read around it stays as written where only \
         the ruling's revoke reached"
    );
    Ok(())
}

#[test]
fn a_ruled_value_inside_a_longer_token_stays_masked_on_every_install() -> TestResult {
    for screen_only in [false, true] {
        let (_dir, vault, owner) = open_vault()?;
        let id = ruled_record(&vault, &owner, screen_only)?;
        // The provider rule reads the token with its label whole, and so does
        // the credential rule: no rule places the ruled value alone there.
        let body = notes_body(&format!("deploy, token={TOKEN}_v2"));
        put(&vault, &id, 2, &body)
            .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
        let notes = stored_notes(&vault, &id)?;
        assert!(
            notes.starts_with("deploy, token=[secret sc") && !notes.contains(TOKEN),
            "a longer token that holds the ruled value is masked whole (screen only: \
             {screen_only}): {notes}"
        );
    }
    Ok(())
}

/// An entry of the door's blocklist: its rule places the entry alone, even
/// inside a longer token.
const BLOCKLIST_ENTRY: &str = "oneiron-secret-blocklist-fixture";

#[test]
fn a_ruled_blocklist_entry_inside_a_longer_token_is_masked_on_every_install() -> TestResult {
    for screen_only in [false, true] {
        let (_dir, vault, owner) = open_vault()?;
        let ruled = notes_body(&format!("deploy {BLOCKLIST_ENTRY}"));
        let id = ruled_record_of(
            &vault,
            &owner,
            &ruled,
            BLOCKLIST_ENTRY.as_bytes(),
            screen_only,
        )?;
        let body = notes_body(&format!("deploy {BLOCKLIST_ENTRY}xyz"));
        put(&vault, &id, 2, &body)
            .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
        let notes = stored_notes(&vault, &id)?;
        assert!(
            notes.starts_with("deploy [secret sc") && !notes.contains(BLOCKLIST_ENTRY),
            "a ruled value the rules place alone inside a longer token is masked there \
             (screen only: {screen_only}): {notes}"
        );
    }
    Ok(())
}

/// The base64 line of a private key block that holds no ruled value.
const KEY_BODY_LINE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";

#[test]
fn a_private_key_block_that_holds_a_ruled_value_is_masked_whole_on_every_install() -> TestResult {
    for screen_only in [false, true] {
        let (_dir, vault, owner) = open_vault()?;
        let ruled = notes_body(&format!("aws key {OTHER_KEY}"));
        let id = ruled_record_of(&vault, &owner, &ruled, OTHER_KEY.as_bytes(), screen_only)?;
        // The ruled key stands as its own line of the block, so the provider
        // rule places it alone; the block rule reads both lines as its body.
        let body = notes_body(&format!(
            "-----BEGIN PRIVATE KEY-----\n{OTHER_KEY}\n{KEY_BODY_LINE}\n-----END PRIVATE KEY-----"
        ));
        put(&vault, &id, 2, &body)
            .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
        let notes = stored_notes(&vault, &id)?;
        assert!(
            !notes.contains(KEY_BODY_LINE) && !notes.contains("BEGIN PRIVATE KEY"),
            "a private key block that holds a ruled value is masked whole (screen only: \
             {screen_only}): {notes}"
        );
    }
    Ok(())
}

#[test]
fn a_ruled_value_after_an_escaped_line_break_stays_text_on_the_ruling_install() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let id = ruled_record(&vault, &owner, false)?;
    // The body's JSON writes the line break as `\n`: in its bytes the token
    // follows an `n`, in its notes a line break.
    let notes = format!("line one\n{TOKEN}");
    let body = notes_body(&notes);
    assert!(
        holds(&body, format!("one\\n{TOKEN}").as_bytes()),
        "FIXTURE: the body's bytes escape the line break"
    );
    put(&vault, &id, 2, &body)
        .unwrap_or_else(|error| panic!("the record, written again, lands: {error:?}"));
    assert_eq!(
        stored_notes(&vault, &id)?,
        notes,
        "a ruled value after a line break stays as written"
    );
    Ok(())
}
