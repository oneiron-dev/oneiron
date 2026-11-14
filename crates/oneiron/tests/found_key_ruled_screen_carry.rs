//! Engine RULING 14 Nov 08:35 (NEXT-ROW-15 = A, L6-03-RULED-SCREEN-LOCAL):
//! the revoke a found-key ruling carries to the owner's other machines names
//! the record and a digest of the ruled value keyed by the vault's screen
//! key: never the value, never an unkeyed hash of it. A vault with no data
//! key has no other machine to reach: its ruling stands here and carries no
//! screen, and a write where the ruling is not known masks as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_ruled_screen_carry`.

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityOp, CustodyChange, CustodyRevokeScreen, HostSlipIssuer, MachineRole,
    OwnerWorkBody, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::found_key_forget::forget_found_keys_of;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault on an install with a device keystore and a live machine profile,
/// its data key held when `data_key`, and its embedded owner's proof.
fn open_vault(
    data_key: bool,
) -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key ruled screen carry host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    if data_key {
        vault.ensure_vault_key()?;
    }
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "notes": format!("deploy with token={TOKEN}"),
    }))
    .expect("FIXTURE: the body encodes")
}

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

/// A record whose token the mask lifted, and that key's handle.
fn masked_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    put(vault, &id, 1, &body())?;
    assert!(
        !holds(&stored(vault, &id)?, TOKEN.as_bytes()),
        "FIXTURE: the mask lifted the token"
    );
    let handle = vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == id)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the token into a found key")?;
    Ok((id, handle))
}

/// The screen of each custody revoke this install carried, with the bytes of
/// the entry that carries it.
fn carried_revokes(
    vault: &Vault,
) -> Result<Vec<(Option<CustodyRevokeScreen>, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut revokes = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)? {
        let entry = vault
            .get_authority_log_entry(&id)?
            .ok_or("FIXTURE: a listed authority entry exists")?;
        if let AuthorityOp::OwnerWorkRequest(request) = &entry.op
            && let OwnerWorkBody::Custody {
                change: CustodyChange::Revoke,
                screen,
                ..
            } = request.work
        {
            revokes.push((screen, encode_authority_log_entry_body(&entry)?));
        }
    }
    Ok(revokes)
}

#[test]
fn a_rulings_revoke_carries_a_keyed_screen_and_no_value() -> TestResult {
    let (_dir, vault, owner) = open_vault(true)?;
    let (id, handle) = masked_record(&vault, &owner)?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;

    let carried = carried_revokes(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "the ruling carries one revoke: {carried:?}"
    );
    let (screen, entry) = &carried[0];
    let screen = screen.ok_or("the ruling's revoke carries its screen")?;
    assert_eq!(screen.record, id, "the screen names the record");
    assert_ne!(screen.digest, [0; 32]);
    assert_ne!(
        screen.digest,
        *blake3::hash(TOKEN.as_bytes()).as_bytes(),
        "the digest is keyed, never an unkeyed hash a short value is guessed back from"
    );
    assert!(
        !holds(entry, TOKEN.as_bytes()),
        "the carried entry holds no byte run of the value"
    );
    Ok(())
}

#[test]
fn a_value_kept_as_text_holds_where_only_its_carried_revoke_reaches() -> TestResult {
    let (_dir, vault, owner) = open_vault(true)?;
    let (id, handle) = masked_record(&vault, &owner)?;
    vault.keep_found_key_as_text(&owner, ActSurface::ThisInstall, &handle)?;
    forget_found_keys_of(&vault, id)?;
    vault.run_pending_owner_work(|| true)?;

    let body = body();
    put(&vault, &id, 2, &body)?;
    assert_eq!(
        stored(&vault, &id)?,
        body,
        "a value kept as text stays text where only the ruling's revoke reached"
    );
    Ok(())
}

#[test]
fn a_vault_with_no_data_key_rules_here_and_carries_no_screen() -> TestResult {
    let (_dir, vault, owner) = open_vault(false)?;
    let (id, handle) = masked_record(&vault, &owner)?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert!(
        holds(&stored(&vault, &id)?, TOKEN.as_bytes()),
        "the ruling stands here"
    );
    let carried = carried_revokes(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "FIXTURE: the revoke is carried: {carried:?}"
    );
    assert_eq!(carried[0].0, None, "no data key, no screen");

    // Where the ruling is not known, the door masks as before (fail closed).
    forget_found_keys_of(&vault, id)?;
    vault.run_pending_owner_work(|| true)?;
    put(&vault, &id, 2, &body())?;
    assert!(
        !holds(&stored(&vault, &id)?, TOKEN.as_bytes()),
        "with no screen, the value is masked again"
    );
    Ok(())
}
