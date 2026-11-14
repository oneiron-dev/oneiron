//! Engine RULING 14 Nov 08:35 (NEXT-ROW-15 = A, L6-03-RULED-SCREEN-LOCAL): a
//! found key the owner ruled no secret, or kept as text, stays text on all
//! of the owner's machines. The ruling's revoke carries a value-free screen
//! of the ruled value to each of them, and the write door reads that screen
//! before it masks. While the vault key is locked, a ruling waits, because
//! it would not reach the owner's other machines.
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

fn holds_token(bytes: &[u8]) -> bool {
    bytes
        .windows(TOKEN.len())
        .any(|window| window == TOKEN.as_bytes())
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

/// A record whose token the mask lifted, and that key's handle.
fn masked_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    put(vault, &id, 1, &body())?;
    assert!(
        !holds_token(&stored(vault, &id)?),
        "FIXTURE: the mask lifted the token"
    );
    let handle = found_handle(vault, owner, &id)?;
    Ok((id, handle))
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
