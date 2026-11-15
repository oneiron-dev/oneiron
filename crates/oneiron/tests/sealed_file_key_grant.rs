//! REVIEW-7708 P1 (ARCH-0069 #binary-secrets): a file the write door sealed
//! whole goes to the owner only. Past the seal budget the door marks a
//! file's first keys and seals the rest whole; those marked keys open no
//! agent's grant, since a granted read is served the stored bytes whole,
//! the hit no mark places among them.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test sealed_file_key_grant`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::secret_custody::SecretSight;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::sealed_file_grant;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A vault with the owner's scan switch at its default (on), a device
/// keystore and a serving install profile, as `secret_scan_seal_file.rs`
/// opens it.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"sealed file key grant host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault))
}

fn put_asset(vault: &Vault, body: &[u8]) -> oneiron::Result<EntityId> {
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()?;
    Ok(id)
}

/// A provider token under a credential name, told apart by `at`; as a
/// file's byte values only the door's whole read finds it.
fn token(at: usize) -> Vec<u8> {
    format!("TOKEN=ghp_{at:02}23456789abcdefghijklmnopqrstuvwxyz").into_bytes()
}

/// The control: a file whose one hit the door marks as a key asks one key
/// group of an agent's read, which a grant can answer.
#[test]
fn a_marked_file_asks_one_key_group() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let body = serde_json::to_vec(&serde_json::json!({ "notes": token(0) }))?;
    let id = put_asset(&vault, &body)?;
    let stored = vault.get(&id)?.ok_or("the file is stored")?;
    assert_eq!(
        sealed_file_grant::marked_key_groups(&vault, &stored)?,
        Some(1),
        "the marked key makes one group"
    );
    Ok(())
}

/// 65 tokens as byte values: the door marks the seal budget's worth and
/// seals the file whole for the last one. A masked reader gets none of it,
/// and its marked keys open no grant. Before, they made one grantable
/// group, and a granted read was served the stored bytes, the last token
/// with them.
#[test]
fn a_file_sealed_past_the_seal_budget_opens_no_key_grant() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let tokens: Vec<Vec<u8>> = (0..65).map(token).collect();
    let body = serde_json::to_vec(&serde_json::json!({ "notes": tokens }))?;
    let id = put_asset(&vault, &body)
        .unwrap_or_else(|error| panic!("a file of many hits is stored: {error:?}"));
    let stored = vault.get(&id)?.ok_or("the file is stored")?;
    assert_eq!(stored, body, "the file keeps its bytes as written");
    let served = vault
        .sighted_asset_bytes(stored.clone(), SecretSight::Masked)
        .map(drop)
        .map_err(|error| error.kind());
    assert!(
        matches!(served, Err(ErrorKind::SealedFileWithheld)),
        "the file past the seal budget is sealed whole: {served:?}"
    );
    assert_eq!(
        sealed_file_grant::marked_key_groups(&vault, &stored)?,
        None,
        "no key grant reaches a file sealed whole"
    );
    Ok(())
}
