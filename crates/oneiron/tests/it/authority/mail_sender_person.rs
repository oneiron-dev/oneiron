//! Fix list row 15412, slice 2: a received mail MESSAGE names the PERSON its
//! source says sent it. When the sender's mail party key names a live PERSON,
//! every stored MESSAGE of the landed message carries one `AuthoredBy` edge,
//! to that PERSON: the speaker, never a writer.
//!
//! Red on the PR's base (slice 1): an imported MESSAGE keeps no `AuthoredBy`
//! edge, so the landed MESSAGE names no one.
//!
//! Reaches the crate-private sync step through the test door
//! `oneiron::test_doors::mail_counterparty`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mail_sender_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::test_doors::mail_counterparty::land_from_known_sender;
use oneiron::{Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh vault opened owned, with the host's start a self-hosted server
/// makes: the process keystore, the vault rooted under the host, and this
/// install profiled.
fn fresh_vault(directory: &std::path::Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"mail sender person test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok(vault)
}

#[test]
fn received_mail_names_sender_person() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let landed = land_from_known_sender(&vault, now_sec)?;
    assert!(
        landed
            .authored_by
            .iter()
            .all(|targets| targets.as_slice() == [landed.sender]),
        "each landed MESSAGE names {:?}, not the sender {}",
        landed.authored_by,
        landed.sender.to_hex()
    );
    Ok(())
}
