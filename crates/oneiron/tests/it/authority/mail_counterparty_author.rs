//! Fix list row 15412: received mail speaks as a counterparty. A message the
//! mailbox received lands its MESSAGE under author `counterparty`, not as the
//! vault's user; a message the mailbox sent stays `user`.
//!
//! Red on origin/main: the mail landing hard-codes `WitnessAuthor::User` for
//! every message, so the received message's MESSAGE names `user`.
//!
//! Reaches the crate-private sync step through the test door
//! `oneiron::test_doors::mail_counterparty`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mail_counterparty_author`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::test_doors::mail_counterparty::landed_message_authors;
use oneiron::{Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh vault opened owned, with the host's start a self-hosted server
/// makes: the process keystore, the vault rooted under the host, and this
/// install profiled.
fn fresh_vault(directory: &std::path::Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"mail counterparty author test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok(vault)
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

#[test]
fn imported_mail_lands_counterparty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let authors = landed_message_authors(&vault, now_sec(), false)?;
    assert!(
        authors.iter().all(|author| author == "counterparty"),
        "a received message's MESSAGE rows name {authors:?}"
    );
    Ok(())
}

#[test]
fn mail_the_mailbox_sent_lands_as_user() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let authors = landed_message_authors(&vault, now_sec(), true)?;
    assert!(
        authors.iter().all(|author| author == "user"),
        "a sent message's MESSAGE rows name {authors:?}"
    );
    Ok(())
}
