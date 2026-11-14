//! Fix list row 15412, review #7537 P1: received mail lands its MESSAGE
//! under author `counterparty`, and an own machine's sync of that row still
//! replays on the owner's other devices. The own-device replay door admits a
//! `counterparty` body where it admits the same import as `user`: on a
//! personal vault whose owner is live, from a machine on its roster. A
//! machine off the roster, and a `system` body, stay refused.
//!
//! Red on the PR's base: the door admits only `user` and `companion` bodies,
//! so the counterparty row is refused as a replay and quarantined.
//!
//! Reaches the crate-private door through
//! `oneiron::test_doors::own_device_message_replay`, so it runs only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test own_device_counterparty_replay`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::test_doors::own_device_message_replay::{message_body, own_machine_message_replay};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh personal vault opened owned, rooted under the host, with this
/// install enrolled as the owner's own machine: the roster the own-device
/// door reads. Returns the vault and this install's machine.
fn personal_vault_with_own_machine(
    directory: &std::path::Path,
) -> Result<(Vault, EntityId), Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"own device counterparty replay test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))?;
    let machine = vault
        .local_machine()?
        .expect("FIXTURE: this install has a machine once it is profiled")
        .id;
    Ok((vault, machine))
}

#[test]
fn own_machine_counterparty_message_replays_on_a_personal_vault() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (vault, machine) = personal_vault_with_own_machine(directory.path())?;

    // Guard: the fixture's machine stands on the roster, so the owner's own
    // words replay from it, as before FIX 15412.
    let user = message_body("user", "I will send the contract tomorrow.")?;
    own_machine_message_replay(&vault, machine, &user)
        .expect("FIXTURE: an own machine's user MESSAGE replays");

    let received = message_body("counterparty", "Can we move the review to Thursday?")?;
    own_machine_message_replay(&vault, machine, &received).map_err(|error| {
        format!("an own machine's received-mail MESSAGE is refused as a replay: {error}")
    })?;

    let stranger = EntityId::now();
    assert!(
        own_machine_message_replay(&vault, stranger, &received).is_err(),
        "a machine off the roster does not replay a counterparty MESSAGE"
    );
    let system = message_body("system", "engine notice")?;
    assert!(
        own_machine_message_replay(&vault, machine, &system).is_err(),
        "a system MESSAGE is never a replay's"
    );
    Ok(())
}
