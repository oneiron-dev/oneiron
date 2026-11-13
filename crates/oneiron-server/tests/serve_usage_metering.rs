#![cfg(oneiron_test_support)]
//! A self-hosted serve binds its usage meter before any work starts (FIX
//! 11011, FIX 22868): to the vault's own billing owner, its embedded owner,
//! and to the authority log's vault id. A vault whose authority log has no
//! genesis yet still serves, unmetered.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test serve_usage_metering`.

use std::future::Future;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::test_doors::served_server::build_served_server;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn a_self_hosted_serve_meters_usage_for_the_vault_owner() -> TestResult {
    on_engine_stack(self_hosted_serve_meters_usage)
}

async fn self_hosted_serve_meters_usage() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, _owner_proof) = embedded_owner(&vault)?;
    vault.ensure_host_root_slip(&issuer)?;
    assert_eq!(
        vault.privacy_posture(),
        HostingPrivacyPosture::SelfHostLocal,
        "a device vault is self-hosted"
    );
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or("the rooted vault's authority log has a genesis")?;

    let server = build_served_server(
        Arc::clone(&vault),
        dir.path(),
        Some("serve-usage-metering".into()),
    )
    .await?;

    let usage = server
        .vault_usage()
        .ok_or("serve binds the vault's usage meter before any work starts")?;
    assert_eq!(
        usage.owner(),
        owner.to_hex(),
        "the vault's own billing owner is its embedded owner"
    );
    assert_eq!(
        usage.vault_id(),
        hex(&vault_id),
        "the meter's vault is the authority log's vault id"
    );
    Ok(())
}

#[test]
fn a_vault_with_no_genesis_serves_unmetered() -> TestResult {
    on_engine_stack(vault_with_no_genesis_serves_unmetered)
}

async fn vault_with_no_genesis_serves_unmetered() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));

    // No auth secret: serve does not root a fresh vault.
    let server = build_served_server(Arc::clone(&vault), dir.path(), None).await?;

    assert!(
        vault.authority_fold()?.vault_id.is_none(),
        "a fresh vault served with no auth secret has no genesis"
    );
    assert!(
        server.vault_usage().is_none(),
        "with no genesis there is no vault id to meter under; serve goes on unmetered"
    );
    Ok(())
}
