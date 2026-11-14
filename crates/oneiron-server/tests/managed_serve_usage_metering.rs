#![cfg(oneiron_test_support)]
//! A managed start binds its hosted vault's usage meter before any worker
//! starts (census L8-12; oneiron/runtime.md #provider-health: "the trusted
//! host binds before work starts"): to the payer of the tenancy the
//! supervisor started the vault under, as a 32-byte id in lowercase hex, and
//! to the authority log's vault id. RULING HOSTED-BILLING-OWNER = A (14 Nov):
//! an account vault meters for its owner; an organization's shared vault and
//! each member vault it started meter for the organization (ARCH-0043 :108,
//! RD-28: "The org account pays"). A vault whose authority log has no genesis
//! yet still serves, unmetered.
//!
//! Red on main: the managed start builds its server with no meter bind
//! (`managed/state_serve/coordinator.rs`), so `vault_usage()` stays `None`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test managed_serve_usage_metering`.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::{Vault, VaultConfig};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::build_server::bind_managed_usage_metering;
use oneiron_vault_contract::tenancy::VaultTenancy;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The account that owns an account vault, the organization, and one of its
/// members, as the supervisor's argv names them.
const OWNER: [u8; 32] = [0x11; 32];
const ORGANIZATION: [u8; 32] = [0x22; 32];
const MEMBER: [u8; 32] = [0x33; 32];

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

/// A vault at `dir` whose authority log has its genesis: this install's
/// machines provisioned, its live profile enrolled and its host root logged.
fn rooted_vault(dir: &Path) -> TestResult<Arc<Vault>> {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_host_root_slip(&issuer)?;
    Ok(vault)
}

#[test]
fn a_managed_start_meters_usage_for_the_tenancy_payer() -> TestResult {
    on_engine_stack(managed_start_meters_usage_for_the_tenancy_payer)
}

async fn managed_start_meters_usage_for_the_tenancy_payer() -> TestResult {
    let tenancies = [
        (
            "an account vault",
            VaultTenancy::Account { owner: OWNER },
            OWNER,
        ),
        (
            "an organization's shared vault",
            VaultTenancy::OrganizationShared {
                organization: ORGANIZATION,
            },
            ORGANIZATION,
        ),
        (
            "a member vault the organization started",
            VaultTenancy::OrganizationMember {
                organization: ORGANIZATION,
                member: MEMBER,
            },
            ORGANIZATION,
        ),
    ];
    for (label, tenancy, payer) in tenancies {
        let dir = tempfile::tempdir()?;
        let vault = rooted_vault(dir.path())?;
        let vault_id = vault
            .authority_fold()?
            .vault_id
            .ok_or("the rooted vault's authority log has a genesis")?;
        let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default())?;
        assert!(
            server.vault_usage().is_none(),
            "{label}: a built server is unmetered until its start binds the meter"
        );

        bind_managed_usage_metering(&server, tenancy);

        let usage = server
            .vault_usage()
            .ok_or_else(|| format!("{label}: the managed start binds the vault's usage meter"))?;
        assert_eq!(
            usage.owner(),
            hex(&payer),
            "{label}: the meter names the tenancy's payer"
        );
        assert_eq!(
            usage.vault_id(),
            hex(&vault_id),
            "{label}: the meter's vault is the authority log's vault id"
        );
    }
    Ok(())
}

#[test]
fn a_managed_vault_with_no_genesis_serves_unmetered() -> TestResult {
    on_engine_stack(managed_vault_with_no_genesis_serves_unmetered)
}

async fn managed_vault_with_no_genesis_serves_unmetered() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default())?;
    assert!(
        vault.authority_fold()?.vault_id.is_none(),
        "a fresh vault built with no auth secret has no genesis"
    );

    bind_managed_usage_metering(&server, VaultTenancy::Account { owner: OWNER });

    assert!(
        server.vault_usage().is_none(),
        "with no genesis there is no vault id to meter under; the start goes on unmetered"
    );
    Ok(())
}
