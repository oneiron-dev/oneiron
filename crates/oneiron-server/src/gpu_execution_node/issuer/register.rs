//! Where the `vault_machine` backend may exist (pass 33, 8.1 and 8.7).
//!
//! - Only in a vault its owner operates: a managed (hosted) server never registers it (owner
//!   ruling, 24 Nov: hosted customers never run on the owner's machines).
//! - Only on the one issuer: the install whose MACHINE is `[gpu_jobs.vault_machine] issuer`
//!   (R5-ISSUER-IDENTITY = A). Each allocation generation has one issuing machine, so a start on
//!   any other replica answers `not_the_issuer { issuer }` at the start gate, before any
//!   reservation. The node's own `issuers` list stays the hard check.
//!
//! The issuer is read through one function, [`issuer_machine`], which the later row that moves
//! the issuer as an owner act replaces.
use std::sync::Arc;
#[cfg(feature = "mesh")]
use std::time::Duration;

use oneiron::EntityId;
use oneiron::machine_signature::MachineSignatures;

use super::VAULT_MACHINE_BACKEND;
use super::connector::VaultMachineConnector;
use crate::server::SyncServer;

/// A start on a replica that is not the vault's issuer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("this server is not the vault's issuer of vault machine jobs")]
pub struct NotTheIssuer {
    /// The issuer the setting names; `None` when it names none.
    pub issuer: Option<EntityId>,
}

impl NotTheIssuer {
    /// The refusal's name on door 7.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "not_the_issuer"
    }
}

/// Why the backend was not registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultMachineNotRegistered {
    #[error("[gpu_jobs.vault_machine] is not enabled")]
    Disabled,
    /// A managed (hosted) server never runs jobs on the owner's machines.
    #[error("a managed server never registers the vault_machine backend")]
    Managed,
    #[error("this install has no MACHINE id yet")]
    NoMachineId,
    #[error("this install is not the vault's issuer of vault machine jobs")]
    NotTheIssuer {
        issuer: Option<EntityId>,
        local: EntityId,
    },
    /// The connector's calls run on the serving runtime, and none is running.
    #[error("no tokio runtime to run the job protocol calls on")]
    NoRuntime,
    /// The server is built without its mesh listener.
    #[error("this server is built without the mesh")]
    NoMesh,
    #[error("the vault could not be read: {0}")]
    Store(String),
}

/// The vault's issuer of vault machine jobs: the one place it is read.
#[must_use]
pub fn issuer_machine(server: &SyncServer) -> Option<EntityId> {
    server.config.gpu_jobs.vault_machine.issuer
}

/// The start gate's one-issuer check (call 1 of the gate, before the reservation): `Ok` for
/// any backend other than `vault_machine`, and on the issuer.
///
/// # Errors
///
/// [`NotTheIssuer`] on any other install, and wherever no issuer is set.
pub fn not_the_issuer(server: &SyncServer, backend: &str) -> Result<(), NotTheIssuer> {
    if backend != VAULT_MACHINE_BACKEND {
        return Ok(());
    }
    let issuer = issuer_machine(server);
    let local = server
        .vault()
        .local_machine()
        .ok()
        .flatten()
        .map(|local| local.id);
    match (issuer, local) {
        (Some(issuer), Some(local)) if issuer == local => Ok(()),
        _ => Err(NotTheIssuer { issuer }),
    }
}

/// The `vault_machine` backend of `server`, signing as `signer`: built only when the section is
/// enabled, the server is not managed, and this install is the issuer.
///
/// # Errors
///
/// [`VaultMachineNotRegistered`] says why it was not built.
pub fn vault_machine_backend(
    server: &Arc<SyncServer>,
    signer: Arc<dyn MachineSignatures>,
) -> Result<Arc<VaultMachineConnector>, VaultMachineNotRegistered> {
    let settings = &server.config.gpu_jobs.vault_machine;
    if !settings.enabled {
        return Err(VaultMachineNotRegistered::Disabled);
    }
    if server.managed_issuer.is_some() {
        return Err(VaultMachineNotRegistered::Managed);
    }
    let local = server
        .vault()
        .local_machine()
        .map_err(|error| VaultMachineNotRegistered::Store(error.to_string()))?
        .ok_or(VaultMachineNotRegistered::NoMachineId)?
        .id;
    let issuer = issuer_machine(server);
    if issuer != Some(local) {
        return Err(VaultMachineNotRegistered::NotTheIssuer { issuer, local });
    }
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| VaultMachineNotRegistered::NoRuntime)?;
    mesh_backend(server, signer, local, runtime)
}

#[cfg(feature = "mesh")]
fn mesh_backend(
    server: &Arc<SyncServer>,
    signer: Arc<dyn MachineSignatures>,
    local: EntityId,
    runtime: tokio::runtime::Handle,
) -> Result<Arc<VaultMachineConnector>, VaultMachineNotRegistered> {
    let settings = server.config.gpu_jobs.vault_machine.clone();
    let client: Arc<dyn super::node_client::JobNodeClient> =
        Arc::new(super::node_client::MeshJobNodeClient::new(
            Arc::downgrade(server),
            runtime,
            Duration::from_secs(settings.call_timeout_secs),
        ));
    let clock: Arc<dyn super::clock::IssuerClock> = Arc::new(super::clock::SystemIssuerClock);
    // Row R4: a key a node holds that this issuer never dispatched gets its JOB_ORPHAN row and
    // its stop (pass 33, 8.5).
    let orphans = Arc::new(super::orphans::JobOrphanKeys {
        vault: Arc::clone(server.vault()),
        issuer: local,
        client: Arc::clone(&client),
        signer: Arc::clone(&signer),
        clock: Arc::clone(&clock),
        ledger: Arc::new(super::orphans::LoggedUnattributedLedger),
    });
    Ok(Arc::new(VaultMachineConnector::new(
        super::connector::VaultMachineParts {
            vault: Arc::clone(server.vault()),
            issuer: local,
            client,
            signer,
            clock,
            orphans,
            settings,
        },
    )))
}

#[cfg(not(feature = "mesh"))]
fn mesh_backend(
    _server: &Arc<SyncServer>,
    _signer: Arc<dyn MachineSignatures>,
    _local: EntityId,
    _runtime: tokio::runtime::Handle,
) -> Result<Arc<VaultMachineConnector>, VaultMachineNotRegistered> {
    Err(VaultMachineNotRegistered::NoMesh)
}

/// Registers [`vault_machine_backend`] in `server`'s backend registry as `vault_machine`.
///
/// # Errors
///
/// As [`vault_machine_backend`]; nothing is registered then.
pub fn register_vault_machine(
    server: &Arc<SyncServer>,
    signer: Arc<dyn MachineSignatures>,
) -> Result<(), VaultMachineNotRegistered> {
    let backend = vault_machine_backend(server, signer)?;
    server
        .gpu_jobs
        .register_backend(VAULT_MACHINE_BACKEND, backend);
    Ok(())
}

/// Server start's registration of the `vault_machine` backend, before the GPU job worker starts
/// (R6 runbook B2). The vault signs as this install's machine (`impl MachineSignatures for
/// Vault`). A disabled section registers nothing and logs nothing. Any other refusal is one warn
/// line, and the server serves on: a start on the backend's offer then answers
/// `gpu_jobs.no_backend` before any reservation.
///
/// # Errors
///
/// As [`register_vault_machine`]; nothing is registered then.
pub fn register_vault_machine_at_start(
    server: &Arc<SyncServer>,
) -> Result<(), VaultMachineNotRegistered> {
    let signer: Arc<dyn MachineSignatures> = Arc::<oneiron::Vault>::clone(server.vault());
    let registered = register_vault_machine(server, signer);
    match &registered {
        Ok(()) => tracing::info!(backend = VAULT_MACHINE_BACKEND, "GPU backend registered"),
        Err(VaultMachineNotRegistered::Disabled) => {}
        Err(refusal) => tracing::warn!(
            backend = VAULT_MACHINE_BACKEND,
            refusal = %refusal,
            "GPU backend not registered"
        ),
    }
    registered
}
