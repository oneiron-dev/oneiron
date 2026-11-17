//! The vendor sandboxes this server serves (L8-43): the backends a vault's
//! finite Foreign and Untrusted runs take once the owner switched them to a
//! vendor. [`ServedSandboxBackends`] forwards our own backends to the build's
//! compiled set, and answers `vendor` with that vendor's batch backend
//! (`VendorBatchBackend`) only while the owner's switch names the vendor and
//! the custody secret holding the owner's key for it. Without either, it
//! answers none, and the run is refused as the vendor unavailable: ours never
//! runs in its place (L8-43-SWITCH = A).
//!
//! Daytona, E2B, Modal and boat are the vendors served so far (L8-43-VENDORS = A:
//! Daytona, then E2B, Modal, boat, InstaBox). A vendor's batch backend runs
//! on Linux only, as `VendorBatchBackend` does.

#[cfg(target_os = "linux")]
mod boat;
#[cfg(target_os = "linux")]
mod daytona;
#[cfg(target_os = "linux")]
mod e2b;
#[cfg(target_os = "linux")]
mod grpc;
#[cfg(target_os = "linux")]
mod modal;
#[cfg(target_os = "linux")]
mod protobuf;
#[cfg(target_os = "linux")]
mod vendor_http;

use std::path::PathBuf;
use std::sync::{Arc, Weak};

use oneiron::Vault;
use oneiron::code_sandbox::microvm::{MicroVmBackend, SandboxBackends};
use oneiron::code_sandbox::{SandboxProvider, SandboxVendor};
use oneiron_agent_runtime::code_sandbox::CompiledSandboxBackends;

#[cfg(target_os = "linux")]
pub(crate) use boat::BoatEndpoints;
#[cfg(target_os = "linux")]
pub(crate) use daytona::DaytonaEndpoints;
#[cfg(target_os = "linux")]
pub(crate) use e2b::E2bEndpoints;
#[cfg(target_os = "linux")]
pub(crate) use modal::ModalEndpoints;

/// The backends of one vault on this server: ours as compiled, and the
/// vendors this server serves. It holds its vault weakly, since the vault
/// holds it.
pub(crate) struct ServedSandboxBackends {
    compiled: CompiledSandboxBackends,
    vault: Weak<Vault>,
    #[cfg(target_os = "linux")]
    daytona: DaytonaEndpoints,
    #[cfg(target_os = "linux")]
    e2b: E2bEndpoints,
    #[cfg(target_os = "linux")]
    modal: ModalEndpoints,
    #[cfg(target_os = "linux")]
    boat: BoatEndpoints,
    /// Where each vendor run keeps its private scratch.
    #[cfg(target_os = "linux")]
    scratch_root: PathBuf,
}

impl ServedSandboxBackends {
    /// The backends of `vault`, reaching each vendor at its own API.
    pub(crate) fn new(vault: &Arc<Vault>) -> Self {
        Self {
            compiled: CompiledSandboxBackends,
            vault: Arc::downgrade(vault),
            #[cfg(target_os = "linux")]
            daytona: DaytonaEndpoints::default(),
            #[cfg(target_os = "linux")]
            e2b: E2bEndpoints::default(),
            #[cfg(target_os = "linux")]
            modal: ModalEndpoints::default(),
            #[cfg(target_os = "linux")]
            boat: BoatEndpoints::default(),
            #[cfg(target_os = "linux")]
            scratch_root: std::env::temp_dir().join("oneiron-vendor-sandbox"),
        }
    }

    /// The backends of `vault`, reaching Daytona at `daytona` and keeping
    /// each run's scratch under `scratch_root`.
    #[cfg(all(target_os = "linux", oneiron_test_support))]
    pub(crate) fn with_daytona(
        vault: &Arc<Vault>,
        daytona: DaytonaEndpoints,
        scratch_root: PathBuf,
    ) -> Self {
        Self {
            daytona,
            scratch_root,
            ..Self::new(vault)
        }
    }

    /// The backends of `vault`, reaching E2B at `e2b` and keeping each
    /// run's scratch under `scratch_root`.
    #[cfg(all(target_os = "linux", oneiron_test_support))]
    pub(crate) fn with_e2b(vault: &Arc<Vault>, e2b: E2bEndpoints, scratch_root: PathBuf) -> Self {
        Self {
            e2b,
            scratch_root,
            ..Self::new(vault)
        }
    }

    /// The backends of `vault`, reaching Modal's control API at `modal` and
    /// keeping each run's scratch under `scratch_root`.
    #[cfg(all(target_os = "linux", oneiron_test_support))]
    pub(crate) fn with_modal(
        vault: &Arc<Vault>,
        modal: ModalEndpoints,
        scratch_root: PathBuf,
    ) -> Self {
        Self {
            modal,
            scratch_root,
            ..Self::new(vault)
        }
    }

    /// The backends of `vault`, reaching boat's API at `boat` and keeping
    /// each run's scratch under `scratch_root`.
    #[cfg(all(target_os = "linux", oneiron_test_support))]
    pub(crate) fn with_boat(
        vault: &Arc<Vault>,
        boat: BoatEndpoints,
        scratch_root: PathBuf,
    ) -> Self {
        Self {
            boat,
            scratch_root,
            ..Self::new(vault)
        }
    }

    /// `vendor`'s batch backend on the owner's key named `key_name`.
    #[cfg(target_os = "linux")]
    fn vendor_backend(
        &self,
        vault: &Arc<Vault>,
        vendor: SandboxVendor,
        key_name: String,
    ) -> Option<Box<dyn MicroVmBackend>> {
        use oneiron_agent_runtime::code_sandbox::microvm::{
            VendorBatchBackend, VendorSandboxClient,
        };

        let client: Arc<dyn VendorSandboxClient> = match vendor {
            SandboxVendor::Daytona => Arc::new(daytona::DaytonaClient::new(
                Arc::downgrade(vault),
                key_name,
                self.daytona.clone(),
            )),
            SandboxVendor::E2b => Arc::new(e2b::E2bClient::new(
                Arc::downgrade(vault),
                key_name,
                self.e2b.clone(),
            )),
            SandboxVendor::Modal => Arc::new(modal::ModalClient::new(
                Arc::downgrade(vault),
                key_name,
                self.modal.clone(),
            )),
            SandboxVendor::Boat => Arc::new(boat::BoatClient::new(
                Arc::downgrade(vault),
                key_name,
                self.boat.clone(),
            )),
            SandboxVendor::Instabox => return None,
        };
        Some(Box::new(VendorBatchBackend::new(
            client,
            self.scratch_root.clone(),
        )))
    }

    /// No vendor's batch backend runs off Linux.
    #[cfg(not(target_os = "linux"))]
    fn vendor_backend(
        &self,
        _vault: &Arc<Vault>,
        _vendor: SandboxVendor,
        _key_name: String,
    ) -> Option<Box<dyn MicroVmBackend>> {
        None
    }
}

impl SandboxBackends for ServedSandboxBackends {
    fn firecracker(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.compiled.firecracker()
    }

    fn container(&self) -> Option<Box<dyn MicroVmBackend>> {
        self.compiled.container()
    }

    fn session_container(
        &self,
        runtime: PathBuf,
        image: &str,
    ) -> Option<oneiron::Result<Box<dyn MicroVmBackend>>> {
        self.compiled.session_container(runtime, image)
    }

    fn vendor(&self, vendor: SandboxVendor) -> Option<Box<dyn MicroVmBackend>> {
        let vault = self.vault.upgrade()?;
        let setting = match vault.sandbox_provider_setting() {
            Ok(setting) => setting,
            Err(error) => {
                tracing::warn!(%error, "sandbox provider switch unreadable");
                return None;
            }
        };
        if setting.provider != SandboxProvider::Vendor(vendor) {
            return None;
        }
        self.vendor_backend(&vault, vendor, setting.vendor_key?)
    }
}
