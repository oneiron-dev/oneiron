//! A hosted device vault that an embedded handle attaches to, for the
//! integration tests of the owner-device answer (UC-05 PR 2b,
//! `oneiron-remote`'s `tests/owner_device_answer.rs`): the keys sit in a
//! memory keystore in place of the platform's, and the owner enrols this
//! install's owner signing key on demand. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::sync::Arc;

use crate::authority::{ActAuthority, ActSurface, HostSlipIssuer, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

/// A hosted vault on a device, opened as an embedded host opens it, with
/// its embedded owner.
pub struct OwnerDeviceVault {
    /// The vault, for the embedded handle a test attaches.
    pub vault: Arc<Vault>,
    /// The vault's embedded owner, the actor that handle binds.
    pub owner: EntityId,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
}

/// Opens a hosted device vault at `path` with its writer lease held, as
/// `OneironClient::open` opens one, but with a memory keystore in place of
/// the platform's: engine machines provisioned, this install profiled under
/// the host root and the embedded owner bound. This install holds no key the
/// authority fold trusts as the owner's: the host root is in the host's
/// custody, and no device owner key is enrolled.
///
/// # Errors
///
/// The vault's.
pub fn open_owner_device_vault(path: &std::path::Path) -> Result<OwnerDeviceVault> {
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(path, config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = crate::test_fixtures::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, proof) = super::label_writers::embedded_owner(&vault)?;
    Ok(OwnerDeviceVault {
        vault: Arc::new(vault),
        owner,
        issuer,
        proof,
    })
}

impl OwnerDeviceVault {
    /// The owner enrols this install's owner signing key: from then on the
    /// handle holds a key the authority fold trusts as the owner's.
    ///
    /// # Errors
    ///
    /// The enrolment's.
    pub fn enrol_owner_key(&self) -> Result<()> {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .map(drop)
    }
}
