//! The owner anchor's appointment of a successor root key (row
//! OWNER-ANCHOR-ROOT-RECOVERY, PLAN v3 section 7): not built yet, so the door
//! refuses.

use super::{KitConfirmation, RecoveryRootSeed, refused};
use crate::Vault;
use crate::authority::RootAppointmentReceipt;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;

/// No appointment door is built yet. Nothing was written.
const APPOINTMENT_UNAVAILABLE: &str = "no root appointment door is built yet";

impl Vault {
    /// The owner's appointment of a successor root key: refused until it is
    /// built.
    ///
    /// # Errors
    /// [`crate::error::SecretError::WorldKeyRefused`], always.
    pub fn appoint_owner_root(
        &self,
        _owner: &AuthenticatedOwner,
        _seed: &RecoveryRootSeed,
        _confirm: Option<KitConfirmation>,
    ) -> Result<RootAppointmentReceipt> {
        Err(refused(APPOINTMENT_UNAVAILABLE))
    }
}
