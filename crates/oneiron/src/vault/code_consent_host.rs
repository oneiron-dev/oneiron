//! The one host seam a code consent wait needs: the served host that drives
//! an already-answered effect through its own transport. It is no second
//! authoriser: it cannot make, change or replace an answer, and the effect's
//! own gate still decides in the engine.

use std::sync::Arc;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The host that drives an answered code consent wait's effect. A served
/// host installs one per open vault ([`Vault::install_code_consent_effect_host`]),
/// whatever hooks or models it serves: it checks the original caller's
/// instrument the way only it can (its current scope), then runs the effect
/// through [`Vault::resume_answered_code_consent_wait`]. It never runs under
/// an LMDB writer.
pub trait CodeConsentEffectHost: Send + Sync {
    /// Drives `wait_id`'s answered effect once. A failure leaves the wait
    /// settling, for the host's next pass.
    ///
    /// # Errors
    ///
    /// The host's or the effect's own failure.
    fn resume_answered(&self, vault: &Vault, wait_id: EntityId) -> Result<()>;
}

impl Vault {
    /// Installs the host that drives answered code consent effects on this
    /// vault handle. A second install does nothing. Without one, a new
    /// approving answer is refused before it lands.
    pub fn install_code_consent_effect_host(&self, host: Arc<dyn CodeConsentEffectHost>) {
        let _ = self.code_consent_host.set(host);
    }

    /// The installed host, if any.
    pub(crate) fn code_consent_effect_host(&self) -> Option<Arc<dyn CodeConsentEffectHost>> {
        self.code_consent_host.get().cloned()
    }
}
