//! This server's check that a managed vault's attested owner is its live
//! owner, which his queued work runs under (FIX 11090): his queued Continue
//! and Retry, the turn programs he arms and the wakes his landed turns owe
//! them. Each judgment builds him again as the owner the vault records as
//! live now ([`crate::auth::CoreAuth::for_attested_owner`]), never from a
//! header or the host's root, and answers a fresh owner proof the engine
//! revalidates in its own transaction and drops. Nothing is minted or kept
//! for him.

use std::sync::{Arc, Weak};

use oneiron::EntityId;
use oneiron::authority::{ManagedOwnerCheck, ManagedOwnerCheckError};
use oneiron::consent::AuthenticatedOwner;
use oneiron::runtime_hooks::verb::VerbAskRefusal;

use crate::server::SyncServer;

/// The managed-owner check of this server, which it holds weakly, as its
/// code consent host does.
pub(crate) struct ServerManagedOwnerCheck {
    server: Weak<SyncServer>,
}

impl ServerManagedOwnerCheck {
    /// Installs this server's check on its vault, before any worker takes
    /// up queued work. A second install does nothing.
    pub(crate) fn install(server: &Arc<SyncServer>) {
        server.vault().install_managed_owner_check(Arc::new(Self {
            server: Arc::downgrade(server),
        }));
    }
}

impl ManagedOwnerCheck for ServerManagedOwnerCheck {
    /// `holder` as the vault's live owner now: refused as not live only when
    /// the vault reads and records someone else, or no one, as its live
    /// owner. A stopped server, a vault no supervisor manages now, or
    /// standing that does not read is unavailable, never his refusal.
    fn require_live(&self, holder: EntityId) -> Result<AuthenticatedOwner, ManagedOwnerCheckError> {
        let server = self
            .server
            .upgrade()
            .ok_or(ManagedOwnerCheckError::Unavailable)?;
        crate::code_consent_host::attested_owner_standing(&server, holder).map_err(|refusal| {
            if refusal == VerbAskRefusal::OwnerNotLive {
                ManagedOwnerCheckError::OwnerNotLive
            } else {
                ManagedOwnerCheckError::Unavailable
            }
        })?;
        match crate::api::managed_owner_proof(&server, holder) {
            Ok(Some(owner)) => Ok(owner),
            Ok(None) => Err(ManagedOwnerCheckError::OwnerNotLive),
            Err(_) => Err(ManagedOwnerCheckError::Unavailable),
        }
    }
}
