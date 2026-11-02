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

use crate::auth::CoreAuth;
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
    /// `holder` as the vault's live owner now. [`CoreAuth::for_attested_owner`]
    /// is the gate; the cause of its answer is the vault's own typed verdict
    /// ([`oneiron::Vault::attested_owner_verdict`]), read before any API
    /// error mapping: not live when the vault records someone else or no
    /// one, or records him while his PERSON is merged, split or deleted. A
    /// stopped server, a vault no supervisor manages now, or standing that
    /// does not read is unavailable, never his refusal.
    fn require_live(&self, holder: EntityId) -> Result<AuthenticatedOwner, ManagedOwnerCheckError> {
        let server = self
            .server
            .upgrade()
            .ok_or(ManagedOwnerCheckError::Unavailable)?;
        let gate = CoreAuth::for_attested_owner(holder, &server);
        if server.managed_issuer.is_none() {
            return Err(ManagedOwnerCheckError::Unavailable);
        }
        match (gate, server.vault().attested_owner_verdict(holder)) {
            (Ok(_), verdict) => verdict,
            (Err(_), Err(refusal)) => Err(refusal),
            // The gate refused what a read now finds live: judged again later.
            (Err(_), Ok(_)) => Err(ManagedOwnerCheckError::Unavailable),
        }
    }
}
