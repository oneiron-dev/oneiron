//! One server's Responses state (FIX 9516): the vault its stored chains are
//! kept in, whose owner's `store` switch (OF-602, the key
//! `models.responses_store`) each turn reads, held by each Responses socket
//! pool its model runtime builds and by nothing process-wide. Two vault
//! servers in one process keep apart: each reads and writes its own chains,
//! and only its own owner's setting asks its providers to keep a response.
//! Unbound, a context keeps no chain and asks for no retention.
//! Entry: `ResponsesContext::bind`.
use std::sync::{Arc, PoisonError, RwLock, Weak};

use oneiron::Vault;

use crate::models::ModelRuntime;

/// One model runtime's Responses state. A clone shares it: the runtime's,
/// and each of its providers' socket pools.
#[derive(Clone, Default)]
pub(crate) struct ResponsesContext {
    held: Arc<HeldContext>,
}

#[derive(Default)]
struct HeldContext {
    /// The vault this server keeps its stored chains in, once bound.
    vault: RwLock<Option<Weak<Vault>>>,
}

impl ResponsesContext {
    /// Binds this server's `vault`: its stored chains, and its owner's
    /// `store` setting.
    pub(crate) fn bind(&self, vault: &Arc<Vault>) {
        *self
            .held
            .vault
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(vault));
    }

    /// Whether this server's owner keeps responses at the provider, read from
    /// the bound vault at each turn, so a change through any door holds from
    /// the next turn. Unbound or unreadable, off.
    pub(crate) fn store(&self) -> bool {
        self.chain_vault()
            .is_some_and(|vault| vault.responses_store().unwrap_or(false))
    }

    /// The vault this server keeps its stored chains in, while it is open.
    pub(crate) fn chain_vault(&self) -> Option<Arc<Vault>> {
        self.held
            .vault
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?
            .upgrade()
    }
}

impl ModelRuntime {
    /// This runtime's Responses state, which its server binds to its vault
    /// and its owner's setting.
    pub(crate) fn responses_context(&self) -> &ResponsesContext {
        &self.responses
    }
}
