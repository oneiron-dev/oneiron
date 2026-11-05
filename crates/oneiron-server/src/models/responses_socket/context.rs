//! One server's Responses state (FIX 9516): the vault its stored chains are
//! kept in and the owner's `store` switch (OF-602), held by each Responses
//! socket pool its model runtime builds and by nothing process-wide. Two
//! vault servers in one process keep apart: each reads and writes its own
//! chains, and only its own owner's setting asks its providers to keep a
//! response. Unbound, a context keeps no chain and asks for no retention.
//! Entry: `ResponsesContext::bind`.
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// The owner's `store` switch, off until the vault's setting is read.
    store: AtomicBool,
}

impl ResponsesContext {
    /// Binds this server's `vault` and its owner's `store` setting as read
    /// at start-up.
    pub(crate) fn bind(&self, vault: &Arc<Vault>, store: bool) {
        *self
            .held
            .vault
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(vault));
        self.set_store(store);
    }

    /// Sets whether each Responses turn from here on asks its provider to
    /// keep the response: this server's owner changed the setting.
    pub(crate) fn set_store(&self, on: bool) {
        self.held.store.store(on, Ordering::Relaxed);
    }

    /// Whether this server's owner keeps responses at the provider.
    pub(super) fn store(&self) -> bool {
        self.held.store.load(Ordering::Relaxed)
    }

    /// The vault this server keeps its stored chains in, while it is open.
    pub(super) fn chain_vault(&self) -> Option<Arc<Vault>> {
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
