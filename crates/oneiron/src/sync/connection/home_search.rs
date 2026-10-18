//! The home search this device's query doors reach through its own sync
//! connection (OF-534): a search an opened machine cannot answer locally goes
//! to the home node (ARCH-0023b, partial sync).

use std::sync::{Arc, PoisonError};

use tokio::sync::watch;

use crate::Vault;
use crate::sync::client::{ResidenceSearch, SyncClientConfig, SyncResidenceMode};
use crate::sync::transport::TransportError;

/// What an own-device sync connection lends the vault's query doors: the
/// client config it dials the home with and the mode the machine runs now.
/// The connection holds it and the vault keeps a `Weak`, so a dropped
/// connection routes nothing.
pub struct HomeSearch {
    vault: Arc<Vault>,
    config: SyncClientConfig,
    mode: watch::Receiver<SyncResidenceMode>,
}

impl HomeSearch {
    /// Lends `vault`'s query doors this connection's home search. The last
    /// own-device connection over the vault wins.
    pub(super) fn attach(
        vault: &Arc<Vault>,
        config: SyncClientConfig,
        mode: watch::Receiver<SyncResidenceMode>,
    ) -> Arc<Self> {
        let search = Arc::new(Self {
            vault: Arc::clone(vault),
            config,
            mode,
        });
        *vault
            .home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(&search);
        search
    }

    /// The home's hits when it is reachable, else this device's opened items
    /// alone, marked local-only and incomplete. A page larger than the home
    /// answers at once asks for the home's cap.
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, None).await
    }

    /// [`Self::search`] for a caller narrower than this device's owner
    /// (FIX 2907): the home judges `caller`'s own holder proof, which this
    /// install signs over with the request, and answers within the caller's
    /// reach and this device's selector. No home, or a refusal, is no home
    /// hits, never this device's own unscoped scan.
    pub async fn search_for(
        &self,
        query: &str,
        limit: usize,
        caller: &crate::authority::ForwardedCallerProof,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, Some(caller)).await
    }

    async fn ask(
        &self,
        query: &str,
        limit: usize,
        caller: Option<&crate::authority::ForwardedCallerProof>,
    ) -> Result<ResidenceSearch, TransportError> {
        let limit = match self.vault.residence_operation_budgets() {
            Ok(Some(budgets)) => limit.min(budgets.search_limit),
            _ => limit,
        };
        let mut config = self.config.clone();
        config.residence_mode = *self.mode.borrow();
        crate::sync::client::search_resident(&self.vault, &config, query, limit, caller).await
    }
}

impl Vault {
    /// This device's home search, while it syncs only what it opened and an
    /// own-device sync connection over it lives. `None` on a machine that
    /// holds every window, or with no such connection: its local search is
    /// the whole answer.
    #[must_use]
    pub fn home_search(&self) -> Option<Arc<HomeSearch>> {
        let search = self
            .home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade()?;
        let opened = *search.mode.borrow() == SyncResidenceMode::Opened;
        opened.then_some(search)
    }
}
