//! The home search this device's query doors reach through its own sync
//! connection (OF-534): a search an opened machine cannot answer locally goes
//! to the home node (ARCH-0023b, partial sync).

use std::sync::{Arc, PoisonError, Weak};

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

/// The vault's hold on its own sync connection's home search: the live
/// search, and the mode the last own-device connection that attached ran,
/// which the vault keeps once that connection drops (FIX 2905).
#[derive(Default)]
pub(crate) struct HomeSearchSlot {
    search: Weak<HomeSearch>,
    /// The mode the attached connection ran when it attached, or when it
    /// dropped; `None` until one attaches.
    mode: Option<SyncResidenceMode>,
}

/// What this device's own sync connection says of its residence (FIX 2905):
/// whether its local answers are the whole vault it may read.
pub enum DeviceResidence {
    /// The device holds every window it may read, or no own-device sync
    /// connection ever attached over the vault: its local answer is whole.
    HoldsEverything,
    /// The device syncs only what it opened. `search` is the live
    /// connection's home search; `None` once that connection dropped, when
    /// the home cannot be asked and a local answer is not the whole one.
    Opened {
        /// The live connection's home search, when one lives.
        search: Option<Arc<HomeSearch>>,
    },
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
        let mut slot = vault
            .home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        slot.search = Arc::downgrade(&search);
        slot.mode = Some(*search.mode.borrow());
        drop(slot);
        search
    }

    /// The home's hits when it is reachable, else this device's opened items
    /// alone, marked local-only and incomplete. More hits than the home
    /// answers at once come a page at a time (FIX 8865), each page within
    /// the residence RPC timeout and `due`, the caller's deadline: a drain
    /// that stops short keeps the home's pages, marked incomplete (FIX 9256).
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
        due: Option<std::time::Instant>,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, None, None, due).await
    }

    /// [`Self::search`] for a caller narrower than this device's owner
    /// (FIX 2907): the home judges `caller`'s own holder proof, which this
    /// install signs over with the request and the caller's `locality` on
    /// this device (FIX 3550), and answers within the caller's reach, at
    /// that locality, and this device's selector. No home, or a refusal, is
    /// no home hits, never this device's own unscoped scan.
    pub async fn search_for(
        &self,
        query: &str,
        limit: usize,
        caller: &crate::authority::ForwardedCallerProof,
        locality: crate::claim::CallerLocality,
        due: Option<std::time::Instant>,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, None, Some((caller, locality)), due)
            .await
    }

    /// A recall's search (FIX 2905): the home narrows it by `scope`, the
    /// scope the device's recall resolved, before its candidate cut, and
    /// returns the unit recall returns. `caller` is a narrower caller's own
    /// holder proof and its locality, as for [`Self::search_for`]; `None`
    /// asks as this device's owner. No home, or a refusal, is no home hits:
    /// a scoped search never falls back to this device's own scan. `due` is
    /// as for [`Self::search`].
    pub async fn search_recall(
        &self,
        query: &str,
        limit: usize,
        scope: &crate::sync::residence::ResolvedRecallSelection,
        caller: Option<(
            &crate::authority::ForwardedCallerProof,
            crate::claim::CallerLocality,
        )>,
        due: Option<std::time::Instant>,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, Some(scope), caller, due).await
    }

    async fn ask(
        &self,
        query: &str,
        limit: usize,
        scope: Option<&crate::sync::residence::ResolvedRecallSelection>,
        caller: Option<(
            &crate::authority::ForwardedCallerProof,
            crate::claim::CallerLocality,
        )>,
        due: Option<std::time::Instant>,
    ) -> Result<ResidenceSearch, TransportError> {
        let mut config = self.config.clone();
        config.residence_mode = *self.mode.borrow();
        crate::sync::client::search_resident(&self.vault, &config, query, limit, scope, caller, due)
            .await
    }
}

impl Drop for HomeSearch {
    /// The connection let go: the vault keeps the mode it ran, so a device
    /// that syncs only what it opened still answers as one with no home to
    /// ask. A connection that attached since keeps its own.
    fn drop(&mut self) {
        let this: *const Self = self;
        let mut slot = self
            .vault
            .home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if std::ptr::eq(slot.search.as_ptr(), this) {
            slot.mode = Some(*self.mode.borrow());
        }
    }
}

impl Vault {
    /// This device's home search, while it syncs only what it opened and an
    /// own-device sync connection over it lives. `None` on a machine that
    /// holds every window, or with no such connection: its local search is
    /// the whole answer.
    #[must_use]
    pub fn home_search(&self) -> Option<Arc<HomeSearch>> {
        match self.device_residence() {
            DeviceResidence::Opened { search } => search,
            DeviceResidence::HoldsEverything => None,
        }
    }

    /// Whether this device syncs only what it opened, as the last
    /// own-device sync connection that attached over the vault runs it: the
    /// mode it runs now while it lives, the mode it ran when it dropped
    /// after. A host whose connection never attached reads as holding
    /// everything.
    #[must_use]
    pub fn device_residence(&self) -> DeviceResidence {
        // The slot is let go before a search is: dropping the last one
        // takes the slot again.
        let (search, kept) = {
            let slot = self
                .home_search
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (slot.search.upgrade(), slot.mode)
        };
        let mode = search
            .as_ref()
            .map_or(kept, |search| Some(*search.mode.borrow()));
        match mode {
            Some(SyncResidenceMode::Opened) => DeviceResidence::Opened { search },
            Some(SyncResidenceMode::All) | None => DeviceResidence::HoldsEverything,
        }
    }
}
