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
    claim_vector_cursor: std::sync::Mutex<Option<Vec<u8>>>,
}

/// The vault's hold on its own sync connection's home search: the live
/// search, and the mode the configured link resolves or the last own-device
/// connection ran, kept once that connection drops (FIX 2905).
#[derive(Default)]
pub(crate) struct HomeSearchSlot {
    search: Weak<HomeSearch>,
    /// The configured link's resolved mode before first attachment, then
    /// the attached connection's mode when it attached or dropped.
    mode: Option<SyncResidenceMode>,
}

/// What this device's own sync connection says of its residence (FIX 2905):
/// whether its local answers are the whole vault it may read.
pub enum DeviceResidence {
    /// The device holds every window it may read, or no own-device link
    /// has been configured over the vault: its local answer is whole.
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
            claim_vector_cursor: std::sync::Mutex::new(None),
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
    /// answers at once come a page at a time (FIX 8865).
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, None, None, None).await
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
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, None, None, Some((caller, locality)))
            .await
    }

    /// A recall's search (FIX 2905): the home narrows it by `scope`, the
    /// scope the device's recall resolved, before its candidate cut, at its
    /// optional `as_of` clock pin, and returns the unit recall returns.
    /// `caller` is a narrower caller's own
    /// holder proof and its locality, as for [`Self::search_for`]; `None`
    /// asks as this device's owner. No home, or a refusal, is no home hits:
    /// a scoped search never falls back to this device's own scan.
    pub async fn search_recall(
        &self,
        query: &str,
        limit: usize,
        scope: &crate::sync::residence::ResolvedRecallSelection,
        as_of: Option<u64>,
        caller: Option<(
            &crate::authority::ForwardedCallerProof,
            crate::claim::CallerLocality,
        )>,
    ) -> Result<ResidenceSearch, TransportError> {
        self.ask(query, limit, Some(scope), as_of, caller).await
    }

    pub(crate) async fn media_vectors_for(
        &self,
        space: &str,
        ids: &[crate::EntityId],
    ) -> Result<Vec<(crate::EntityId, crate::embed::MediaVectorReplica)>, TransportError> {
        let mut config = self.config.clone();
        config.residence_mode = *self.mode.borrow();
        crate::sync::client::request_media_vectors(&self.vault, &config, space, ids).await
    }

    async fn ask(
        &self,
        query: &str,
        limit: usize,
        scope: Option<&crate::sync::residence::ResolvedRecallSelection>,
        as_of: Option<u64>,
        caller: Option<(
            &crate::authority::ForwardedCallerProof,
            crate::claim::CallerLocality,
        )>,
    ) -> Result<ResidenceSearch, TransportError> {
        let mut config = self.config.clone();
        config.residence_mode = *self.mode.borrow();
        crate::sync::client::search_resident(
            &self.vault,
            &config,
            query,
            limit,
            scope,
            as_of,
            caller,
        )
        .await
    }
}

impl HomeSearch {
    pub(crate) async fn default_claim_vector(
        &self,
        id: crate::EntityId,
    ) -> crate::Result<Option<crate::embed::home_vectors::ReceivedHomeClaimVector>> {
        // Unlike an opened-item search, this derivation read is also used by
        // an All device. The machine proof, not a selector, grants this read.
        crate::sync::client::default_claim_vector(&self.vault, &self.config, id).await
    }
}

impl Vault {
    pub(crate) fn embedding_home(&self) -> Option<Arc<HomeSearch>> {
        self.home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .search
            .upgrade()
    }
}

impl HomeSearch {
    pub(crate) fn next_claim_vector_job(
        &self,
    ) -> crate::Result<Option<crate::sync::queue::EmbedQueueRow>> {
        let mut cursor = self
            .claim_vector_cursor
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let queue = crate::sync::queue::SyncQueue::new(Arc::clone(&self.vault))?;
        let row = queue.next_embed_job(cursor.as_deref())?;
        *cursor = row.as_ref().map(|row| row.key.clone());
        Ok(row)
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
    /// Records a configured own-device link before a connection can attach.
    /// An attached connection's live or last mode still takes precedence.
    pub fn record_configured_device_residence(
        &self,
        configured: SyncResidenceMode,
    ) -> crate::Result<()> {
        let mode = crate::sync::residence::resolve_residence_mode(self, configured)?;
        let mut slot = self
            .home_search
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        slot.mode.get_or_insert(mode);
        Ok(())
    }

    /// This device's home search, while it syncs only what it opened and an
    /// own-device sync connection over it lives. `None` on a machine that
    /// holds every window, or has no live connection. An Opened device
    /// without a connection still reports a partial local answer.
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
    /// after. Before first attachment it uses the configured link's resolved
    /// mode; with no configured link, it reads as holding everything.
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
