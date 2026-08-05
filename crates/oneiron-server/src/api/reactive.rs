//! Reactive local-first read contract (ONE-1437 — the on-device half of
//! OF-241).
//!
//! A [`ReactiveLocalRead`] is a framework-neutral Rust hook over the local
//! LMDB-backed [`oneiron::Vault`]: it reads synchronously when it is opened,
//! retains that snapshot, and re-runs its query only after a matching
//! *persistent* change notice. Three properties are load-bearing and pinned by
//! ARCH-0044 T1/T4/T6:
//!
//! 1. **No `Loading` state.** [`ReactiveLocalRead::open`] subscribes BEFORE it
//!    reads, so a write landing between the two arrives as a notice instead of
//!    vanishing into the gap, and the constructor returns holding a real
//!    snapshot. Nothing on the initial path is async, and nothing on it needs a
//!    socket, a server request, or network access — a consumer may start
//!    offline and call [`ReactiveLocalRead::snapshot`] immediately.
//! 2. **Only persistent frames invalidate.** Ephemeral state, root version
//!    vectors, lease traffic, WindowSync VV/selector requests, malformed and
//!    unknown frames, and future app-tier RPC/SUB frames never re-run an LMDB
//!    query. Classification happens in [`crate::broadcast`] through the
//!    read-only `protocol::parse_message` seam.
//! 3. **Coarse re-derive, not incremental view maintenance.** A matching notice
//!    re-runs the whole query exactly once. A lagged receiver escalates to one
//!    coarse full re-read rather than surfacing stale data or disconnecting.
//!
//! The cloud tier (ONE-1495) later carries this same contract over the wire and
//! owns the remote subscription mechanism. This module is the local half only:
//! it adds no route, no wire tag, and no subscription endpoint.

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::broadcast::ReactiveChangeSubscriber;
use crate::server::{BroadcastPayload, SyncServer};

/// The closed set of persistent stores a local query may read.
///
/// A query declares this up front so an arriving notice can be matched without
/// re-deriving a read set: this tier deliberately has no global read-set index
/// (that lands with the cloud carrier, ONE-1495).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ReactiveDependency {
    /// The root doc: window registry, schema version, lease registry.
    Root,
    /// One specific window, keyed `YYYY-MM`.
    Window(String),
    /// Every persistent change, whichever store it lands in.
    AnyPersistent,
}

/// A persistent-store invalidation notice derived from one broadcast frame.
///
/// Only changes that can alter what an LMDB read returns are represented here;
/// [`crate::broadcast::ReactiveChangeSubscriber`] drops everything else before
/// it ever becomes a `ReactiveChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReactiveChange {
    /// A root-doc update landed.
    Root,
    /// A window received a persisted CRDT update.
    Window {
        /// Window key (`YYYY-MM`) the update belongs to.
        window_key: String,
    },
    /// The notice channel dropped `missed` frames. Which stores changed is
    /// unknowable, so every query re-reads once.
    InvalidateAll {
        /// Number of frames the receiver fell behind by.
        missed: u64,
    },
}

impl ReactiveChange {
    /// Whether this notice invalidates a query with `dependencies`.
    ///
    /// `Root` matches [`ReactiveDependency::Root`] and
    /// [`ReactiveDependency::AnyPersistent`]; a window update matches its exact
    /// window plus `AnyPersistent`; `InvalidateAll` matches everything.
    pub(crate) fn invalidates(&self, dependencies: &[ReactiveDependency]) -> bool {
        match self {
            Self::InvalidateAll { .. } => true,
            Self::Root => dependencies.iter().any(|dependency| {
                matches!(
                    dependency,
                    ReactiveDependency::Root | ReactiveDependency::AnyPersistent
                )
            }),
            Self::Window { window_key } => dependencies.iter().any(|dependency| match dependency {
                ReactiveDependency::Window(key) => key == window_key,
                ReactiveDependency::AnyPersistent => true,
                ReactiveDependency::Root => false,
            }),
        }
    }
}

/// A synchronous local query over the vault plus the closed set of stores it
/// depends on.
///
/// `read` must be a pure LMDB read: it runs on the initial (non-async) open
/// path and again on every matching notice.
pub(crate) trait ReactiveLocalQuery: Send + Sync + 'static {
    /// What one run of this query returns.
    type Output: Clone + Send + Sync + 'static;

    /// The stores whose persistent changes invalidate this query.
    fn dependencies(&self) -> &[ReactiveDependency];

    /// Runs the query against the local vault.
    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output>;
}

/// Why a [`ReactiveLocalRead::refresh_on_change`] await ended without a fresh
/// snapshot. Neither variant discards the retained snapshot: the last good
/// value stays readable through [`ReactiveLocalRead::snapshot`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReactiveReadError {
    /// The notice channel closed (the server was dropped). Terminal — no
    /// further change can arrive — but the cached read stays valid and
    /// serveable offline.
    #[error("reactive change channel closed")]
    ChannelClosed,
    /// The vault re-read itself failed. The previous snapshot is retained
    /// rather than replaced by a placeholder.
    #[error("reactive local re-read failed: {0}")]
    Read(#[from] oneiron::Error),
}

/// A retained local read that re-derives itself on matching persistent change.
pub(crate) struct ReactiveLocalRead<Q: ReactiveLocalQuery> {
    vault: Arc<oneiron::Vault>,
    query: Q,
    subscriber: ReactiveChangeSubscriber,
    snapshot: Q::Output,
    revision: u64,
}

impl<Q: ReactiveLocalQuery> ReactiveLocalRead<Q> {
    /// Subscribes, then reads — in that order — and returns with a snapshot.
    ///
    /// The ordering is the whole point: subscribing second would drop any write
    /// that landed between the read and the subscribe, and the consumer would
    /// serve that stale value until some unrelated later change happened to
    /// wake it. Because the read is synchronous and local, no `Loading` state
    /// is representable and no request leaves the process.
    pub(crate) fn open(
        vault: Arc<oneiron::Vault>,
        tx: &broadcast::Sender<BroadcastPayload>,
        query: Q,
    ) -> oneiron::Result<Self> {
        let subscriber = ReactiveChangeSubscriber::new(tx);
        let snapshot = query.read(&vault)?;
        Ok(Self {
            vault,
            query,
            subscriber,
            snapshot,
            revision: 0,
        })
    }

    /// The retained snapshot. Immediate, infallible, and independent of any
    /// socket or server request.
    #[must_use]
    pub(crate) fn snapshot(&self) -> &Q::Output {
        &self.snapshot
    }

    /// How many times the snapshot has been re-derived since [`Self::open`].
    #[must_use]
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    /// Waits past every notice that does not touch this query's dependencies,
    /// then re-reads once and returns the fresh snapshot.
    ///
    /// A lagged channel arrives as
    /// [`ReactiveChange::InvalidateAll`](ReactiveChange::InvalidateAll) and is
    /// honoured as a coarse full re-read: losing notices must degrade to extra
    /// work, never to stale data.
    pub(crate) async fn refresh_on_change(&mut self) -> Result<&Q::Output, ReactiveReadError> {
        loop {
            let Some(change) = self.subscriber.recv().await else {
                return Err(ReactiveReadError::ChannelClosed);
            };
            if !change.invalidates(self.query.dependencies()) {
                continue;
            }
            self.snapshot = self.query.read(&self.vault)?;
            self.revision = self.revision.saturating_add(1);
            break;
        }
        Ok(&self.snapshot)
    }
}

/// Opens a [`ReactiveLocalRead`] against a running server's local tier.
///
/// This is the whole composition: the server's vault is the read side and its
/// broadcast channel is the notice side. It lives here rather than beside the
/// router body because it is an in-process contract — a later client-framework
/// binding wraps it — not an HTTP surface.
pub(crate) fn open_local_reactive_read<Q: ReactiveLocalQuery>(
    server: &Arc<SyncServer>,
    query: Q,
) -> oneiron::Result<ReactiveLocalRead<Q>> {
    ReactiveLocalRead::open(Arc::clone(server.vault()), &server.broadcast_tx, query)
}
