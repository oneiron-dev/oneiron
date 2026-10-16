//! Per-connection budgets, quotas, and sync-mode binding.

use std::collections::{BTreeMap, HashMap};

use oneiron::sync::{SyncSelector, WindowKey};

use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError};

/// Per-connection mutable state. This is intentionally local to one socket:
/// Phase-1 auth has only a shared secret, so user-scoped limits are not sound.
pub(super) struct ConnState {
    subscribed_windows: SubscribedWindows,
    /// Whether this socket has asked `max_windows_per_connection`'s question.
    limit_asked: bool,
    /// Only windows rechecked under a live bound grant can exchange full VVs.
    pub(super) promoted_windows: std::collections::HashMap<WindowKey, SyncSelector>,
    /// Each promoted window's baseline: the home's version when this socket promoted it. A
    /// vector behind it never receives older history. It only rises.
    pub(super) promotion_baselines: std::collections::HashMap<WindowKey, loro::VersionVector>,
    pub(super) documents:
        std::collections::HashMap<oneiron::EntityId, oneiron::sync::SelectorVvRequest>,
    /// Owner-lane NOTE subscriptions of an own device, with its last VV.
    pub(super) owner_documents: std::collections::HashMap<oneiron::EntityId, Vec<u8>>,
    pub(super) window_sync_mode: WindowSyncMode,
    pub(super) lfs_owner_mode: bool,
    /// The object of each chunk reply queued on this socket, in queue order,
    /// so the reply is checked against the device-only flag again on release.
    pub(super) queued_chunk_objects: std::collections::VecDeque<oneiron::origin::lfs::LfsOid>,
    pub(super) protocol_version: u8,
    /// App-tier authority is established only by a successful in-band bind.
    pub(super) bound_auth: Option<CoreAuth>,
    /// Where this socket's peer sits; a bound auth reads from there.
    pub(super) locality: oneiron::claim::CallerLocality,
    /// A single revision-bound, metadata-only index projection for this socket.
    pub(super) residence_index: Option<crate::livequery::ResidenceIndexCache>,
    /// The machine this socket's upgrade proved, independent of its actor.
    /// Read it through [`Self::peer_machine`], which asks the fold again.
    proven_machine: oneiron::authority::PeerMachine,
}

impl ConnState {
    pub(super) fn new(protocol_version: u8) -> Self {
        Self {
            subscribed_windows: SubscribedWindows::default(),
            limit_asked: false,
            promoted_windows: std::collections::HashMap::new(),
            promotion_baselines: std::collections::HashMap::new(),
            documents: std::collections::HashMap::new(),
            owner_documents: std::collections::HashMap::new(),
            window_sync_mode: WindowSyncMode::Unbound,
            lfs_owner_mode: false,
            queued_chunk_objects: std::collections::VecDeque::new(),
            protocol_version,
            bound_auth: None,
            locality: oneiron::claim::CallerLocality::OffDevice,
            residence_index: None,
            proven_machine: oneiron::authority::PeerMachine::Unknown,
        }
    }

    pub(super) fn with_peer_machine(mut self, machine: oneiron::authority::PeerMachine) -> Self {
        self.proven_machine = machine;
        self
    }

    /// The machine this socket proved at upgrade, while the vault's fold
    /// still holds it on the key it proved. The socket outlives that instant:
    /// a machine removed, poisoned, gone stale or trusted under other keys
    /// since is an unknown destination, as is one the fold cannot be read
    /// for. `Unknown` is never this machine or the owner's.
    pub(super) fn peer_machine(&self, vault: &oneiron::Vault) -> oneiron::authority::PeerMachine {
        vault.peer_machine_stands(self.proven_machine)
    }

    /// This socket's peer as a world-privacy destination: the machine it
    /// proved, re-judged against the fold, or unknown. Destination-aware
    /// doors (the sealed relay) read world settings against it.
    pub(super) fn destination(&self, vault: &oneiron::Vault) -> oneiron::authority::Destination {
        match self.peer_machine(vault) {
            oneiron::authority::PeerMachine::Proven { machine, .. } => {
                oneiron::authority::Destination::Machine(machine)
            }
            oneiron::authority::PeerMachine::Unknown => oneiron::authority::Destination::Unknown,
        }
    }

    /// Pushes `key`'s changes to this socket from now on, after a valid version exchange. Only an
    /// owner-lane socket is pushed windows, so no other keeps a subscription. Past `bound` a
    /// socket whose peer takes `WINDOW_INVALIDATE` forgets its least recently requested window;
    /// a v11 peer cannot be told, so it keeps every one: each names a window the vault holds,
    /// since its `VV_REQUEST` creates the window it names. Nothing is refused.
    ///
    /// Returns the subscription count the first time this socket crosses `bound`, for the row's
    /// question.
    pub(super) fn subscribe_window(&mut self, key: &WindowKey, bound: usize) -> Option<usize> {
        if !protocol::is_owner_window_version(self.protocol_version) {
            return None;
        }
        let windows = &mut self.subscribed_windows;
        windows.next += 1;
        if let Some(earlier) = windows.at.insert(key.clone(), windows.next) {
            windows.order.remove(&earlier);
        }
        windows.order.insert(windows.next, key.clone());
        let held = windows.at.len();
        if held <= bound.max(1) {
            return None;
        }
        if protocol::takes_window_invalidations(self.protocol_version)
            && let Some((_, oldest)) = windows.order.pop_first()
        {
            windows.at.remove(&oldest);
            windows.forgot_any = true;
        }
        self.crossed_limit(held)
    }

    pub(super) fn receives_window(&self, key: &WindowKey) -> bool {
        self.subscribed_windows.at.contains_key(key)
    }

    /// Whether `key`'s next change must reach this socket as `WINDOW_INVALIDATE`: it follows
    /// `WINDOW_INVALIDATE`, it forgot a subscription, and it is not pushed `key`. A window it
    /// never requested may be one it forgot, so the notice goes out for it too; a peer that does
    /// not follow the window reads it as nothing.
    pub(super) fn invalidates_window(&self, key: &WindowKey) -> bool {
        self.subscribed_windows.forgot_any && !self.receives_window(key)
    }

    /// This socket holds `held` windows or documents, past `max_windows_per_connection`. Returns
    /// `held` the first time, for the row's question; the socket asks it once.
    pub(super) fn crossed_limit(&mut self, held: usize) -> Option<usize> {
        if self.limit_asked {
            return None;
        }
        self.limit_asked = true;
        Some(held)
    }

    pub(super) fn bind_window_sync_mode(
        &mut self,
        mode: WindowSyncMode,
    ) -> Result<(), ProtocolError> {
        if mode == WindowSyncMode::Selector && self.lfs_owner_mode {
            return Err(ProtocolError::InvalidPayload(
                "owner chunk connection cannot become selector-scoped",
            ));
        }
        if mode == WindowSyncMode::Unbound {
            return Ok(());
        }
        match mode {
            WindowSyncMode::Selector if self.protocol_version != protocol::PROTOCOL_VERSION => {
                return Err(ProtocolError::InvalidPayload(
                    "selector sync requires the current selector protocol",
                ));
            }
            WindowSyncMode::FullWindow
                if self.protocol_version != protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION
                    && !protocol::is_owner_window_version(self.protocol_version) =>
            {
                return Err(ProtocolError::InvalidPayload(
                    "full-window sync requires the current full-window protocol",
                ));
            }
            WindowSyncMode::Residence if !protocol::is_residence_version(self.protocol_version) => {
                return Err(ProtocolError::InvalidPayload(
                    "opened-item sync requires the residence protocol",
                ));
            }
            _ => {}
        }

        match (self.window_sync_mode, mode) {
            (WindowSyncMode::Unbound, requested) => {
                self.window_sync_mode = requested;
                Ok(())
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::FullWindow)
            | (WindowSyncMode::Selector, WindowSyncMode::Selector)
            | (WindowSyncMode::Residence, WindowSyncMode::Residence) => Ok(()),
            (WindowSyncMode::Selector, WindowSyncMode::FullWindow) => {
                Err(ProtocolError::InvalidPayload(
                    "selector-scoped connection cannot use full-window sync",
                ))
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::Selector) => Err(
                ProtocolError::InvalidPayload("full-window connection cannot use selector sync"),
            ),
            (_, WindowSyncMode::Unbound) => Ok(()),
            _ => Err(ProtocolError::InvalidPayload(
                "opened-item sync cannot mix with full-window or federation sync",
            )),
        }
    }
}

/// One socket's window subscriptions in the order they were last requested.
#[derive(Default)]
struct SubscribedWindows {
    order: BTreeMap<u64, WindowKey>,
    at: HashMap<WindowKey, u64>,
    next: u64,
    /// Whether a subscription was forgotten past the row.
    forgot_any: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowSyncMode {
    Unbound,
    FullWindow,
    Selector,
    Residence,
}
