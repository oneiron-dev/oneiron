//! Per-connection budgets, quotas, and sync-mode binding.

use std::collections::HashSet;

use oneiron::sync::WindowKey;

use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError};

/// Per-connection mutable state. This is intentionally local to one socket:
/// Phase-1 auth has only a shared secret, so user-scoped limits are not sound.
pub(super) struct ConnState {
    windows_touched: HashSet<WindowKey>,
    pub(super) documents:
        std::collections::HashMap<oneiron::EntityId, oneiron::sync::SelectorVvRequest>,
    pub(super) window_sync_mode: WindowSyncMode,
    pub(super) lfs_owner_mode: bool,
    pub(super) protocol_version: u8,
    /// App-tier authority is established only by a successful in-band bind.
    pub(super) bound_auth: Option<CoreAuth>,
}

impl ConnState {
    pub(super) fn new(protocol_version: u8) -> Self {
        Self {
            windows_touched: HashSet::new(),
            documents: std::collections::HashMap::new(),
            window_sync_mode: WindowSyncMode::Unbound,
            lfs_owner_mode: false,
            protocol_version,
            bound_auth: None,
        }
    }

    pub(super) fn touch_window(
        &mut self,
        key: WindowKey,
        max_windows_per_connection: usize,
    ) -> Result<WindowKey, ProtocolError> {
        if self.windows_touched.contains(&key) {
            return Ok(key);
        }

        if self.windows_touched.len() >= max_windows_per_connection {
            return Err(ProtocolError::InvalidPayload(
                "window creation limit exceeded",
            ));
        }

        self.windows_touched.insert(key.clone());
        Ok(key)
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
                    && self.protocol_version != protocol::CHUNK_FULL_WINDOW_PROTOCOL_VERSION =>
            {
                return Err(ProtocolError::InvalidPayload(
                    "full-window sync requires the current full-window protocol",
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
            | (WindowSyncMode::Selector, WindowSyncMode::Selector) => Ok(()),
            (WindowSyncMode::Selector, WindowSyncMode::FullWindow) => {
                Err(ProtocolError::InvalidPayload(
                    "selector-scoped connection cannot use full-window sync",
                ))
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::Selector) => Err(
                ProtocolError::InvalidPayload("full-window connection cannot use selector sync"),
            ),
            (_, WindowSyncMode::Unbound) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowSyncMode {
    Unbound,
    FullWindow,
    Selector,
}
