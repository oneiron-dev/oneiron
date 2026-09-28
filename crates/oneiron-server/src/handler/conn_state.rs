//! Per-connection budgets, quotas, and sync-mode binding.

use std::collections::HashSet;

use oneiron::sync::WindowKey;

use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError};

/// Per-connection mutable state. This is intentionally local to one socket:
/// Phase-1 auth has only a shared secret, so user-scoped limits are not sound.
pub(super) struct ConnState {
    windows_touched: HashSet<WindowKey>,
    subscribed_windows: HashSet<WindowKey>,
    pub(super) documents:
        std::collections::HashMap<oneiron::EntityId, oneiron::sync::SelectorVvRequest>,
    /// Owner-lane NOTE subscriptions of an own device, with its last VV.
    pub(super) owner_documents: std::collections::HashMap<oneiron::EntityId, Vec<u8>>,
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
            subscribed_windows: HashSet::new(),
            documents: std::collections::HashMap::new(),
            owner_documents: std::collections::HashMap::new(),
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

    pub(super) fn subscribe_window(&mut self, key: &WindowKey) {
        self.subscribed_windows.insert(key.clone());
    }

    pub(super) fn receives_window(&self, key: &WindowKey) -> bool {
        self.subscribed_windows.contains(key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_followed_windows_receive_broadcasts_and_late_follow_backfills() {
        let mut device = ConnState::new(protocol::CHUNK_FULL_WINDOW_PROTOCOL_VERSION);
        let month = WindowKey::new("2026-03");
        let worlds: Vec<_> = (1..=5)
            .map(|byte| oneiron::EntityId::from_bytes([byte; 16]).unwrap())
            .collect();
        let keys: Vec<_> = worlds
            .iter()
            .map(|world| WindowKey::for_month_world(&month, *world))
            .collect();
        for key in &keys {
            assert!(!device.receives_window(key));
        }
        device.touch_window(keys[0].clone(), 32).unwrap();
        assert!(!device.receives_window(&keys[0]));
        device.subscribe_window(&keys[0]);
        assert!(device.receives_window(&keys[0]));
        assert!(keys[1..].iter().all(|key| !device.receives_window(key)));
        device.touch_window(keys[1].clone(), 32).unwrap();
        device.subscribe_window(&keys[1]);
        assert!(device.receives_window(&keys[1]));
        let mut home = ConnState::new(protocol::CHUNK_FULL_WINDOW_PROTOCOL_VERSION);
        for key in &keys {
            home.touch_window(key.clone(), 32).unwrap();
            home.subscribe_window(key);
        }
        assert!(keys.iter().all(|key| home.receives_window(key)));
    }
}
