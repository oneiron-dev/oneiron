//! Paged, revision-bound current-window metadata enrolment.
use std::collections::HashSet;

use crate::EntityId;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::sync::client::SyncResidenceMode;
use crate::sync::residence::WindowIndexEntry;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

/// One current window's thin index as this device last fetched it: what
/// exists, titles and times, never a body or CRDT history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidenceIndexWindow {
    pub window: WindowKey,
    pub items: Vec<WindowIndexEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexReply {
    window: String,
    items: Vec<WindowIndexEntry>,
    next_cursor: Option<String>,
    revision: String,
}

impl SyncClient {
    /// Fetch the current windows' thin index without a full-window VV exchange.
    pub async fn fetch_current_index(&self, now_secs: u64) -> Result<usize, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let budgets = residence_budgets(&self.vault)?;
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector_bytes = encode_sync_selector(selector).map_err(|_| refused())?;
        let selector = base64::engine::general_purpose::STANDARD.encode(selector_bytes);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        let mut eligible = HashSet::new();
        let mut next = Some(WindowKey::from_timestamp(now_secs));
        for _ in 0..budgets.current_window_count {
            let Some(key) = next else { break };
            next = key.previous_month();
            eligible.insert(key);
        }
        // A current month's world windows are indexed for the worlds this
        // device follows; any other world item is still opened by id.
        let worlds = self.effective_worlds()?;
        let mut total = 0;
        let mut indexed = HashSet::new();
        for key in self.server_windows() {
            let Some(window) = WindowKey::try_new(&key) else {
                continue;
            };
            let month = window.start_timestamp().map(WindowKey::from_timestamp);
            if !month.is_some_and(|month| eligible.contains(&month))
                || !Self::follows_window(&window, &worlds)
            {
                continue;
            }
            let mut complete = None;
            for _retry in 0..3 {
                let mut cursor: Option<String> = None;
                let mut revision: Option<String> = None;
                let mut items = Vec::new();
                // The page count is a work slice, not a ceiling: past it the
                // scan yields and goes on, keeping what it read (FIX 8867).
                let mut pages = 0usize;
                loop {
                    pages = pages.wrapping_add(1);
                    if pages % budgets.max_index_pages == 0 {
                        tokio::task::yield_now().await;
                    }
                    let value = match rpc
                        .request(
                            "residence.index",
                            json!({
                                "window": key, "selector": selector, "after": cursor,
                                "revision": revision, "limit": budgets.index_page_limit,
                            }),
                        )
                        .await
                    {
                        Ok(value) => value,
                        Err(TransportError::IndexRevisionChanged) => break,
                        Err(error) => return Err(error),
                    };
                    let reply: IndexReply = serde_json::from_value(value).map_err(|_| refused())?;
                    if reply.window != key
                        || reply.revision.len() != 64
                        || !reply.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || revision
                            .as_ref()
                            .is_some_and(|prior| prior != &reply.revision)
                    {
                        return Err(refused());
                    }
                    revision = Some(reply.revision);
                    let mut previous = cursor.clone();
                    for entry in &reply.items {
                        let id = EntityId::from_hex(&entry.entity_id).map_err(|_| refused())?;
                        if entry.entity_id != id.to_hex()
                            || previous
                                .as_ref()
                                .is_some_and(|prior| prior >= &entry.entity_id)
                        {
                            return Err(refused());
                        }
                        previous = Some(entry.entity_id.clone());
                    }
                    items.extend(reply.items);
                    match reply.next_cursor {
                        Some(next) => {
                            let id = EntityId::from_hex(&next).map_err(|_| refused())?;
                            if next != id.to_hex()
                                || previous.as_ref().is_some_and(|prior| prior > &next)
                                || cursor.as_ref().is_some_and(|prior| prior >= &next)
                            {
                                return Err(refused());
                            }
                            cursor = Some(next);
                        }
                        None => {
                            complete = Some(items);
                            break;
                        }
                    }
                }
                if complete.is_some() {
                    break;
                }
            }
            let items = complete.ok_or(TransportError::IndexRevisionChanged)?;
            let prefix = format!("ri:w:{key}:");
            self.vault
                .with_write_txn_grouped(|txn| {
                    let old: Vec<_> = self
                        .vault
                        .store
                        .sync_state
                        .prefix_iter(txn, &prefix)?
                        .map(|row| row.map(|(key, _)| key.to_string()))
                        .collect::<std::result::Result<_, _>>()?;
                    for key in old {
                        self.vault.store.sync_state.delete(txn, &key)?;
                    }
                    for entry in &items {
                        let key = format!("{prefix}{}", entry.entity_id);
                        let bytes = rmp_serde::to_vec_named(entry)
                            .map_err(|_| crate::Error::InvariantViolation("index codec"))?;
                        self.vault.store.sync_state.put(txn, &key, &bytes)?;
                    }
                    Ok(())
                })
                .map_err(|e| TransportError::Storage(e.to_string()))?;
            total += items.len();
            indexed.insert(key);
        }
        // A window that left the current set, or that this device no longer
        // follows, keeps no stale titles.
        self.vault
            .with_write_txn_grouped(|txn| {
                let stale: Vec<_> = self
                    .vault
                    .store
                    .sync_state
                    .prefix_iter(txn, "ri:w:")?
                    .map(|row| row.map(|(key, _)| key.to_string()))
                    .collect::<std::result::Result<_, _>>()?;
                for key in stale {
                    let window = key
                        .strip_prefix("ri:w:")
                        .and_then(|rest| rest.rsplit_once(':'))
                        .map(|(window, _)| window);
                    if !window.is_some_and(|window| indexed.contains(window)) {
                        self.vault.store.sync_state.delete(txn, &key)?;
                    }
                }
                Ok(())
            })
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        Ok(total)
    }

    /// Fetch the current windows' thin index again and return it. Hosts call
    /// this after a root or world-selection change; enrol already does.
    pub async fn refresh_residence_index(
        &self,
        now_secs: u64,
    ) -> Result<Vec<ResidenceIndexWindow>, TransportError> {
        self.fetch_current_index(now_secs).await?;
        self.residence_index()
    }

    /// The thin index this device holds, window by window in key order.
    pub fn residence_index(&self) -> Result<Vec<ResidenceIndexWindow>, TransportError> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(refused());
        }
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|e| TransportError::Storage(e.to_string()))?;
        let mut windows: Vec<ResidenceIndexWindow> = Vec::new();
        for row in self
            .vault
            .store
            .sync_state
            .prefix_iter(&txn, "ri:w:")
            .map_err(|e| TransportError::Storage(e.to_string()))?
        {
            let (key, value) = row.map_err(|e| TransportError::Storage(e.to_string()))?;
            let window = key
                .strip_prefix("ri:w:")
                .and_then(|rest| rest.rsplit_once(':'))
                .and_then(|(window, _)| WindowKey::try_new(window))
                .ok_or_else(refused)?;
            let entry: WindowIndexEntry = rmp_serde::from_slice(&value).map_err(|_| refused())?;
            match windows.last_mut() {
                Some(last) if last.window == window => last.items.push(entry),
                _ => windows.push(ResidenceIndexWindow {
                    window,
                    items: vec![entry],
                }),
            }
        }
        Ok(windows)
    }
}
