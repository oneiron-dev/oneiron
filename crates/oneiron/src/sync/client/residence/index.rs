//! Paged, revision-bound current-window metadata enrolment.
use std::collections::HashSet;

use crate::EntityId;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::rpc::RpcFault;
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

/// Why a residence index fetch failed, by the side the fault is on (FIX
/// 22153), around the error the fetch tells.
#[derive(Debug)]
pub(crate) enum IndexFetchFault {
    /// The home's: no socket to it, its refusal, or a reply that breaks the
    /// RPC's or the index's paging contract.
    Remote(TransportError),
    /// This machine's own: its lane mode, residence policy or selector, its
    /// actor session, its endpoint and upgrade, its own encode, or a read or
    /// write of its store (FIX 22179).
    Local(TransportError),
}

impl IndexFetchFault {
    /// The fault of a residence RPC, on the side the RPC named (FIX 22179).
    fn of_rpc(fault: RpcFault) -> Self {
        match fault {
            RpcFault::Remote(error) => Self::Remote(error),
            RpcFault::Local(error) => Self::Local(error),
        }
    }

    /// Whether the fault is this machine's own.
    pub(crate) const fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// The error the fetch tells, its side dropped.
    pub(crate) fn into_error(self) -> TransportError {
        match self {
            Self::Remote(error) | Self::Local(error) => error,
        }
    }
}

impl std::fmt::Display for IndexFetchFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(error) | Self::Local(error) => std::fmt::Display::fmt(error, f),
        }
    }
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
        self.fetch_current_index_by_side(now_secs)
            .await
            .map_err(IndexFetchFault::into_error)
    }

    /// The windows the thin index enrols now: each of the current
    /// `current_window_count` months' windows the home lists, its base window
    /// and the windows of every world readable on this machine, followed or
    /// not (ARCH-0023b #partial-sync). Following decides only which full
    /// window documents sync; an item of any world still opens by id.
    pub(crate) fn thin_index_windows(
        &self,
        now_secs: u64,
        current_window_count: usize,
    ) -> Result<Vec<WindowKey>, TransportError> {
        let mut eligible = HashSet::new();
        let mut next = Some(WindowKey::from_timestamp(now_secs));
        for _ in 0..current_window_count {
            let Some(key) = next else { break };
            next = key.previous_month();
            eligible.insert(key);
        }
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let readable = self.readable_worlds_in(&txn)?;
        drop(txn);
        Ok(self
            .server_windows()
            .iter()
            .filter_map(|key| WindowKey::try_new(key))
            .filter(|window| {
                window
                    .start_timestamp()
                    .map(WindowKey::from_timestamp)
                    .is_some_and(|month| eligible.contains(&month))
                    && Self::follows_window(window, &readable)
            })
            .collect())
    }

    /// [`Self::fetch_current_index`], its fault told by the side it is on
    /// (FIX 22153): a home session counts only the home's against the home.
    /// The residence socket's opening and each call on it fail on the side
    /// the RPC names (FIX 22179): its endpoint, its signing, its actor
    /// session and its bind's or request's encode are this machine's own.
    pub(crate) async fn fetch_current_index_by_side(
        &self,
        now_secs: u64,
    ) -> Result<usize, IndexFetchFault> {
        if self.config.residence_mode != SyncResidenceMode::Opened {
            return Err(IndexFetchFault::Local(refused()));
        }
        let budgets = residence_budgets(&self.vault).map_err(IndexFetchFault::Local)?;
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(|| IndexFetchFault::Local(refused()))?;
        let selector_bytes =
            encode_sync_selector(selector).map_err(|_| IndexFetchFault::Local(refused()))?;
        let selector = base64::engine::general_purpose::STANDARD.encode(selector_bytes);
        let Some(mut rpc) = ResidenceRpc::connect_by_side(&self.vault, &self.config, budgets)
            .await
            .map_err(IndexFetchFault::of_rpc)?
        else {
            return Err(IndexFetchFault::Remote(TransportError::home_offline()));
        };
        let windows = self
            .thin_index_windows(now_secs, budgets.current_window_count)
            .map_err(IndexFetchFault::Local)?;
        let mut total = 0;
        let mut indexed = HashSet::new();
        for window in windows {
            let key = window.as_str().to_owned();
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
                        .request_by_side(
                            "residence.index",
                            json!({
                                "window": key, "selector": selector, "after": cursor,
                                "revision": revision, "limit": budgets.index_page_limit,
                            }),
                        )
                        .await
                    {
                        Ok(value) => value,
                        Err(RpcFault::Remote(TransportError::IndexRevisionChanged)) => break,
                        Err(fault) => return Err(IndexFetchFault::of_rpc(fault)),
                    };
                    let reply: IndexReply = serde_json::from_value(value)
                        .map_err(|_| IndexFetchFault::Remote(refused()))?;
                    if reply.window != key
                        || reply.revision.len() != 64
                        || !reply.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || revision
                            .as_ref()
                            .is_some_and(|prior| prior != &reply.revision)
                    {
                        return Err(IndexFetchFault::Remote(refused()));
                    }
                    revision = Some(reply.revision);
                    let mut previous = cursor.clone();
                    for entry in &reply.items {
                        let id = EntityId::from_hex(&entry.entity_id)
                            .map_err(|_| IndexFetchFault::Remote(refused()))?;
                        if entry.entity_id != id.to_hex()
                            || previous
                                .as_ref()
                                .is_some_and(|prior| prior >= &entry.entity_id)
                        {
                            return Err(IndexFetchFault::Remote(refused()));
                        }
                        previous = Some(entry.entity_id.clone());
                    }
                    items.extend(reply.items);
                    match reply.next_cursor {
                        Some(next) => {
                            let id = EntityId::from_hex(&next)
                                .map_err(|_| IndexFetchFault::Remote(refused()))?;
                            if next != id.to_hex()
                                || previous.as_ref().is_some_and(|prior| prior > &next)
                                || cursor.as_ref().is_some_and(|prior| prior >= &next)
                            {
                                return Err(IndexFetchFault::Remote(refused()));
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
            let items = complete.ok_or(IndexFetchFault::Remote(
                TransportError::IndexRevisionChanged,
            ))?;
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
                .map_err(|e| IndexFetchFault::Local(TransportError::Storage(e.to_string())))?;
            total += items.len();
            indexed.insert(key);
        }
        // A window that left the current set, or whose world this machine may
        // no longer read, keeps no stale titles.
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
            .map_err(|e| IndexFetchFault::Local(TransportError::Storage(e.to_string())))?;
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
