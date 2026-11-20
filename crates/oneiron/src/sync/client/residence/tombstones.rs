//! A followed world's tombstone id set, taken from the home on each connect
//! (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; canon ARCH-0023b :500: "Tier 1 ...
//! also carries the tombstone id set for every followed world. So a device
//! writes the delete marker even for a window it never held.").
//!
//! An opened-item device asks the home, by `residence.tombstones`, for the
//! tombstones of every window of every world it follows, of every month,
//! whether or not the home grants it the window's full exchange. The
//! residence upkeep asks again, every pass, for each followed window this
//! device holds no rows of, or whose follow the home refused on the live
//! socket, so a delete the home makes during a session reaches a window the
//! home refuses to it (FOLLOWED-TOMBSTONE-HELD-WINDOW-REFUSED-LIVE). Each one
//! goes through the one replay primitive every sync route uses, so a hard
//! delete purges the row and its thin copies and writes the permanent `dt:`
//! marker even for an id this device never held, and a soft one stays soft.
//! The home's answer is admitted per request by its own reader rule and
//! names only deletes the home placed in the window, so it is the residence
//! witness for an id with no local trace; the guard that skips unknown ids
//! in a peer's window document stays as it is. A row this device places in
//! another window keeps its residence veto, as a window replay keeps it, so
//! an answer never deletes a row this device knows lives elsewhere (blind
//! review 2 of #9593).

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::EntityId;
use crate::deletion::decode_tombstone_value;
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::sync::types::{TombstoneResidence, WindowKey, tombstone_residence_in};

/// One page of a window's tombstone id set, as the home answers it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TombstonesReply {
    window: String,
    items: Vec<TombstoneItem>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TombstoneItem {
    entity_id: String,
    /// The raw tombstone value, base64.
    value: String,
}

impl SyncClient {
    /// The windows whose tombstone id set this device takes: every window the
    /// home lists of a world this lane follows now, of every month. A world
    /// whose read setting keeps it off this machine is followed by no lane
    /// here, so its windows are never asked.
    pub(crate) fn followed_tombstone_windows(&self) -> Result<Vec<WindowKey>, TransportError> {
        let worlds = self.effective_worlds()?;
        Ok(self
            .server_windows()
            .iter()
            .filter_map(|key| WindowKey::try_new(key))
            .filter(|window| window.world().is_some_and(|world| worlds.contains(&world)))
            .collect())
    }

    /// Takes the tombstone id set of every followed window from the home and
    /// applies each tombstone here: the count applied. An opened-item device
    /// lane only; any other lane takes none.
    pub(crate) async fn fetch_followed_tombstones(&self) -> Result<usize, TransportError> {
        if !opened_device_lane(&self.config) {
            return Ok(0);
        }
        let windows = self.followed_tombstone_windows()?;
        self.fetch_tombstones_of(windows).await
    }

    /// Takes the tombstone id set of each of `windows` from the home and
    /// applies each tombstone here: the count applied. A tombstone that fails
    /// to apply, and a window the home refuses (it went unreadable to this
    /// machine before its page was released), leave the rest going, and the
    /// first failure is returned once the set is done; the next pass asks
    /// again (blind review 2 of #9593).
    async fn fetch_tombstones_of(&self, windows: Vec<WindowKey>) -> Result<usize, TransportError> {
        if windows.is_empty() {
            return Ok(0);
        }
        let budgets = residence_budgets(&self.vault)?;
        let selector = self
            .config
            .residence_selector
            .as_ref()
            .ok_or_else(refused)?;
        let selector = base64::engine::general_purpose::STANDARD
            .encode(encode_sync_selector(selector).map_err(|_| refused())?);
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::home_offline());
        };
        let mut applied = 0;
        let mut failed = None;
        for window in windows {
            let key = window.as_str().to_owned();
            let mut cursor: Option<String> = None;
            // The page count is a work slice, not a ceiling: past it the
            // pass yields and goes on (FIX 8867).
            let mut pages = 0usize;
            loop {
                pages = pages.wrapping_add(1);
                if pages % budgets.max_index_pages == 0 {
                    tokio::task::yield_now().await;
                }
                let answer = rpc
                    .call(
                        "residence.tombstones",
                        json!({
                            "window": key, "selector": selector, "after": cursor,
                            "limit": budgets.index_page_limit,
                        }),
                    )
                    .await?;
                let Ok(value) = answer else {
                    failed.get_or_insert_with(refused);
                    break;
                };
                let reply: TombstonesReply =
                    serde_json::from_value(value).map_err(|_| refused())?;
                if reply.window != key {
                    return Err(refused());
                }
                let page = checked_page(&reply, cursor.as_deref())?;
                for (id, value) in &page {
                    match self.apply_followed_tombstone(&window, *id, value) {
                        Ok(true) => applied += 1,
                        Ok(false) => {}
                        Err(error) => {
                            failed.get_or_insert(error);
                        }
                    }
                }
                match reply.next_cursor {
                    Some(next) => {
                        let last = page.last().map(|(id, _)| id.to_hex());
                        if EntityId::from_hex(&next).map(|id| id.to_hex()).ok()
                            != Some(next.clone())
                            || last.as_ref() != Some(&next)
                        {
                            return Err(refused());
                        }
                        cursor = Some(next);
                    }
                    None => break,
                }
            }
        }
        failed.map_or(Ok(applied), Err)
    }

    /// Applies one followed tombstone of `window` through the sync replay
    /// primitive: whether it was applied. A row this device places in
    /// another window is not applied: the residence veto a window replay
    /// keeps (blind review 2 of #9593). A hard one whose `dt:` marker this
    /// device already holds is done, and so is a soft one with no full local
    /// row to scrub (none here, or already its shell): neither is applied
    /// again.
    fn apply_followed_tombstone(
        &self,
        window: &WindowKey,
        id: EntityId,
        value: &[u8],
    ) -> Result<bool, TransportError> {
        let storage = |error: crate::Error| TransportError::Storage(error.to_string());
        let (residence, marked) = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(|error| TransportError::Storage(error.to_string()))?;
            (
                tombstone_residence_in(&self.vault, &txn, &id, window),
                crate::deletion::hard_delete_marker_exists_in_txn(&self.vault.store, &txn, &id)
                    .map_err(storage)?,
            )
        };
        match residence {
            Ok(TombstoneResidence::Match | TombstoneResidence::Unknown) => {}
            Ok(TombstoneResidence::Wrong)
            | Err(crate::Error::CorruptedIndex(_) | crate::Error::InvalidKey) => {
                tracing::warn!(
                    entity = %id.to_hex(),
                    window = window.as_str(),
                    "followed tombstone outside this device's residence for its window; not applied"
                );
                return Ok(false);
            }
            Err(error) => return Err(storage(error)),
        }
        let done = if decode_tombstone_value(value).is_hard() {
            marked
        } else {
            self.vault
                .get_raw(&id)
                .map_err(storage)?
                .is_none_or(|raw| raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN)
        };
        if done {
            return Ok(false);
        }
        crate::sync::quarantine::apply_replayed_tombstone_for_sync(&self.vault, &id, value)
            .map_err(storage)?;
        Ok(true)
    }
}

/// Takes again, from the residence upkeep, the tombstone id set of each
/// followed window this device holds no rows of (a follow the home refused
/// or has not answered), and of each held one whose follow the home refused
/// on the live socket: the count applied. A held window the home grants
/// takes its deletes through its own exchange; a refused one has none
/// (FOLLOWED-TOMBSTONE-HELD-WINDOW-REFUSED-LIVE). An opened-item device
/// lane only.
pub(crate) async fn refresh_followed_tombstones(
    manager: &std::sync::Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    if !opened_device_lane(config) {
        return Ok(0);
    }
    let (client, _events) = SyncClient::new(std::sync::Arc::clone(manager), config.clone())
        .map_err(|error| TransportError::Storage(error.to_string()))?;
    let mut asked = Vec::new();
    for window in client.followed_tombstone_windows()? {
        if manager.follow_refused(&window)
            || !window_rows_held(&client.vault, &window)
                .map_err(|error| TransportError::Storage(error.to_string()))?
        {
            asked.push(window);
        }
    }
    client.fetch_tombstones_of(asked).await
}

/// Whether `config` is an opened-item device lane, the one lane that takes
/// followed tombstone id sets.
fn opened_device_lane(config: &SyncClientConfig) -> bool {
    config.residence_mode == SyncResidenceMode::Opened && config.federation_peer.is_none()
}

/// Whether this install keeps rows of `window`: a persisted snapshot or a
/// persisted update.
fn window_rows_held(vault: &crate::Vault, window: &WindowKey) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    if vault
        .store
        .sync_state
        .get(&txn, &format!("d:w:{window}"))?
        .is_some()
    {
        return Ok(true);
    }
    Ok(vault
        .store
        .sync_state
        .prefix_iter(&txn, &format!("u:w:{window}:"))?
        .next()
        .transpose()?
        .is_some())
}

/// The ids and raw values of one page, refused unless each id is canonical
/// and the page runs in ascending order past `after`.
fn checked_page(
    reply: &TombstonesReply,
    after: Option<&str>,
) -> Result<Vec<(EntityId, Vec<u8>)>, TransportError> {
    let mut previous = after.map(str::to_owned);
    let mut page = Vec::with_capacity(reply.items.len());
    for item in &reply.items {
        let id = EntityId::from_hex(&item.entity_id).map_err(|_| refused())?;
        if item.entity_id != id.to_hex()
            || previous
                .as_ref()
                .is_some_and(|prior| prior >= &item.entity_id)
        {
            return Err(refused());
        }
        // An empty value is the home window's own reading of a value that
        // is no binary: it decodes hard, as the window's replay reads it,
        // and never refuses the page (blind review 1 of #9593).
        let value = base64::engine::general_purpose::STANDARD
            .decode(&item.value)
            .map_err(|_| refused())?;
        previous = Some(item.entity_id.clone());
        page.push((id, value));
    }
    Ok(page)
}
