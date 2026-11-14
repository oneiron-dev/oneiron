//! The predicted level's upkeep on a machine (census L7-46 + L10-14, ARCH-0023b
//! #predicted-residence). Once per connection after the authority catch-up, then every 6 h, the
//! machine asks its home for a prediction (Engine ruling L7-46-MERGE A); it fetches the windows
//! and entity documents the adopted set names and evicts what the set drops. Phones fetch only on
//! a reported unmetered and powered state, closed by default. A prediction freezes while the home
//! is down, and eviction is a local residence change through the demotion path, never a CRDT
//! delete: unsynced edits are never evicted.

use std::collections::HashSet;

use tokio::sync::mpsc;

use crate::EntityId;
use crate::Vault;
use crate::authority::{PredictedResidenceSet, ResidenceDirective};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::sync::client::SyncEvent;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

use super::SyncConnection;
use super::directives::{refuses, storage};

/// How often a predicted machine asks its home for a prediction (Engine ruling L7-46-MERGE A).
const PREDICT_ASK_EVERY_SECS: u64 = 6 * 3600;

/// How long after a (re)connect a predicted machine waits before it asks again for a prediction.
const PREDICT_ASK_AFTER_CONNECT_SECS: u64 = 3600;

/// The canonical body of the predicted set this machine adopted.
pub(super) const PREDICTED_TARGET: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_PREDICTED_TARGET);

/// When this machine last asked its home for a prediction, in wall-clock seconds.
const PREDICTED_ASKED: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_PREDICTED_ASKED);

/// A window prediction this machine fetched here, by window key.
const PREDICTED_WINDOW: SideTable<String, (), Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_PREDICTED_WINDOW);

/// An entity document prediction this machine subscribed here, by entity.
const PREDICTED_DOCUMENT: SideTable<HexId, (), Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_PREDICTED_DOCUMENT);

/// One read of this machine's prediction rows, in its own read transaction.
fn read_rows<T>(
    vault: &Vault,
    read: impl FnOnce(&heed::RoTxn<'_>) -> crate::error::Result<T>,
) -> Result<T, TransportError> {
    let txn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| TransportError::Storage(error.to_string()))?;
    read(&txn).map_err(storage)
}

/// One write of this machine's prediction rows, through the grouped writer.
fn write_rows(
    vault: &Vault,
    write: impl FnOnce(&mut heed::RwTxn<'_>) -> crate::error::Result<()>,
) -> Result<(), TransportError> {
    vault.with_write_txn_grouped(write).map_err(storage)
}

/// Whether `error` is the home's outage, which ends the pass quietly: the prediction freezes
/// while the home is down.
fn is_home_offline(error: &TransportError) -> bool {
    matches!(error, TransportError::WebSocket(message) if message == "home node offline")
}

/// Whether subscribing `error` says the entity may not be subscribed here, rather than that the
/// store failed: a predicted document this machine holds no row for waits for its window.
fn admission_denied(error: &crate::error::Error) -> bool {
    matches!(
        error,
        crate::error::Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: crate::error::SyncProtocolValidation::DocumentAdmissionDenied,
        })
    )
}

/// The pass after `stage` ran: quiet when the home is offline, so a prediction freezes while the
/// home is down instead of erroring on every pass.
async fn unless_home_offline(
    stage: impl std::future::Future<Output = Result<(), TransportError>>,
) -> Result<(), TransportError> {
    match stage.await {
        Ok(()) => Ok(()),
        Err(error) if is_home_offline(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

impl SyncConnection {
    /// Runs the predicted level's upkeep each time it wakes: one pass under the host's
    /// admission, a pause waited out (FIX 12036), errors reported as [`SyncEvent::Error`].
    pub(super) async fn run_predicted_residence(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> std::convert::Infallible {
        loop {
            self.predicted_wake.notified().await;
            let _round = self.admit_round().await;
            if let Err(error) = self.run_predicted_pass().await {
                let _ = events.send(SyncEvent::Error(format!(
                    "Predicted residence failed: {error}"
                )));
            }
        }
    }

    /// Runs one predicted upkeep pass: ask when due and the fetch gate is open, fetch the
    /// adopted set's windows and documents, and evict what the set dropped, at any time. A
    /// federation lane does nothing. The home's outage ends the pass quietly.
    pub(crate) async fn run_predicted_pass(&self) -> Result<(), TransportError> {
        if self.config.client_config.federation_peer.is_some() {
            return Ok(());
        }
        let vault = self.manager.vault();
        let predicted = crate::sync::residence::load_device_sync_preference(vault)
            .map_err(storage)?
            .is_some_and(|preference| preference.predicted);
        if !predicted {
            if read_rows(vault, |txn| {
                PREDICTED_TARGET.contains(&vault.store, txn, &())
            })? {
                write_rows(vault, |txn| {
                    PREDICTED_TARGET.delete(&vault.store, txn, &()).map(drop)
                })?;
            }
            let empty = PredictedResidenceSet::default();
            return unless_home_offline(self.evict_predictions(&empty)).await;
        }
        if self.fetch_gate_open() {
            unless_home_offline(self.maybe_ask_prediction()).await?;
            let target = self.predicted_target()?;
            unless_home_offline(self.fetch_predicted_windows(&target)).await?;
            self.fetch_predicted_documents(&target)?;
            return unless_home_offline(self.evict_predictions(&target)).await;
        }
        let target = self.predicted_target()?;
        unless_home_offline(self.evict_predictions(&target)).await
    }

    /// The accepted residence directives naming `machine`, oldest first, read in one
    /// transaction.
    pub(crate) fn directives_naming_machine(
        vault: &Vault,
        machine: EntityId,
    ) -> crate::error::Result<Vec<ResidenceDirective>> {
        let txn = vault.store.env.read_txn()?;
        Ok(
            crate::sync::residence::directive_states_in_txn(vault, &txn)?
                .into_iter()
                .filter(|state| state.directive.machine == machine)
                .map(|state| state.directive)
                .collect(),
        )
    }

    /// Asks the home for a prediction when one is due, and takes a pushed one through the
    /// authority catch-up, waking the directives that apply it.
    async fn maybe_ask_prediction(&self) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let now = vault.store.clock.wall_now();
        let last = read_rows(vault, |txn| PREDICTED_ASKED.get(&vault.store, txn, &()))?;
        let due = last.is_none_or(|asked| now.saturating_sub(asked) >= PREDICT_ASK_EVERY_SECS);
        let connected = self
            .predicted_connected
            .swap(false, std::sync::atomic::Ordering::Relaxed);
        let after_connect = connected
            && last.is_none_or(|asked| now.saturating_sub(asked) >= PREDICT_ASK_AFTER_CONNECT_SECS);
        if !due && !after_connect {
            return Ok(());
        }
        write_rows(vault, |txn| {
            PREDICTED_ASKED.put(&vault.store, txn, &(), &now)
        })?;
        let mut client = self.client()?;
        if client.ask_prediction().await?.pushed().is_some() {
            client.catch_up_authority().await?;
            self.wake_residence_directives();
        }
        Ok(())
    }

    /// The predicted set this machine adopted, or none when it adopted nothing yet.
    fn predicted_target(&self) -> Result<PredictedResidenceSet, TransportError> {
        let vault = self.manager.vault();
        let Some(body) = read_rows(vault, |txn| PREDICTED_TARGET.get(&vault.store, txn, &()))?
        else {
            return Ok(PredictedResidenceSet::default());
        };
        PredictedResidenceSet::decode_verified(&body, &PredictedResidenceSet::body_digest(&body))
            .map_err(|error| TransportError::Storage(error.to_string()))
    }

    /// Fetches the target's windows, skipping the followed worlds', the fetched ones and the
    /// held ones; each other window prefetches through its thin index anchor. A refused window
    /// waits for the next pass; any other failure holds the pass back.
    async fn fetch_predicted_windows(
        &self,
        target: &PredictedResidenceSet,
    ) -> Result<(), TransportError> {
        if target.windows.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        let pick = crate::sync::residence::load_device_world_pick(vault).map_err(storage)?;
        let held: HashSet<WindowKey> = crate::sync::residence::discover_local_window_keys(vault)
            .map_err(storage)?
            .into_iter()
            .collect();
        let mut client = self.client()?;
        for name in &target.windows {
            let Some(window) = WindowKey::try_new(name.as_str()) else {
                continue;
            };
            if window.world().is_some_and(|world| pick.contains(&world)) {
                continue;
            }
            let marker = window.as_str().to_owned();
            if read_rows(vault, |txn| {
                PREDICTED_WINDOW.contains(&vault.store, txn, &marker)
            })? {
                continue;
            }
            if vault
                .sync_state_get(&format!("rp:w:{window}"))
                .map_err(storage)?
                .is_some()
                || held.contains(&window)
            {
                continue;
            }
            let Some(anchor) = client.thin_index_anchor(&window)? else {
                continue;
            };
            match client.prefetch_window(&window, anchor).await {
                Ok(true) => {
                    write_rows(vault, |txn| {
                        PREDICTED_WINDOW.put(&vault.store, txn, &marker, &())
                    })?;
                }
                Ok(false) => {}
                Err(error) if refuses(&error) => {
                    tracing::warn!(%error, %window, "predicted window not prefetched");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Subscribes the target's entity documents through the document registry. A document this
    /// machine holds no row for waits for its window; any other failure holds the pass back.
    fn fetch_predicted_documents(
        &self,
        target: &PredictedResidenceSet,
    ) -> Result<(), TransportError> {
        if target.documents.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        let selector =
            self.client_config()
                .residence_selector
                .ok_or(TransportError::InvalidPayload(
                    "a prediction needs this machine's residence selector",
                ))?;
        for id in &target.documents {
            let marker = HexId(*id);
            if read_rows(vault, |txn| {
                PREDICTED_DOCUMENT.contains(&vault.store, txn, &marker)
            })? {
                continue;
            }
            match self.manager.documents().subscribe_entity(*id, &selector) {
                Ok(()) => {
                    write_rows(vault, |txn| {
                        PREDICTED_DOCUMENT.put(&vault.store, txn, &marker, &())
                    })?;
                }
                Err(error) if admission_denied(&error) => {
                    tracing::warn!(%error, document = %id.to_hex(), "predicted document not subscribed");
                }
                Err(error) => return Err(storage(error)),
            }
        }
        Ok(())
    }

    /// Evicts what the target dropped: predicted windows demote through the demotion path, and
    /// predicted documents unsubscribe once no edit waits. Runs without the fetch gate, and never
    /// writes a tombstone, a deletion op or any frame to the home.
    async fn evict_predictions(
        &self,
        target: &PredictedResidenceSet,
    ) -> Result<(), TransportError> {
        self.evict_predicted_windows(target).await?;
        self.evict_predicted_documents(target)
    }

    /// Demotes the fetched windows the target dropped. A window whose world is now followed
    /// keeps syncing through the follow and only loses its marker; a marker whose promotion is
    /// gone goes with nothing to demote. An incomplete demotion keeps its marker for the next
    /// pass: unsynced edits are never evicted.
    async fn evict_predicted_windows(
        &self,
        target: &PredictedResidenceSet,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let markers = read_rows(vault, |txn| {
            PREDICTED_WINDOW.scan_keys(&vault.store, txn, &[])
        })?;
        if markers.is_empty() {
            return Ok(());
        }
        let pick = crate::sync::residence::load_device_world_pick(vault).map_err(storage)?;
        for marker in &markers {
            let drop_marker = || {
                write_rows(vault, |txn| {
                    PREDICTED_WINDOW.delete(&vault.store, txn, marker).map(drop)
                })
            };
            let Some(window) = WindowKey::try_new(marker) else {
                drop_marker()?;
                continue;
            };
            if target.windows.contains(window.as_str()) {
                continue;
            }
            if window.world().is_some_and(|world| pick.contains(&world)) {
                drop_marker()?;
                continue;
            }
            if vault
                .sync_state_get(&format!("rp:w:{window}"))
                .map_err(storage)?
                .is_none()
            {
                drop_marker()?;
                continue;
            }
            match self.demote_window(&window).await {
                Ok(demotion) if demotion.complete => drop_marker()?,
                Ok(_) => {}
                Err(error) if refuses(&error) => {
                    tracing::warn!(%error, %window, "predicted window not demoted");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Unsubscribes the predicted documents the target dropped whose `qd:e:` queue holds no row,
    /// deleting their `ds:e:` subscription row with their marker. A document with an edit waiting
    /// stays subscribed: unsynced edits are never evicted.
    fn evict_predicted_documents(
        &self,
        target: &PredictedResidenceSet,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let markers = read_rows(vault, |txn| {
            PREDICTED_DOCUMENT.scan_keys(&vault.store, txn, &[])
        })?;
        for marker in &markers {
            if target.documents.contains(&marker.0) {
                continue;
            }
            if !vault
                .sync_state_keys_with_prefix(&format!("qd:e:{}:", marker.0.to_hex()))
                .map_err(storage)?
                .is_empty()
            {
                continue;
            }
            write_rows(vault, |txn| {
                crate::sync::documents::DS_E.delete(&vault.store, txn, marker)?;
                PREDICTED_DOCUMENT
                    .delete(&vault.store, txn, marker)
                    .map(drop)
            })?;
        }
        Ok(())
    }
}
