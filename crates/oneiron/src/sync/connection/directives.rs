//! The owner's residence directives, applied on the machine they name
//! (OF-534). They run beside the connection loop, across its reconnects,
//! each time the residence upkeep wakes them once the authority history is
//! in. Each pending directive runs in the order the owner issued it, through
//! the same `SyncConnection` methods the owner's residence rows call on a
//! host that runs this connection, and records its result
//! (`sync::residence::directives`). A directive that cannot run yet (the home
//! offline, say) holds back the ones after it until the next wake; one that
//! does not apply on this machine is reported refused, once.

use tokio::sync::mpsc;

use crate::EntityId;
use crate::Vault;
use crate::authority::{ResidenceAct, ResidenceDirective, ResidenceResultStatus};
use crate::sync::TransportError;
use crate::sync::client::{SyncEvent, SyncResidenceMode};
use crate::sync::residence::{
    ResidenceDirectiveState, finish_residence_directive_in_txn, load_device_sync_preference,
    pending_residence_directives, residence_refusal_reason,
};

use super::SyncConnection;

/// Wraps a storage failure for the transport boundary.
pub(super) fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// Whether `error` says the directive does not apply on this machine, as a
/// refused residence call does, rather than that it cannot run yet.
pub(super) fn refuses(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::InvalidPayload(_)
            | TransportError::InvalidWindowKey
            | TransportError::AdmissionDenied(_)
    )
}

/// Records an applied directive's result in the act's own transaction.
fn applied(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pending: &ResidenceDirectiveState,
    count: usize,
) -> crate::error::Result<()> {
    finish_residence_directive_in_txn(
        vault,
        txn,
        pending,
        ResidenceResultStatus::Applied,
        u64::try_from(count).unwrap_or(u64::MAX),
        None,
    )
    .map(drop)
}

/// The owner's budget the prediction `pending` names through `parent`: its parent's, once the
/// owner's live predicted level for this machine is that directive and no newer prediction
/// replaced it (Engine ruling PLAN-SIGNER A).
fn check_prediction_parent(
    pending: &ResidenceDirectiveState,
    directives: &[ResidenceDirective],
    parent: EntityId,
) -> Result<(u32, u32), TransportError> {
    let mut last: Option<(EntityId, u32, u32)> = None;
    let mut later = false;
    for directive in directives {
        match &directive.act {
            ResidenceAct::SyncPredicted {
                window_budget,
                document_budget,
            } => {
                last = Some((directive.id, *window_budget, *document_budget));
            }
            ResidenceAct::SyncAll | ResidenceAct::SyncOpened => {
                last = None;
            }
            ResidenceAct::Predicted { .. }
                if (directive.issued_at, directive.id)
                    > (pending.directive.issued_at, pending.directive.id) =>
            {
                later = true;
            }
            _ => {}
        }
    }
    match last {
        Some((id, window_budget, document_budget)) if id == parent => {
            if later {
                return Err(TransportError::InvalidPayload(
                    "a newer prediction replaced it",
                ));
            }
            Ok((window_budget, document_budget))
        }
        _ => Err(TransportError::InvalidPayload(
            "a prediction applies under the owner's live predicted level",
        )),
    }
}

impl SyncConnection {
    /// Runs a round of the owner's residence directives each time the
    /// upkeep wakes them. When a round finished one, the authority catch-up
    /// runs again, so the results reach the home by its append half. Each
    /// round holds the host's admission, a pause waited out (FIX 12036).
    pub(super) async fn run_residence_directives(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> std::convert::Infallible {
        loop {
            self.directive_wake.notified().await;
            let _round = self.admit_round().await;
            match self.apply_residence_directives().await {
                Ok(0) | Err(TransportError::InvalidPayload(_)) => {}
                Ok(_) => {
                    if let Err(error) = self.catch_up_authority().await
                        && !matches!(error, TransportError::InvalidPayload(_))
                    {
                        let _ = events.send(SyncEvent::Error(format!(
                            "Authority catch-up failed: {error}"
                        )));
                    }
                }
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Residence directives failed: {error}"
                    )));
                }
            }
        }
    }

    /// Runs every pending directive naming this machine, oldest first, and
    /// returns how many it finished. A federation lane runs none.
    pub(crate) async fn apply_residence_directives(&self) -> Result<usize, TransportError> {
        if self.config.client_config.federation_peer.is_some() {
            return Ok(0);
        }
        let vault = self.manager.vault();
        let mut finished = 0;
        for pending in pending_residence_directives(vault).map_err(storage)? {
            match self.apply_residence_directive(&pending).await {
                Ok(()) => finished += 1,
                Err(error) if refuses(&error) => {
                    let reason = residence_refusal_reason(&error.to_string());
                    vault
                        .with_write_txn_grouped(|txn| {
                            finish_residence_directive_in_txn(
                                vault,
                                txn,
                                &pending,
                                ResidenceResultStatus::Refused,
                                0,
                                Some(reason),
                            )
                            .map(drop)
                        })
                        .map_err(storage)?;
                    finished += 1;
                }
                Err(error) if finished == 0 => return Err(error),
                Err(error) => {
                    tracing::debug!(%error, "residence directive waits for the next upkeep");
                    break;
                }
            }
        }
        Ok(finished)
    }

    /// Runs one directive and records its result. A mode switch, a world
    /// pick and a prune commit with their result; an open and the index read
    /// commit nothing a second run would change, then the result.
    async fn apply_residence_directive(
        &self,
        pending: &ResidenceDirectiveState,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        match &pending.directive.act {
            ResidenceAct::SyncAll
            | ResidenceAct::SyncOpened
            | ResidenceAct::SyncPredicted { .. } => {
                // The predicted level runs as opened on the wire; its budget
                // binds the home's predictions, which name this directive.
                let (mode, predicted) = match pending.directive.act {
                    ResidenceAct::SyncAll => (SyncResidenceMode::All, false),
                    ResidenceAct::SyncPredicted { .. } => (SyncResidenceMode::Opened, true),
                    _ => (SyncResidenceMode::Opened, false),
                };
                self.switch_residence_mode(mode, predicted, |txn, change| {
                    let count = match change.mode {
                        SyncResidenceMode::All => change.pruned_items,
                        SyncResidenceMode::Opened => change.retained.len(),
                    };
                    applied(vault, txn, pending, count)
                })
                .await?;
            }
            ResidenceAct::Follow { worlds } => {
                self.switch_followed_worlds(worlds.clone(), |txn| {
                    applied(vault, txn, pending, worlds.len())
                })?;
            }
            ResidenceAct::Open { window, item } => {
                let window = crate::sync::WindowKey::try_new(window.as_str())
                    .ok_or(TransportError::InvalidWindowKey)?;
                self.open_item(&window, *item).await?;
                vault
                    .with_write_txn_grouped(|txn| applied(vault, txn, pending, 1))
                    .map_err(storage)?;
            }
            ResidenceAct::Index => {
                let windows = self.residence_index()?;
                vault
                    .with_write_txn_grouped(|txn| applied(vault, txn, pending, windows.len()))
                    .map_err(storage)?;
            }
            ResidenceAct::Prune { before } => {
                self.prune_opened_items_with(*before, |txn, pruned| {
                    applied(vault, txn, pending, pruned)
                })?;
            }
            ResidenceAct::Predicted {
                parent,
                set_digest,
                window_count,
                document_count,
            } => {
                self.apply_prediction(pending, *parent, set_digest, *window_count, *document_count)
                    .await?;
            }
        }
        Ok(())
    }

    /// Applies the home's prediction for this machine at the predicted level (ARCH-0023b
    /// #predicted-residence): under the owner's live predicted level within its budget
    /// (PLAN-SIGNER A), the set fetched by its digest and refused unless it matches
    /// (BUDGET-CEILING), then adopted as this machine's target. A transport failure that is no
    /// refusal holds the directive for the next round: the prediction freezes while the home is
    /// down.
    async fn apply_prediction(
        &self,
        pending: &ResidenceDirectiveState,
        parent: EntityId,
        set_digest: &[u8; 32],
        window_count: u32,
        document_count: u32,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let predicted = load_device_sync_preference(vault)
            .map_err(storage)?
            .is_some_and(|preference| preference.predicted);
        if !predicted {
            return Err(TransportError::InvalidPayload(
                "a prediction applies on a machine at the predicted level",
            ));
        }
        let machine = vault
            .local_machine()
            .map_err(storage)?
            .map(|local| local.id)
            .ok_or(TransportError::InvalidPayload(
                "a prediction applies under the owner's live predicted level",
            ))?;
        let directives = Self::directives_naming_machine(vault, machine).map_err(storage)?;
        let (window_budget, document_budget) =
            check_prediction_parent(pending, &directives, parent)?;
        if window_count > window_budget || document_count > document_budget {
            return Err(TransportError::InvalidPayload(
                "a prediction exceeds the owner's budget",
            ));
        }
        let mut client = self.client()?;
        let body = client.fetch_predicted_set(set_digest).await?;
        let set = crate::authority::PredictedResidenceSet::decode_verified(&body, set_digest)
            .map_err(|_| {
                TransportError::InvalidPayload("the predicted set does not match its digest")
            })?;
        if set.counts() != Some((window_count, document_count)) {
            return Err(TransportError::InvalidPayload(
                "the predicted set does not match its counts",
            ));
        }
        vault
            .with_write_txn_grouped(|txn| {
                super::predicted::PREDICTED_TARGET.put(&vault.store, txn, &(), &body)?;
                applied(vault, txn, pending, set.windows.len() + set.documents.len())
            })
            .map_err(storage)?;
        self.predicted_wake.notify_one();
        Ok(())
    }
}
