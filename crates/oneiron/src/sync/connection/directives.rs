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

use crate::Vault;
use crate::authority::{ResidenceAct, ResidenceResultStatus};
use crate::sync::TransportError;
use crate::sync::client::{SyncEvent, SyncResidenceMode};
use crate::sync::residence::{
    ResidenceDirectiveState, finish_residence_directive_in_txn, pending_residence_directives,
    residence_refusal_reason,
};

use super::SyncConnection;

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// Whether `error` says the directive does not apply on this machine, as a
/// refused residence call does, rather than that it cannot run yet.
fn refuses(error: &TransportError) -> bool {
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

impl SyncConnection {
    /// Runs a round of the owner's residence directives each time the
    /// upkeep wakes them. When a round finished one, the authority catch-up
    /// runs again, so the results reach the home by its append half.
    pub(super) async fn run_residence_directives(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> std::convert::Infallible {
        loop {
            self.directive_wake.notified().await;
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
    async fn apply_residence_directives(&self) -> Result<usize, TransportError> {
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

    /// Runs one directive and records its result. A mode switch and a prune
    /// commit with their result; an open and the index read commit nothing
    /// a second run would change, then the result.
    async fn apply_residence_directive(
        &self,
        pending: &ResidenceDirectiveState,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        match &pending.directive.act {
            ResidenceAct::SyncAll | ResidenceAct::SyncOpened => {
                let mode = if pending.directive.act == ResidenceAct::SyncAll {
                    SyncResidenceMode::All
                } else {
                    SyncResidenceMode::Opened
                };
                self.switch_residence_mode(mode, |txn, change| {
                    let count = match change.mode {
                        SyncResidenceMode::All => change.pruned_items,
                        SyncResidenceMode::Opened => change.retained.len(),
                    };
                    applied(vault, txn, pending, count)
                })
                .await?;
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
        }
        Ok(())
    }
}
