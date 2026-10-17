//! The owner's residence directives, applied on the machine they name
//! (OF-534). A lane's residence upkeep, off the live loop, runs each pending
//! directive in the order the owner issued them, through the same doors the
//! machine's own residence calls use, and records its result
//! (`sync::residence::directives`). A directive that cannot run yet (the home
//! offline, say) holds back the ones after it until the next upkeep; one that
//! does not apply on this machine is reported refused, once.

use std::sync::Arc;

use crate::Vault;
use crate::authority::{ResidenceAct, ResidenceResultStatus};
use crate::sync::TransportError;
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::residence::{
    ResidenceDirectiveState, finish_residence_directive_in_txn, pending_residence_directives,
    prune_thin_items_in_txn, residence_refusal_reason,
};

/// One lane's directive rounds, one at a time: a reconnect starts a new
/// upkeep while the last may still be applying.
pub(super) type DirectiveRound = tokio::sync::Mutex<()>;

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

/// Runs every pending directive naming this machine, oldest first, and
/// returns how many it finished. A federation lane runs none.
pub(super) async fn apply_residence_directives(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
    mode: &tokio::sync::watch::Sender<SyncResidenceMode>,
    round: &DirectiveRound,
) -> Result<usize, TransportError> {
    if config.federation_peer.is_some() {
        return Ok(0);
    }
    let _round = round.lock().await;
    let vault = manager.vault();
    let mut finished = 0;
    for pending in pending_residence_directives(vault).map_err(storage)? {
        // A mode directive earlier in the round changes what the rest run
        // under.
        let mut config = config.clone();
        config.residence_mode = *mode.borrow();
        match apply_directive(manager, &config, mode, &pending).await {
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

/// Runs one directive and records its result. A local act commits with its
/// result; an act the home answers commits its own rows, then the result.
async fn apply_directive(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
    mode: &tokio::sync::watch::Sender<SyncResidenceMode>,
    pending: &ResidenceDirectiveState,
) -> Result<(), TransportError> {
    let vault = manager.vault();
    match &pending.directive.act {
        ResidenceAct::SyncAll | ResidenceAct::SyncOpened => {
            let target = if pending.directive.act == ResidenceAct::SyncAll {
                SyncResidenceMode::All
            } else {
                SyncResidenceMode::Opened
            };
            super::switch_residence_mode(manager, config, mode, target, |txn, change| {
                let count = match change.mode {
                    SyncResidenceMode::All => change.pruned_items,
                    SyncResidenceMode::Opened => change.retained.len(),
                };
                applied(vault, txn, pending, count)
            })
            .await?;
        }
        ResidenceAct::Open {
            window,
            item,
            promote,
        } => {
            let window = crate::sync::WindowKey::try_new(window.as_str())
                .ok_or(TransportError::InvalidWindowKey)?;
            let (mut client, _events) =
                crate::sync::SyncClient::new(Arc::clone(manager), config.clone())
                    .map_err(storage)?;
            client.open_item(&window, *item).await?;
            // A machine that syncs all holds its windows in full already.
            if *promote
                && config.residence_mode == SyncResidenceMode::Opened
                && vault
                    .sync_state_get(&format!("rp:w:{window}"))
                    .map_err(storage)?
                    .is_none()
            {
                client.promote_window(&window, *item).await?;
            }
            vault
                .with_write_txn_grouped(|txn| applied(vault, txn, pending, 1))
                .map_err(storage)?;
        }
        ResidenceAct::Index => {
            let (client, _events) =
                crate::sync::SyncClient::new(Arc::clone(manager), config.clone())
                    .map_err(storage)?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let windows = client.refresh_residence_index(now_secs).await?;
            vault
                .with_write_txn_grouped(|txn| applied(vault, txn, pending, windows.len()))
                .map_err(storage)?;
        }
        ResidenceAct::Prune { before } => {
            vault
                .with_write_txn_grouped(|txn| {
                    let pruned = prune_thin_items_in_txn(vault, txn, *before)?;
                    applied(vault, txn, pending, pruned)
                })
                .map_err(storage)?;
        }
    }
    Ok(())
}
