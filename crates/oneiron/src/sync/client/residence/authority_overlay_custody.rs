//! One page-by-page authority overlay key round with this machine's
//! residence home (census L5-22 1a-iii commit 7): inventories, retirements
//! and keys sealed to each receiver's fresh session go both ways. The
//! round holds no seal after it sends or applies it, and stores none. A
//! home out of reach is retried on the next upkeep pass.

use std::sync::Arc;

use super::rpc::RpcFault;
use super::{ResidenceRpc, residence_budgets};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::sync::authority_overlay_custody::{apply_overlay_answer, offer_overlay_page};
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::{
    overlay_answer_from_wire, overlay_keys_to_wire, overlay_offer_to_wire,
};
use crate::sync::transport::TransportError;

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> Result<T, TransportError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| TransportError::Storage("authority overlay exchange work stopped".into()))?
        .map_err(storage)
}

/// Exchanges every page with the home this socket proved and this
/// machine's own authority fold trusts; an unavailable home waits for the
/// next pass.
///
/// # Errors
/// Storage and custody faults, a malformed answer, or a failed page RPC.
pub(crate) async fn exchange_authority_overlay_custody(
    vault: &Arc<Vault>,
    config: &SyncClientConfig,
) -> Result<(), TransportError> {
    if config.federation_peer.is_some() || config.residence_selector.is_none() {
        return Ok(());
    }
    let Some(local) = vault
        .local_machine()
        .map_err(storage)?
        .filter(|machine| machine.mine)
    else {
        return Ok(());
    };
    let machine = local.id;
    let connected = match residence_budgets(vault) {
        Ok(budgets) => ResidenceRpc::connect_by_side(vault, config, budgets).await,
        Err(error) => Err(RpcFault::Local(error)),
    };
    let (mut rpc, home, key) = match connected {
        Ok(Some(rpc)) => match rpc.home {
            PeerMachine::Proven { machine, key } => (rpc, machine, key),
            PeerMachine::Unknown => {
                tracing::debug!("authority overlay exchange: the home proved no machine");
                return Ok(());
            }
        },
        Ok(None) => {
            tracing::debug!("authority overlay exchange: the home is out of reach");
            return Ok(());
        }
        Err(RpcFault::Remote(error)) => {
            tracing::debug!(%error, "authority overlay exchange: the home refused its socket");
            return Ok(());
        }
        Err(RpcFault::Local(error)) => {
            tracing::debug!(%error, "authority overlay exchange: this machine's socket not set up");
            return Ok(());
        }
    };
    let trusted = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .map_err(storage)?;
        let fold = vault
            .authority_fold_readonly_in_txn(&txn)
            .map_err(storage)?;
        fold.trusted_machine(home).is_some() && fold.machine_proof_key(home) == Some(key)
    };
    if !trusted {
        tracing::debug!("authority overlay exchange: this machine does not trust the proven home");
        return Ok(());
    }
    let mut after = None;
    loop {
        let held = Arc::clone(vault);
        let (offer, page_session) =
            blocking(move || offer_overlay_page(&held, &machine, &home, after)).await?;
        let reply = rpc
            .request(
                "residence.authority_overlay.offer",
                overlay_offer_to_wire(&offer),
            )
            .await?;
        let answer = overlay_answer_from_wire(reply).ok_or(TransportError::InvalidPayload(
            "malformed authority overlay answer",
        ))?;
        let through = answer.through;
        let held = Arc::clone(vault);
        let keys = blocking(move || {
            apply_overlay_answer(&held, &machine, &home, &offer, &page_session, answer)
        })
        .await?;
        if !keys.is_empty() {
            let reply = rpc
                .request(
                    "residence.authority_overlay.keys",
                    overlay_keys_to_wire(&keys),
                )
                .await?;
            tracing::debug!(
                installed = ?reply.get("installed"),
                "authority overlay keys answered by the home"
            );
        }
        match through {
            Some(through) if after.is_none_or(|after| through > after) => after = Some(through),
            _ => return Ok(()),
        }
    }
}
