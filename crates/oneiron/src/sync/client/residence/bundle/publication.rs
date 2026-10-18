//! The owner's ask to publish the vault's sealed bundle (WILL L04 row 03), run
//! by the install his counted request names, in any role and on any
//! substrate. Each relay pass runs it first, after the authority catch-up,
//! with no timer, queue or attempt record of its own.
//!
//! For each pending publication naming this install whose home is the one
//! this machine reaches, it lists and reads the home's newest generation,
//! naming the request, which the home admits it under:
//! - When that generation names the request and this install sealed it, a
//!   commit whose ack was lost stands, and the request is enacted.
//! - When another upload already took the slot, the request waits for the
//!   next one.
//! - Otherwise, once it holds the publisher turn, it assembles with the
//!   request in the bundle's signed provenance, stages both objects and
//!   commits on the parent it read. The home's ack of that commit enacts the
//!   request (CALLS BUNDLE_PUBLISH_COMPLETION), in a writer transaction of its
//!   own that first rechecks the request is still pending and its owner live.
//!
//! Busy, offline, missing keys, a refused upload or an uncertain ack leave it
//! pending for the next pass.

use std::sync::Arc;

use super::{
    CommittedBundle, PartSource, ResidenceRpc, commit_generation, fetch_generation,
    list_generations_for, put_object, refused, residence_budgets, storage, turn,
};
use crate::EntityId;
use crate::authority::{AuthorityEntryHash, Destination, PeerMachine};
use crate::sync::client::SyncClientConfig;
use crate::sync::manager::WindowManager;
use crate::sync::residence::SealedBundleObject;
use crate::sync::transport::TransportError;
use crate::world_keys::sealed_bundle_slot;

/// When a publication's request is enacted (CALLS
/// BUNDLE_PUBLISH_COMPLETION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishCompletion {
    /// The home acknowledged committing the generation this install staged
    /// for the request, with that bundle's digest; or, after a lost ack, the
    /// home's newest generation names the request in its signed provenance
    /// and this install sealed it. A stage, a slot another upload took, a
    /// generic result or replication never is.
    HomeCommitWithRequest,
}

const BUNDLE_PUBLISH_COMPLETION: PublishCompletion = PublishCompletion::HomeCommitWithRequest;

fn stopped(error: tokio::task::JoinError) -> TransportError {
    TransportError::Storage(error.to_string())
}

/// Runs each pending publication naming this install for the home `config`
/// reaches. One that does not finish stays pending, and the pass goes on to
/// the slot's cadence.
pub(super) async fn publish_asked(manager: &Arc<WindowManager>, config: &SyncClientConfig) {
    if let Err(error) = publish_all(manager, config).await {
        tracing::warn!(%error, "an asked sealed bundle publication stays pending");
    }
}

async fn publish_all(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<(), TransportError> {
    let vault = manager.vault();
    // A federation lane reaches another vault's home.
    if config.federation_peer.is_some() {
        return Ok(());
    }
    let asked = vault.pending_bundle_publications().map_err(storage)?;
    if asked.is_empty() {
        return Ok(());
    }
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Ok(());
    };
    let PeerMachine::Proven { machine: home, .. } = vault.peer_machine_stands(rpc.home) else {
        return Ok(());
    };
    for (request, _) in asked.into_iter().filter(|(_, to)| *to == home) {
        publish_one(manager, &mut rpc, request, home).await?;
    }
    Ok(())
}

/// One request's publication to `home`, which `rpc` reaches.
async fn publish_one(
    manager: &Arc<WindowManager>,
    rpc: &mut ResidenceRpc,
    request: AuthorityEntryHash,
    home: EntityId,
) -> Result<(), TransportError> {
    let holder = Destination::Machine(home);
    let slot = sealed_bundle_slot(manager.vault().store.clock.now_recorded_at());
    let latest = list_generations_for(rpc, Some(request))
        .await?
        .first()
        .copied();
    let mut held = match latest {
        None => None,
        Some(newest) => Some(
            fetch_generation(&mut PartSource::Asked(rpc, request), Some(newest))
                .await?
                .ok_or_else(refused)?,
        ),
    };
    // A commit whose ack was lost: the newest names the request, sealed here.
    if let Some((bundle, pads)) = held.take() {
        let reading = Arc::clone(manager);
        let (named, bundle) = tokio::task::spawn_blocking(move || {
            let named = reading
                .vault()
                .bundle_names_request(&bundle, holder, request);
            (named, bundle)
        })
        .await
        .map_err(stopped)?;
        if named.map_err(storage)? {
            return enact(manager, request).await;
        }
        held = Some((bundle, pads));
    }
    if latest.is_some_and(|newest| newest.slot >= slot) || !turn::ask_turn(rpc, false).await? {
        return Ok(());
    }
    let assembling = Arc::clone(manager);
    let upload = turn::renewing_turn(rpc, move || {
        assembling.assemble_sealed_bundle(
            slot,
            holder,
            held.as_ref().map(|(bundle, pads)| (bundle, pads)),
            Some(request),
        )
    })
    .await?;
    let upload = match upload {
        Ok(upload) => upload,
        Err(error) => {
            // The next machine waiting need not wait out the lease.
            let _ = turn::ask_turn(rpc, true).await;
            return Err(storage(error));
        }
    };
    let generation = upload.bundle.generation();
    let committed = if put_object(
        rpc,
        &generation,
        SealedBundleObject::Bundle,
        upload.bundle.as_bytes(),
    )
    .await?
        && put_object(
            rpc,
            &generation,
            SealedBundleObject::Pads,
            upload.pads.as_bytes(),
        )
        .await?
    {
        commit_generation(rpc, &generation, latest, upload.kit_root).await?
    } else {
        None
    };
    let enacted = match BUNDLE_PUBLISH_COMPLETION {
        PublishCompletion::HomeCommitWithRequest => {
            committed
                == Some(CommittedBundle {
                    generation,
                    bundle_digest: upload.bundle.digest(),
                })
        }
    };
    if enacted {
        return enact(manager, request).await;
    }
    let _ = turn::ask_turn(rpc, true).await;
    Ok(())
}

/// Appends the request's enacted result in a writer transaction of its own,
/// off the runtime ([`crate::Vault::enact_bundle_publication`]).
async fn enact(
    manager: &Arc<WindowManager>,
    request: AuthorityEntryHash,
) -> Result<(), TransportError> {
    let vault = Arc::clone(manager.vault());
    tokio::task::spawn_blocking(move || vault.enact_bundle_publication(request))
        .await
        .map_err(stopped)?
        .map_err(storage)?;
    Ok(())
}
