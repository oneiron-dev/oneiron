//! The owner's ask to publish the vault's sealed bundle (WILL L04 row 03), run
//! by the install his counted request names, in any role and on any
//! substrate. Each relay pass runs it first, after the authority catch-up,
//! with no timer or queue of its own; the one record it keeps is the exact
//! attempt it persists before a commit (FIX 4787).
//!
//! For each pending publication naming this install whose home is the one
//! this machine reaches, it first reconciles an attempt it persisted and has
//! not resolved with the home's record of the request's commit (`attempt`,
//! CALLS BUNDLE_PUBLISH_RECONCILE): a recorded commit enacts the request, and
//! an unanswered read leaves it pending. Then it lists and reads the home's
//! newest generation, naming the request, which the home admits it under:
//! - When that generation names the request and this install sealed it, a
//!   commit whose ack was lost stands, and the request is enacted.
//! - When another upload already took the slot, the request waits for the
//!   next one.
//! - Otherwise, once it holds the publisher turn, it assembles with the
//!   request in the bundle's signed provenance, stages both objects and
//!   commits on the parent it read, naming the request, after persisting
//!   the exact attempt. The home's ack of that commit enacts the request
//!   (CALLS BUNDLE_PUBLISH_COMPLETION), in a writer transaction of its own
//!   that first rechecks the request is still pending and its owner live.
//!
//! Busy, offline, missing keys, a refused upload or an uncertain ack leave it
//! pending for the next pass. Each pass keeps what it saw for the owner's
//! diagnostics (FIX 4784, 4785): the home it reached, or why none, and how
//! the newest generation's outer capsules opened here. It decides nothing:
//! who executes and what is carried stay as they are.

use std::sync::Arc;

use super::attempt::{self, Reconciled};
use super::{
    PartSource, ResidenceRpc, commit_generation, fetch_generation, list_generations_for,
    put_object, refused, residence_budgets, storage, turn,
};
use crate::authority::{AuthorityEntryHash, Destination, PeerMachine};
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::residence::SealedBundleObject;
use crate::sync::transport::TransportError;
use crate::world_keys::{LatestRead, PublishObserved, PublishReach, sealed_bundle_slot};
use crate::{EntityId, Vault};

/// When a publication's request is enacted (CALLS
/// BUNDLE_PUBLISH_COMPLETION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishCompletion {
    /// The home acknowledged committing the generation this install staged
    /// for the request, with that bundle's digest; or, after a lost ack, the
    /// home recorded a commit of this install's for the request (FIX 4787),
    /// or its newest generation names the request in its signed provenance
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

/// Keeps what this pass saw for `request` (FIX 4784, 4785).
fn observe(
    vault: &Vault,
    request: AuthorityEntryHash,
    home: Option<EntityId>,
    reach: PublishReach,
    latest: LatestRead,
) {
    let observed = PublishObserved {
        at: vault.store.clock.now_recorded_at(),
        home,
        reach,
        latest,
    };
    vault.observe_bundle_publication(request, observed);
}

/// Keeps `reach`, with no home and nothing read, for every request asked.
fn observe_all(vault: &Vault, asked: &[(AuthorityEntryHash, EntityId)], reach: PublishReach) {
    for (request, _) in asked {
        observe(vault, *request, None, reach, LatestRead::NotRead);
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
    // What is resolved goes: an attempt whose request has its result, and
    // what was observed of a request no longer pending here.
    attempt::settle(vault).map_err(storage)?;
    vault.keep_bundle_publication_observations(&asked);
    if asked.is_empty() {
        return Ok(());
    }
    let budgets = residence_budgets(vault)?;
    let mut rpc = match ResidenceRpc::connect(vault, config, budgets).await {
        Ok(Some(rpc)) => rpc,
        Ok(None) => {
            observe_all(vault, &asked, PublishReach::Offline);
            return Ok(());
        }
        Err(error) => {
            observe_all(vault, &asked, PublishReach::Refused);
            return Err(error);
        }
    };
    let PeerMachine::Proven { machine: home, .. } = vault.peer_machine_stands(rpc.home) else {
        observe_all(vault, &asked, PublishReach::HomeUnproven);
        return Ok(());
    };
    // A full machine lands what the assembly merges (FIX 4788).
    let materialize = config.residence_mode == SyncResidenceMode::All;
    for (request, to) in asked {
        if to != home {
            observe(
                vault,
                request,
                Some(home),
                PublishReach::OtherHome,
                LatestRead::NotRead,
            );
            continue;
        }
        observe(
            vault,
            request,
            Some(home),
            PublishReach::Reached,
            LatestRead::NotRead,
        );
        publish_one(manager, &mut rpc, request, home, materialize).await?;
    }
    Ok(())
}

/// One request's publication to `home`, which `rpc` reaches. `materialize`
/// is a full machine's: the windows its assembly merges land here too.
async fn publish_one(
    manager: &Arc<WindowManager>,
    rpc: &mut ResidenceRpc,
    request: AuthorityEntryHash,
    home: EntityId,
    materialize: bool,
) -> Result<(), TransportError> {
    let vault = manager.vault();
    let holder = Destination::Machine(home);
    let slot = sealed_bundle_slot(vault.store.clock.now_recorded_at());
    // An attempt this install persisted and has not resolved comes first
    // (CALLS BUNDLE_PUBLISH_RECONCILE).
    match attempt::reconcile(vault, rpc, request, home).await? {
        Reconciled::Committed => return enact(manager, request).await,
        Reconciled::Uncertain => return Ok(()),
        Reconciled::Open => {}
    }
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
    // How its outer capsules open here is kept for the owner (FIX 4785).
    let (named, read) = match held.take() {
        None => (false, LatestRead::NoneKept),
        Some((bundle, pads)) => {
            let reading = Arc::clone(manager);
            let (read, bundle, pads) = tokio::task::spawn_blocking(move || {
                let read = reading
                    .vault()
                    .read_latest_for_request(&bundle, &pads, holder, request);
                (read, bundle, pads)
            })
            .await
            .map_err(stopped)?;
            held = Some((bundle, pads));
            read.map_err(storage)?
        }
    };
    observe(vault, request, Some(home), PublishReach::Reached, read);
    if named {
        return enact(manager, request).await;
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
            materialize,
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
        // The exact attempt is persisted before the commit, so an ack lost
        // on the way is reconciled, never published again (FIX 4787).
        attempt::persist(vault, request, home, generation, upload.bundle.digest())
            .map_err(storage)?;
        commit_generation(rpc, &generation, latest, upload.kit_root, Some(request)).await?
    } else {
        None
    };
    let enacted = match BUNDLE_PUBLISH_COMPLETION {
        PublishCompletion::HomeCommitWithRequest => committed.is_some_and(|entry| {
            entry.generation == generation && entry.bundle_digest == upload.bundle.digest()
        }),
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
