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
//! - When the home's newest is of a later slot than this clock's, the request
//!   waits for it; a slot another upload took already takes this one too
//!   (FIX 8885).
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
//! the newest generation's outer capsules opened here. An upload it assembles
//! notes the sections it carries unmerged in the record the slot's own upload
//! notes too (`relay_observation`, FIX 19525), which outlives the request. It
//! decides nothing: who executes and what is carried stay as they are.

use std::sync::Arc;

use super::attempt::{self, AttemptKey};
use super::work;
use super::{
    PartSource, ResidenceRpc, fetch_generation, list_generations_for, put_object, refused,
    residence_budgets, storage, turn,
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
    incomplete_authority: Vec<EntityId>,
) {
    let observed = PublishObserved {
        at: vault.store.clock.now_recorded_at(),
        home,
        reach,
        latest,
        incomplete_authority,
    };
    vault.observe_bundle_publication(request, observed);
}

/// Keeps `reach`, with no home and nothing read, for every request asked.
fn observe_all(vault: &Vault, asked: &[(AuthorityEntryHash, EntityId)], reach: PublishReach) {
    for (request, _) in asked {
        observe(
            vault,
            *request,
            None,
            reach,
            LatestRead::NotRead,
            Vec::new(),
        );
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
    // what was observed of a request no longer pending here. Housekeeping
    // that fails stops no publication.
    if let Err(error) = attempt::settle(vault) {
        tracing::warn!(kind = ?error.kind(), "resolved bundle publication attempts stay for now");
    }
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
                Vec::new(),
            );
            continue;
        }
        observe(
            vault,
            request,
            Some(home),
            PublishReach::Reached,
            LatestRead::NotRead,
            Vec::new(),
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
    match work::reconcile_request(rpc, vault, request, home).await? {
        work::WorkFate::Committed(attempt) => {
            // What it carries unmerged stays shown to the owner once the
            // request has its result (FIX 19525).
            super::relay_observation::restore_upload(vault, &attempt);
            return enact(manager, request).await;
        }
        work::WorkFate::Uncertain => return Ok(()),
        work::WorkFate::Open => {}
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
    observe(
        vault,
        request,
        Some(home),
        PublishReach::Reached,
        read.clone(),
        Vec::new(),
    );
    if named {
        return enact(manager, request).await;
    }
    // An asked publication goes on in a slot that has a generation already
    // (FIX 8885); only a newest of a later slot than this clock's waits.
    if latest.is_some_and(|newest| newest.slot > slot) || !turn::ask_turn(rpc, false).await? {
        return Ok(());
    }
    // Without an executor identity no begin addresses: the next machine
    // waiting need not wait out the lease.
    let Some(executor) = work::executor_id(vault).map_err(storage)? else {
        let _ = turn::ask_turn(rpc, true).await;
        return Ok(());
    };
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
    // The owner sees each world this upload could not seal fresh (FIX 12417).
    observe(
        vault,
        request,
        Some(home),
        PublishReach::Reached,
        read,
        upload.incomplete_authority.clone(),
    );
    let generation = upload.bundle.generation();
    // And each readable section it carries unmerged, in the one record the
    // slot's own upload notes too, which outlives the request (FIX 19525).
    super::relay_observation::observe_upload(
        vault,
        Some(home),
        generation,
        &upload.unmerged_sections,
    );
    let staged = put_object(
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
        .await?;
    if staged {
        let mut attempt = attempt::BundleAttempt {
            home: Some(home),
            executor,
            generation,
            bundle_digest: upload.bundle.digest(),
            parent: latest,
            root: upload.kit_root,
            request: Some(request),
            bundle_total: upload.bundle.as_bytes().len() as u64,
            pads_total: upload.pads.as_bytes().len() as u64,
            pads_digest: upload.pads.digest(),
            incomplete_authority: upload.incomplete_authority.clone(),
            awaiting_reader: Vec::new(),
            unmerged_sections: upload.unmerged_sections.clone(),
            assembled_at: Some(vault.store.clock.peek_recorded_at()),
        };
        // The exact attempt persists before the first commit send, so an ack
        // lost on the way resumes, never reuploads.
        attempt::persist(vault, AttemptKey::Request(request), &mut attempt).map_err(storage)?;
        match work::begin_work(rpc, &attempt).await? {
            work::WorkOutcome::Accepted(status) => match status.state {
                work::WorkState::Pending => return Ok(()),
                work::WorkState::Committed => {
                    let entry = status.entry.ok_or_else(refused)?;
                    let enacted = match BUNDLE_PUBLISH_COMPLETION {
                        PublishCompletion::HomeCommitWithRequest => {
                            entry.generation == generation
                                && entry.bundle_digest == upload.bundle.digest()
                        }
                    };
                    if enacted {
                        return enact(manager, request).await;
                    }
                    return Err(refused());
                }
                work::WorkState::NeedsRebase | work::WorkState::Refused => {
                    attempt::settle_one(vault, AttemptKey::Request(request), &attempt)
                        .map_err(storage)?;
                }
            },
            work::WorkOutcome::Refused => {
                attempt::settle_one(vault, AttemptKey::Request(request), &attempt)
                    .map_err(storage)?;
            }
        }
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
