//! A late joiner's pad access by the owner's kit, and what the sealed bundle
//! upkeep last moved (FIX 4564, 4953, 4954).
//!
//! - `POST /recovery-kit/pad-access`: the kit grants a machine every pad
//!   object the home keeps. With a home connection, through it
//!   (`SyncConnection::grant_sealed_bundle_pad_access_with_kit`); with none,
//!   on this install when it keeps the generations itself, the home
//!   (`grant_local_sealed_pad_access_with_kit`). Neither is a home out of
//!   reach here: `home_unavailable`, and nothing is granted. The answer is
//!   what was offered, what is usable here and what stays pending, by
//!   generation; an offer is not access.
//! - `GET /recovery-kit/upkeep`: the last relay the upkeep took to the home,
//!   the pending counts of the last one whose erase sweep counted them, the
//!   last relay that failed, each with its time, and the last kit grant this
//!   process answered (CALLS "4953 relay report"). Unobserved is said, never
//!   read as zero; pending counts are observations, not promises. Nothing
//!   here waits on the upkeep or expires.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EntityId;
use oneiron::sync::client::{SealedBundleRelayObservation, sealed_bundle_relay_observation};
use oneiron::sync::residence::{grant_local_sealed_pad_access_with_kit, sealed_generation_hex};
use oneiron::world_keys::{PadAdmissionTarget, RecoveryRootSeed, SealedBundleGeneration};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner, owner_error};
use super::{Kit, OwnerDevice, kit_target, kit_target_refused};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::stamp::{now_unix_ms, rfc3339, rfc3339_secs};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The refusal of a grant with no home in reach: no connection to one, and
/// no generation kept here.
const HOME_UNAVAILABLE: &str = "home_unavailable";

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/recovery-kit/pad-access", post(pad_access))
        .route("/recovery-kit/upkeep", get(upkeep))
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PadAccess {
    /// The install this call's kit is for, 32 hex: this one.
    target: String,
    /// The kit's pieces, as recovery codes.
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    /// The machine to grant, 32 hex; none grants this install.
    #[serde(default)]
    machine: Option<String>,
}

/// Where the kept pad objects a grant reached are.
#[derive(Clone, Copy, Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum PadAccessHome {
    /// The home this install's connection reaches.
    Connection,
    /// This install: it keeps the generations itself.
    ThisInstall,
}

/// What a kit grant of pad access did, by kept generation (hex).
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
struct PadAccessAnswer {
    /// The machine granted, 32 hex.
    machine: String,
    home: PadAccessHome,
    /// Generations whose grant the home took.
    offered: Vec<String>,
    /// Of those, the ones this install opened its pad object with: only
    /// when the machine granted is this one. An offered grant is not yet
    /// access.
    usable: Vec<String>,
    /// Generations the kit did not open, or whose offer the home refused:
    /// pending with the home for an old reader.
    pending: Vec<String>,
    /// How many are pending.
    pending_count: usize,
}

/// The OpenAPI schema of `POST /v1/owner/recovery-kit/pad-access`'s body (FIX 11611):
/// [`PadAccess`].
pub(crate) fn pad_access_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PadAccess>()
}

/// The OpenAPI schema of `POST /v1/owner/recovery-kit/pad-access`'s answer (FIX 11611):
/// [`PadAccessAnswer`].
pub(crate) fn pad_access_answer_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PadAccessAnswer>()
}

/// `POST /v1/owner/recovery-kit/pad-access`: the owner's kit grants a
/// machine (this install when none is named) access to every pad object the
/// home keeps, over this install's own connection to its home, or here when
/// this install keeps them. The machine must stand as the owner's here; the
/// engine checks it, the owner and the kit's root again for every grant.
async fn pad_access(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<PadAccess>,
) -> OwnerReply<PadAccessAnswer> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    let vault = Arc::clone(&server.vault);
    let (seed, recipient, me) = blocking(
        move || -> OwnerResult<(RecoveryRootSeed, PadAdmissionTarget, EntityId)> {
            let kit = Kit::parse(body.pieces, body.passphrase)?;
            let me = vault
                .local_machine()?
                .ok_or_else(|| OwnerError::Refused("this install is no machine yet".to_owned()))?
                .id;
            let machine = match body.machine.as_deref() {
                Some(machine) => entity_id("machine", machine)?,
                None => me,
            };
            let fold = vault.authority_fold()?;
            let trusted = fold.trusted_machine(machine).ok_or_else(|| {
                OwnerError::Refused("the machine does not stand as the owner's here".to_owned())
            })?;
            let recipient = PadAdmissionTarget::of(machine, &trusted.profile.encryption_key);
            Ok((kit.seed(&vault)?, recipient, me))
        },
    )
    .await?;
    let (home, report) = match crate::residence_machines::connection(&me) {
        Some(connection) => {
            let report = connection
                .grant_sealed_bundle_pad_access_with_kit(&owner, &seed, recipient)
                .await
                .map_err(|error| owner_error(OwnerError::Refused(error.to_string())))?;
            (PadAccessHome::Connection, report)
        }
        None => {
            let vault = Arc::clone(&server.vault);
            let report = blocking(move || {
                Ok(grant_local_sealed_pad_access_with_kit(
                    &vault, &owner, &seed, recipient,
                )?)
            })
            .await?
            .ok_or_else(|| {
                kit_target_refused(
                    HOME_UNAVAILABLE,
                    "this install runs no connection to a home and keeps no generation itself, \
                     so no pad object is in reach here; nothing was granted",
                    "Grant from the home, or from a machine that syncs with it.",
                )
            })?;
            (PadAccessHome::ThisInstall, report)
        }
    };
    let answer = PadAccessAnswer {
        machine: recipient.machine.to_hex(),
        home,
        offered: generations(&report.offered),
        usable: generations(&report.usable),
        pending_count: report.pending.len(),
        pending: generations(&report.pending),
    };
    observe_grant(me, &answer);
    Ok(Json(answer))
}

/// Kept generations as hex.
fn generations(list: &[SealedBundleGeneration]) -> Vec<String> {
    list.iter().map(sealed_generation_hex).collect()
}

/// The last grant this process answered, per granting install, with when.
fn grants() -> &'static Mutex<HashMap<EntityId, (String, PadAccessAnswer)>> {
    static GRANTS: OnceLock<Mutex<HashMap<EntityId, (String, PadAccessAnswer)>>> = OnceLock::new();
    GRANTS.get_or_init(Mutex::default)
}

fn observe_grant(me: EntityId, answer: &PadAccessAnswer) {
    if let Ok(mut grants) = grants().lock() {
        grants.insert(me, (rfc3339(now_unix_ms()), answer.clone()));
    }
}

/// One observation: none yet, or what was seen and when.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
enum Observed<T> {
    Unobserved,
    Observed {
        observed_at: String,
        #[serde(flatten)]
        report: T,
    },
}

/// What a take of the home's newest generation moved here.
#[derive(Debug, Serialize)]
struct TakenView {
    generation: String,
    sections: usize,
    merged: usize,
    mirrored: usize,
    unchanged: usize,
    skipped: usize,
}

/// What one relay that reached the home moved (`SealedBundleRelay`).
#[derive(Debug, Serialize)]
struct RelayView {
    taken: Option<TakenView>,
    /// The generation this machine published for the slot.
    published: Option<String>,
    /// Erased worlds and hard-erased keys stripped from the kept pad objects.
    erased: usize,
    /// Grants this machine sealed for a late joiner that the home took.
    offered: usize,
}

/// What the last erase sweep over the kept pad objects counted.
#[derive(Debug, Serialize)]
struct PendingView {
    /// Kept pad objects that open with no key here yet: their access is
    /// pending with the home.
    pending_pad_access: usize,
    /// Erases held back, unswept, while a kept pad object opens with no key
    /// here.
    pending_erases: usize,
}

/// A relay that failed, and when.
#[derive(Debug, Serialize)]
struct RelayFailureView {
    observed_at: String,
    error: String,
}

/// `GET /v1/owner/recovery-kit/upkeep`'s answer.
#[derive(Debug, Serialize)]
struct UpkeepAnswer {
    /// This install's machine, 32 hex; none before it is one.
    machine: Option<String>,
    /// Whether this install runs a connection to a home now.
    home_connection: bool,
    relay: Observed<RelayView>,
    pending: Observed<PendingView>,
    relay_failure: Option<RelayFailureView>,
    grant: Observed<PadAccessAnswer>,
}

/// The upkeep's observation as the answer shows it: what the last relay that
/// reached the home moved, what the last sweep counted, and the last failure.
struct RelayViews {
    relay: Observed<RelayView>,
    pending: Observed<PendingView>,
    failure: Option<RelayFailureView>,
}

fn relay_views(observation: Option<SealedBundleRelayObservation>) -> RelayViews {
    let Some(observation) = observation else {
        return RelayViews {
            relay: Observed::Unobserved,
            pending: Observed::Unobserved,
            failure: None,
        };
    };
    let relay = observation
        .relayed
        .map_or(Observed::Unobserved, |(at, relay)| Observed::Observed {
            observed_at: rfc3339_secs(at),
            report: RelayView {
                taken: relay.taken.map(|(generation, take)| TakenView {
                    generation: sealed_generation_hex(&generation),
                    sections: take.sections,
                    merged: take.merged,
                    mirrored: take.mirrored,
                    unchanged: take.unchanged,
                    skipped: take.skipped,
                }),
                published: relay.published.as_ref().map(sealed_generation_hex),
                erased: relay.erased,
                offered: relay.offered,
            },
        });
    let pending = observation
        .swept
        .map_or(Observed::Unobserved, |(at, relay)| Observed::Observed {
            observed_at: rfc3339_secs(at),
            report: PendingView {
                pending_pad_access: relay.pending_pad_access,
                pending_erases: relay.pending_erases,
            },
        });
    let failure = observation.failed.map(|(at, error)| RelayFailureView {
        observed_at: rfc3339_secs(at),
        error,
    });
    RelayViews {
        relay,
        pending,
        failure,
    }
}

/// `GET /v1/owner/recovery-kit/upkeep`: the last sealed bundle relay this
/// install's upkeep took to the home, the pending counts its last sweep
/// counted, the last relay that failed, and the last kit grant this process
/// answered, each with its time or as unobserved.
async fn upkeep(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<UpkeepAnswer> {
    owner(&auth, &server)?;
    let vault = Arc::clone(&server.vault);
    let me = blocking(move || Ok(vault.local_machine()?.map(|machine| machine.id))).await?;
    let views = relay_views(me.as_ref().and_then(sealed_bundle_relay_observation));
    let grant = me
        .and_then(|me| grants().lock().ok()?.get(&me).cloned())
        .map_or(Observed::Unobserved, |(observed_at, report)| {
            Observed::Observed {
                observed_at,
                report,
            }
        });
    Ok(Json(UpkeepAnswer {
        machine: me.map(|me| me.to_hex()),
        home_connection: me.is_some_and(|me| crate::residence_machines::connection(&me).is_some()),
        relay: views.relay,
        pending: views.pending,
        relay_failure: views.failure,
        grant,
    }))
}
