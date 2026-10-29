//! The voice bank's provisioning door, the owner's alone:
//! `POST /v1/ai/voices/{voice_id}/packs` banks a reference pack,
//! `POST /v1/ai/voices/{voice_id}/render_consent` records the subject's
//! render decision, and `POST`/`DELETE /v1/ai/voices/{voice_id}/targets/{target}`
//! provisions a hosted target's clone or drops it, and
//! `GET /v1/ai/voices/{voice_id}` shows the voice's packs, render decision
//! and each clone target's clone (FIX 1567). A clone is made only from
//! refs the voice's render consent lets reach the target's locality, and it
//! is recorded only while those refs and that consent are still current; a
//! clone the bank no longer holds is deleted at the vendor (ARCH-0061 §5,
//! "A companion reference clip leaves only through consented provisioning").
//! Audio travels as base64 on this wire. Every route here runs the shared
//! host-owner admission first (FIX 8131): a hosted operator's root acts as no
//! customer owner and gets the typed support-grant refusal.
//!
//! The typed `vault.voices.*` doors (api/facade/voice_bank_doors.rs) run the
//! same provisioning and vendor deletions through the helpers here, under
//! their actor's proof, so one paid clone flow serves both.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::task_verb::sdk::{
    VoiceBankClipInput, VoiceBankPackReceipt, VoiceRenderConsentReceipt, VoiceTargetEvictReceipt,
    VoiceTargetReceipt, VoiceVendorDeleteStatus, VoiceVendorEviction,
};
use oneiron::voice_identity::ref_bank::{
    VoiceBankActor, VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRegisterClip,
    VoiceRenderConsentWrite, VoiceRenderDecision, VoiceTargetRecord,
};
use oneiron::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use oneiron::{EntityId, ModelLocality};
use serde::{Deserialize, Serialize};

use super::refusal;
use crate::auth::CoreAuth;
use crate::models::{HostedCloner, MediaRuntime};
use crate::server::SyncServer;

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackBody {
    pack_id: String,
    /// Whose voice it is (entity hex).
    owner: String,
    origin: VoiceRefOrigin,
    clips: Vec<VoiceBankClipInput>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentBody {
    event_id: String,
    /// Whose voice it is (entity hex): a real person, or a designed voice's
    /// creator.
    subject: String,
    /// `person` (when absent) or `designed`; the bank binds it when it first
    /// holds the voice.
    #[serde(default = "VoiceRefSubjectKind::input_default")]
    subject_kind: VoiceRefSubjectKind,
    /// Who recorded the decision (entity hex).
    recorded_by: String,
    occurred_at: u64,
    /// The farthest target a grant lets the refs reach.
    reach: ModelLocality,
    /// How a person's decision was captured; a designed voice's needs none.
    #[serde(default)]
    basis: Option<VoiceConsentBasis>,
    state: VoiceConsentState,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionBody {
    #[serde(default)]
    include_generated: bool,
    /// The language the clip is spoken in, for a target that asks.
    #[serde(default)]
    language: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewQuery {
    /// Whether the selection each clone is checked against counts
    /// generated packs.
    #[serde(default)]
    include_generated: bool,
}

/// A provisioning's answer on the route: the clone's receipt, and whether
/// its vendor holds it until the voice is verified there (FIX 1567).
#[derive(Serialize)]
struct ProvisionAnswer {
    #[serde(flatten)]
    receipt: VoiceTargetReceipt,
    awaiting_verification: bool,
}

/// The voice as the bank holds it, for the owner (FIX 1567): its identity,
/// each pack's metadata, its current render decision, and each configured
/// clone target's current clone, read from one snapshot with no provider
/// call.
pub(super) async fn view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(voice_id): Path<String>,
    Query(query): Query<ViewQuery>,
) -> Response {
    if let Err(refused) = owner_only(&server, &auth) {
        return refused;
    }
    let targets = server.ai.model_runtime().media().clone_targets();
    match server
        .vault
        .voice_bank_view(&voice_id, &targets, query.include_generated)
    {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => refusal(
            StatusCode::NOT_FOUND,
            "unknown_voice",
            "the bank holds nothing of that voice",
        ),
        Err(error) => bank_refusal(error),
    }
}

/// Banks one immutable reference pack. A captured pack cites the subject's
/// current render grant; a retry of the same pack is a no-op.
pub(super) async fn bank_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(voice_id): Path<String>,
    Json(body): Json<PackBody>,
) -> Response {
    if let Err(refused) = owner_only(&server, &auth) {
        return refused;
    }
    let owner = match entity(&body.owner, "owner") {
        Ok(owner) => owner,
        Err(refused) => return refused,
    };
    let mut clips = Vec::with_capacity(body.clips.len());
    for clip in body.clips {
        let Ok(audio) = STANDARD.decode(clip.audio.as_bytes()) else {
            return refusal(
                StatusCode::BAD_REQUEST,
                "invalid_audio",
                "a clip's audio is base64",
            );
        };
        clips.push(VoiceRegisterClip {
            register: clip.register,
            media_type: clip.media_type,
            audio,
            transcript: clip.transcript,
        });
    }
    let pack = VoiceRefPack {
        version: 1,
        id: body.pack_id,
        voice_id,
        owner,
        origin: body.origin,
        clips,
    };
    match server.vault.store_voice_ref_pack(&pack) {
        Ok(()) => Json(VoiceBankPackReceipt {
            voice_id: pack.voice_id,
            pack_id: pack.id,
        })
        .into_response(),
        Err(error) => bank_refusal(error),
    }
}

/// Records the subject's render decision. A withdrawal drops the voice's
/// target pointers and deletes their clones at the vendors; a replay deletes
/// none again.
pub(super) async fn render_consent(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(voice_id): Path<String>,
    Json(body): Json<ConsentBody>,
) -> Response {
    if let Err(refused) = owner_only(&server, &auth) {
        return refused;
    }
    let (subject, recorded_by) = match (
        entity(&body.subject, "subject"),
        entity(&body.recorded_by, "recorded_by"),
    ) {
        (Ok(subject), Ok(recorded_by)) => (subject, recorded_by),
        (Err(refused), _) | (_, Err(refused)) => return refused,
    };
    let decision = VoiceRenderDecision {
        event_id: body.event_id,
        voice_id,
        subject,
        subject_kind: body.subject_kind,
        recorded_by,
        occurred_at: body.occurred_at,
        reach: body.reach,
        basis: body.basis,
        state: body.state,
    };
    let recorded = match server.vault.record_voice_render_consent(&decision) {
        Ok(recorded) => recorded,
        Err(error) => return bank_refusal(error),
    };
    let media = server.ai.model_runtime().media();
    Json(render_consent_answer(media, &recorded).await).into_response()
}

/// A recorded render decision's receipt. Each target clone this call
/// dropped is deleted at its vendor after the decision committed, best
/// effort, and the receipt says what each vendor did; a replay dropped none
/// and deletes none. The route and the `vault.voices.render_consent` door
/// both answer it.
pub(crate) async fn render_consent_answer(
    media: &MediaRuntime,
    recorded: &VoiceRenderConsentWrite,
) -> VoiceRenderConsentReceipt {
    let mut dropped = Vec::with_capacity(recorded.newly_evicted.len());
    for record in &recorded.newly_evicted {
        dropped.push(VoiceVendorEviction {
            target: record.target.clone(),
            vendor_voice_id: record.vendor_voice_id.clone(),
            vendor: delete_at_vendor(media, record).await,
        });
    }
    let consent = &recorded.receipt.consent;
    VoiceRenderConsentReceipt {
        voice_id: consent.decision.voice_id.clone(),
        state: consent.decision.state,
        reach: consent.decision.reach,
        revision: hex(&consent.revision),
        event_id: consent.decision.event_id.clone(),
        sequence: consent.sequence,
        replayed: recorded.replayed,
        evicted: dropped,
    }
}

/// Provisions `target`'s clone of the voice: the current one when it is
/// still current, else a new vendor voice from the selected refs.
pub(super) async fn provision(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((voice_id, target)): Path<(String, String)>,
    Json(body): Json<ProvisionBody>,
) -> Response {
    if let Err(refused) = owner_only(&server, &auth) {
        return refused;
    }
    let request = CloneRequest {
        voice_id: &voice_id,
        target: &target,
        include_generated: body.include_generated,
        language: body.language.as_deref(),
    };
    match provision_record(&server, None, None, request).await {
        Ok(record) => Json(ProvisionAnswer {
            receipt: target_receipt(&record),
            awaiting_verification: record.awaiting_verification,
        })
        .into_response(),
        Err(refused) => refused.response(),
    }
}

/// Why provisioning refused, before or after its vendor call.
pub(crate) enum VoiceBankRefusal {
    /// No configured hosted speech provider by the target's name clones.
    NoCloneTarget,
    /// The target clones only with the clips' language, and none was named.
    LanguageRequired,
    /// The provider did not make the clone, for this reason.
    VendorCloneFailed(String),
    /// The bank refused, or could not be read or written.
    Bank(oneiron::Error),
}

impl VoiceBankRefusal {
    /// The route's refusal of it.
    fn response(self) -> Response {
        match self {
            Self::NoCloneTarget => refusal(
                StatusCode::NOT_FOUND,
                "no_clone_target",
                "no configured hosted speech provider by that name clones voices",
            ),
            Self::LanguageRequired => refusal(
                StatusCode::BAD_REQUEST,
                "language_required",
                "this target clones only with the clip's language",
            ),
            Self::VendorCloneFailed(error) => refusal(
                StatusCode::BAD_GATEWAY,
                "vendor_clone_failed",
                format!("the provider did not make the clone: {error}"),
            ),
            Self::Bank(error) => bank_refusal(error),
        }
    }
}

/// Provisions `target`'s clone of the voice: the current one when it is
/// still current, else a new vendor voice made from the selected refs on a
/// paid run of its own and recorded only while those refs and the render
/// consent they left under are still current. A clone the bank does not
/// record is deleted at the vendor. `actor` is the typed door's: the voice
/// must be its own, a real person's on their proof or a designed voice's
/// creator's, and the record is written under it, revalidated; the route
/// passes none, past its owner-grade check.
pub(crate) async fn provision_clone(
    server: &SyncServer,
    actor: Option<&VoiceBankActor>,
    voice_id: &str,
    target: &str,
    include_generated: bool,
    language: Option<&str>,
) -> Result<VoiceTargetReceipt, VoiceBankRefusal> {
    let request = CloneRequest {
        voice_id,
        target,
        include_generated,
        language,
    };
    provision_clone_funded(server, actor, None, request).await
}

/// One clone a door asks for: the voice, the target, whether generated refs
/// count, and the clips' language when the target needs it.
pub(crate) struct CloneRequest<'a> {
    pub(crate) voice_id: &'a str,
    pub(crate) target: &'a str,
    pub(crate) include_generated: bool,
    pub(crate) language: Option<&'a str>,
}

/// [`provision_clone`], its vendor calls billed to `payer` when the acting
/// payer's own account or consent explicitly funds this clone (FIX 9421),
/// the creator still carried as their initiator. With none, the clone runs
/// on the vault's run, as it always did: no payer is inferred from who made
/// the voice, and none missing refuses it.
pub(crate) async fn provision_clone_funded(
    server: &SyncServer,
    actor: Option<&VoiceBankActor>,
    payer: Option<oneiron::llm::run_admission::PayerPerson>,
    request: CloneRequest<'_>,
) -> Result<VoiceTargetReceipt, VoiceBankRefusal> {
    provision_record(server, actor, payer, request)
        .await
        .map(|record| target_receipt(&record))
}

/// [`provision_clone_funded`]'s record of the clone, as the bank holds it.
/// A current clone its vendor holds for verification is asked about again
/// first, and recorded verified once the vendor says so (FIX 1567).
async fn provision_record(
    server: &SyncServer,
    actor: Option<&VoiceBankActor>,
    payer: Option<oneiron::llm::run_admission::PayerPerson>,
    request: CloneRequest<'_>,
) -> Result<VoiceTargetRecord, VoiceBankRefusal> {
    let CloneRequest {
        voice_id,
        target,
        include_generated,
        language,
    } = request;
    if let Some(actor) = actor {
        server
            .vault
            .owned_voice_identity(actor, voice_id)
            .map_err(VoiceBankRefusal::Bank)?;
    }
    let media = server.ai.model_runtime().media();
    let cloner = media
        .voice_cloner(target)
        .ok_or(VoiceBankRefusal::NoCloneTarget)?;
    if cloner.needs_language() && language.is_none_or(|l| l.trim().is_empty()) {
        return Err(VoiceBankRefusal::LanguageRequired);
    }
    let locality = cloner.locality();
    // A current clone is kept: no new vendor voice without new refs.
    if let Some((record, _)) = server
        .vault
        .voice_target_clone(voice_id, target, include_generated, locality)
        .map_err(VoiceBankRefusal::Bank)?
    {
        if record.awaiting_verification {
            return Ok(refresh_verification(server, media, &cloner, record).await);
        }
        return Ok(record);
    }
    let clone = server
        .vault
        .prepare_voice_clone(voice_id, target, include_generated, locality)
        .map_err(VoiceBankRefusal::Bank)?;
    // The vendor sees a name from the refs' digest, never the voice's id.
    let name = format!("oneiron-{}", &hex(&clone.ref_digest)[..16]);
    // Each vendor call goes out on its own permit of this run (FIX 3009),
    // naming the acting person or creator as its initiator (FIX 8970); who
    // pays is the run's, unchanged.
    let initiator = actor.and_then(|actor| actor.entity_for_read(&server.vault).ok());
    // Its clips are the voice's person's (FIX 11311).
    let person = server
        .vault
        .voice_identity(voice_id)
        .ok()
        .flatten()
        .map(|identity| vec![identity.owner]);
    let created = match media
        .clone_run_funded(payer, person)
        .map(|run| run.initiated_by(initiator))
    {
        Ok(run) => cloner
            .create(&run, &name, &clone.clips, language)
            .await
            .map(|id| (run, id)),
        Err(error) => Err(error),
    };
    let (run, vendor) = created.map_err(|error| {
        tracing::warn!(%target, %error, "vendor voice clone failed");
        VoiceBankRefusal::VendorCloneFailed(error.to_string())
    })?;
    let vendor_voice_id = vendor.id;
    let cloned_at = now_secs();
    let awaiting = vendor.awaiting_verification;
    let recorded = match actor {
        Some(actor) => server.vault.record_voice_target_clone_as(
            actor,
            &clone,
            &vendor_voice_id,
            cloned_at,
            awaiting,
        ),
        None => {
            server
                .vault
                .record_voice_target_clone(&clone, &vendor_voice_id, cloned_at, awaiting)
        }
    };
    match recorded {
        Ok(record) => {
            // Another provisioning recorded a current clone first: ours is spare.
            if record.vendor_voice_id != vendor_voice_id
                && let Err(error) = cloner.delete(&run, &vendor_voice_id).await
            {
                tracing::warn!(%target, %error, "spare vendor clone not deleted");
            }
            Ok(record)
        }
        Err(error) => {
            // The refs or the render consent changed while they uploaded:
            // the new vendor voice is no current clone of this identity.
            if let Err(error) = cloner.delete(&run, &vendor_voice_id).await {
                tracing::warn!(%target, %error, "stale vendor clone not deleted");
            }
            Err(VoiceBankRefusal::Bank(error))
        }
    }
}

/// `record`, a clone its vendor holds for verification, as it stands once
/// the vendor was asked about it on a paid permit of a run of its own: the
/// bank records it verified when the vendor says so. A vendor or bank that
/// could not answer leaves it awaiting.
async fn refresh_verification(
    server: &SyncServer,
    media: &MediaRuntime,
    cloner: &HostedCloner,
    record: VoiceTargetRecord,
) -> VoiceTargetRecord {
    // The question sends the vendor's voice id alone: it reads no row.
    let verified = match media.clone_run(Some(Vec::new())) {
        Ok(run) => cloner.verified(&run, &record.vendor_voice_id).await,
        Err(error) => Err(error),
    };
    match verified {
        Ok(true) => match server.vault.record_voice_target_verified(
            &record.voice_id,
            &record.target,
            record.revision,
        ) {
            Ok(Some(current)) => current,
            Ok(None) => record,
            Err(error) => {
                tracing::warn!(target = %record.target, %error, "verified clone not recorded");
                record
            }
        },
        Ok(false) => record,
        Err(error) => {
            tracing::warn!(target = %record.target, %error, "clone verification not read");
            record
        }
    }
}

/// Drops `target`'s clone pointer and deletes the clone at the vendor.
pub(super) async fn evict(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((voice_id, target)): Path<(String, String)>,
) -> Response {
    if let Err(refused) = owner_only(&server, &auth) {
        return refused;
    }
    let evicted = match server.vault.evict_voice_target(&voice_id, &target) {
        Ok(evicted) => evicted,
        Err(error) => return bank_refusal(error),
    };
    let media = server.ai.model_runtime().media();
    Json(evict_answer(media, voice_id, target, evicted.as_ref()).await).into_response()
}

/// An eviction's receipt: the dropped pointer's clone is deleted at its
/// vendor first, best effort. The route and the `vault.voices.targets.evict`
/// door both answer it.
pub(crate) async fn evict_answer(
    media: &MediaRuntime,
    voice_id: String,
    target: String,
    evicted: Option<&VoiceTargetRecord>,
) -> VoiceTargetEvictReceipt {
    let vendor = match evicted {
        Some(record) => delete_at_vendor(media, record).await,
        None => VoiceVendorDeleteStatus::Absent,
    };
    VoiceTargetEvictReceipt {
        voice_id,
        target,
        evicted: evicted.is_some(),
        vendor,
    }
}

/// Deletes an evicted record's clone at its vendor, best effort, on a paid
/// permit of a run of its own (FIX 3009): what happened, for the owner to
/// see.
async fn delete_at_vendor(
    media: &MediaRuntime,
    record: &VoiceTargetRecord,
) -> VoiceVendorDeleteStatus {
    let Some(cloner) = media.voice_cloner(&record.target) else {
        return VoiceVendorDeleteStatus::NoCloneWire;
    };
    // A delete sends the vendor's voice id alone: it reads no row.
    let deleted = match media.clone_run(Some(Vec::new())) {
        Ok(run) => cloner.delete(&run, &record.vendor_voice_id).await,
        Err(error) => Err(error),
    };
    match deleted {
        Ok(()) => VoiceVendorDeleteStatus::Deleted,
        Err(error) => {
            tracing::warn!(target = %record.target, %error, "vendor clone not deleted");
            VoiceVendorDeleteStatus::DeleteFailed
        }
    }
}

/// The voice bank is the owner's: an owner-grade caller, admitted as the
/// owner by the shared host-owner admission before any bank read, write or
/// vendor call (FIX 8131). A self-hosted root or the dev mode acts as the
/// owner; a hosted operator's root is refused with the support-grant
/// refusal, and a managed vault's attested owner or a verified slip keeps
/// its own key.
fn owner_only(server: &SyncServer, auth: &CoreAuth) -> Result<(), Response> {
    if !auth.is_owner_grade() {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "the voice bank is the owner's",
        ));
    }
    crate::api::host_action::require_host_owner_act(server, auth)
        .map(|_| ())
        .map_err(IntoResponse::into_response)
}

fn entity(hex: &str, field: &str) -> Result<EntityId, Response> {
    EntityId::from_hex(hex).map_err(|_| {
        refusal(
            StatusCode::BAD_REQUEST,
            "invalid_entity",
            format!("{field} is not an entity id"),
        )
    })
}

/// A bank refusal is the caller's to fix; anything else is the vault's.
fn bank_refusal(error: oneiron::Error) -> Response {
    match error {
        oneiron::Error::InvalidConfig(message) => {
            refusal(StatusCode::CONFLICT, "voice_refused", message)
        }
        error => {
            tracing::warn!(%error, "voice bank failed");
            refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "voice_bank_failed",
                "the voice bank could not be read or written",
            )
        }
    }
}

fn target_receipt(record: &VoiceTargetRecord) -> VoiceTargetReceipt {
    VoiceTargetReceipt {
        voice_id: record.voice_id.clone(),
        target: record.target.clone(),
        vendor_voice_id: record.vendor_voice_id.clone(),
        cloned_at: record.cloned_at,
        revision: hex(&record.revision),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
