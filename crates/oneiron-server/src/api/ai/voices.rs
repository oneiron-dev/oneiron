//! The voice bank's provisioning door, the owner's alone:
//! `POST /v1/ai/voices/{voice_id}/packs` banks a reference pack,
//! `POST /v1/ai/voices/{voice_id}/render_consent` records the subject's
//! render decision, and `POST`/`DELETE /v1/ai/voices/{voice_id}/targets/{target}`
//! provisions a hosted target's clone or drops it. A clone is made only from
//! refs the voice's render consent lets reach the target's locality, and it
//! is recorded only while those refs and that consent are still current; a
//! clone the bank no longer holds is deleted at the vendor (ARCH-0061 §5,
//! "A companion reference clip leaves only through consented provisioning").
//! Audio travels as base64 on this wire.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::voice_identity::ref_bank::{
    VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip, VoiceRenderDecision, VoiceTargetRecord,
};
use oneiron::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use oneiron::{EntityId, ModelLocality};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use super::refusal;
use crate::auth::CoreAuth;
use crate::models::HostedCloner;
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackBody {
    pack_id: String,
    /// Whose voice it is (entity hex).
    owner: String,
    origin: VoiceRefOrigin,
    clips: Vec<ClipBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClipBody {
    register: String,
    media_type: String,
    /// Base64.
    audio: String,
    transcript: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsentBody {
    event_id: String,
    /// Whose voice it is (entity hex).
    subject: String,
    /// Who recorded the decision (entity hex).
    recorded_by: String,
    occurred_at: u64,
    /// The farthest target a grant lets the refs reach.
    reach: ModelLocality,
    basis: VoiceConsentBasis,
    state: VoiceConsentState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionBody {
    #[serde(default)]
    include_generated: bool,
    /// The language the clip is spoken in, for a target that asks.
    #[serde(default)]
    language: Option<String>,
}

/// Banks one immutable reference pack. A captured pack cites the subject's
/// current render grant; a retry of the same pack is a no-op.
pub(super) async fn bank_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(voice_id): Path<String>,
    Json(body): Json<PackBody>,
) -> Response {
    if let Err(refused) = owner_only(&auth) {
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
        Ok(()) => Json(json!({"voice_id": pack.voice_id, "pack_id": pack.id})).into_response(),
        Err(error) => bank_refusal(error),
    }
}

/// Records the subject's render decision. A withdrawal drops the voice's
/// target pointers and deletes their clones at the vendors.
pub(super) async fn render_consent(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(voice_id): Path<String>,
    Json(body): Json<ConsentBody>,
) -> Response {
    if let Err(refused) = owner_only(&auth) {
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
        recorded_by,
        occurred_at: body.occurred_at,
        reach: body.reach,
        basis: body.basis,
        state: body.state,
    };
    let (consent, evicted) = match server.vault.record_voice_render_consent(&decision) {
        Ok(recorded) => recorded,
        Err(error) => return bank_refusal(error),
    };
    let mut dropped = Vec::with_capacity(evicted.len());
    for record in &evicted {
        let cloner = server
            .ai
            .model_runtime()
            .media()
            .voice_cloner(&record.target);
        dropped.push(json!({
            "target": record.target,
            "vendor_voice_id": record.vendor_voice_id,
            "vendor": delete_at_vendor(cloner, record).await,
        }));
    }
    Json(json!({
        "voice_id": consent.decision.voice_id,
        "state": consent.decision.state,
        "reach": consent.decision.reach,
        "revision": hex(&consent.revision),
        "evicted": dropped,
    }))
    .into_response()
}

/// Provisions `target`'s clone of the voice: the current one when it is
/// still current, else a new vendor voice from the selected refs.
pub(super) async fn provision(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((voice_id, target)): Path<(String, String)>,
    Json(body): Json<ProvisionBody>,
) -> Response {
    if let Err(refused) = owner_only(&auth) {
        return refused;
    }
    let Some(cloner) = server.ai.model_runtime().media().voice_cloner(&target) else {
        return refusal(
            StatusCode::NOT_FOUND,
            "no_clone_target",
            "no configured hosted speech provider by that name clones voices",
        );
    };
    if cloner.needs_language() && body.language.as_deref().is_none_or(|l| l.trim().is_empty()) {
        return refusal(
            StatusCode::BAD_REQUEST,
            "language_required",
            "this target clones only with the clip's language",
        );
    }
    let locality = cloner.locality();
    // A current clone is kept: no new vendor voice without new refs.
    match server
        .vault
        .voice_target_clone(&voice_id, &target, body.include_generated, locality)
    {
        Ok(Some((record, _))) => return Json(record_view(&record)).into_response(),
        Ok(None) => {}
        Err(error) => return bank_refusal(error),
    }
    let clone =
        match server
            .vault
            .prepare_voice_clone(&voice_id, &target, body.include_generated, locality)
        {
            Ok(clone) => clone,
            Err(error) => return bank_refusal(error),
        };
    // The vendor sees a name from the refs' digest, never the voice's id.
    let name = format!("oneiron-{}", &hex(&clone.ref_digest)[..16]);
    let vendor_voice_id = match cloner
        .create(&name, &clone.clips, body.language.as_deref())
        .await
    {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(%target, %error, "vendor voice clone failed");
            return refusal(
                StatusCode::BAD_GATEWAY,
                "vendor_clone_failed",
                format!("the provider did not make the clone: {error}"),
            );
        }
    };
    match server
        .vault
        .record_voice_target_clone(&clone, &vendor_voice_id, now_secs())
    {
        Ok(record) => {
            // Another provisioning recorded a current clone first: ours is spare.
            if record.vendor_voice_id != vendor_voice_id
                && let Err(error) = cloner.delete(&vendor_voice_id).await
            {
                tracing::warn!(%target, %error, "spare vendor clone not deleted");
            }
            Json(record_view(&record)).into_response()
        }
        Err(error) => {
            // The refs or the render consent changed while they uploaded:
            // the new vendor voice is no current clone of this identity.
            if let Err(error) = cloner.delete(&vendor_voice_id).await {
                tracing::warn!(%target, %error, "stale vendor clone not deleted");
            }
            bank_refusal(error)
        }
    }
}

/// Drops `target`'s clone pointer and deletes the clone at the vendor.
pub(super) async fn evict(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((voice_id, target)): Path<(String, String)>,
) -> Response {
    if let Err(refused) = owner_only(&auth) {
        return refused;
    }
    let evicted = match server.vault.evict_voice_target(&voice_id, &target) {
        Ok(evicted) => evicted,
        Err(error) => return bank_refusal(error),
    };
    let vendor = match &evicted {
        Some(record) => {
            let cloner = server.ai.model_runtime().media().voice_cloner(&target);
            delete_at_vendor(cloner, record).await
        }
        None => "absent",
    };
    Json(json!({
        "voice_id": voice_id,
        "target": target,
        "evicted": evicted.is_some(),
        "vendor": vendor,
    }))
    .into_response()
}

/// Deletes an evicted record's clone at its vendor, best effort: what
/// happened, for the owner to see.
async fn delete_at_vendor(
    cloner: Option<Arc<HostedCloner>>,
    record: &VoiceTargetRecord,
) -> &'static str {
    let Some(cloner) = cloner else {
        return "no_clone_wire";
    };
    match cloner.delete(&record.vendor_voice_id).await {
        Ok(()) => "deleted",
        Err(error) => {
            tracing::warn!(target = %record.target, %error, "vendor clone not deleted");
            "delete_failed"
        }
    }
}

fn owner_only(auth: &CoreAuth) -> Result<(), Response> {
    if auth.is_owner_grade() {
        Ok(())
    } else {
        Err(refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "the voice bank is the owner's",
        ))
    }
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

fn record_view(record: &VoiceTargetRecord) -> JsonValue {
    json!({
        "voice_id": record.voice_id,
        "target": record.target,
        "vendor_voice_id": record.vendor_voice_id,
        "cloned_at": record.cloned_at,
        "revision": hex(&record.revision),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
