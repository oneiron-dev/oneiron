//! ElevenLabs' clone wire: `POST /v1/voices/add` makes a voice from every
//! clip, `GET /v1/voices/{id}` says whether one held for verification is
//! verified (FIX 1567), and `DELETE /v1/voices/{id}` deletes it.
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{FatalLlmError, LlmResult};
use serde_json::Value as JsonValue;

use super::hosted::{CloneForm, VendorVoice, clip_file, url_safe, voice_id};

/// The form that makes a provider voice named `name` from every clip of
/// `clips`, each a file of its own.
pub fn clone_form(name: &str, clips: &[VoiceRegisterClip]) -> LlmResult<CloneForm> {
    if clips.is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(CloneForm {
        path: "/v1/voices/add",
        texts: vec![("name", name.to_owned())],
        files: clips
            .iter()
            .enumerate()
            .map(|(index, clip)| clip_file("files", index, clip))
            .collect(),
    })
}

/// The voice a clone reply names, at its `voice_id`; awaiting verification
/// when the reply says `requires_verification`.
pub fn cloned_voice(body: &JsonValue) -> LlmResult<VendorVoice> {
    Ok(VendorVoice {
        id: voice_id(body, "voice_id")?,
        awaiting_verification: body.get("requires_verification") == Some(&JsonValue::Bool(true)),
    })
}

/// The path of the provider voice `id`; refused unless `id` is safe there.
pub fn voice_path(id: &str) -> LlmResult<String> {
    if !url_safe(id) {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(format!("/v1/voices/{id}"))
}

/// Whether a voice's `GET` reply `body` says it is verified there now, or
/// needs no verification.
pub fn is_verified(body: &JsonValue) -> bool {
    let verification = &body["voice_verification"];
    verification["is_verified"] == JsonValue::Bool(true)
        || verification["requires_verification"] == JsonValue::Bool(false)
}
