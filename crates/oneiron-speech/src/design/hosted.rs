//! The hosted speech providers' clone wires (ARCH-0061 §5): a provider voice
//! made from a banked identity's refs, asked whether it is verified, and
//! deleted. The provider's id is a disposable locator, never the identity.
//! These modules build each call's request and read its reply; the host
//! admits, sends and settles each call on its caller's run, and builds the
//! HTTP form from a [`CloneForm`].
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{FatalLlmError, LlmResult};
use serde_json::Value as JsonValue;

use super::{cartesia, elevenlabs};
use crate::tts::hosted::HostedWire;

/// A provider voice a clone call made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorVoice {
    /// The provider's id for it, safe in a URL path.
    pub id: String,
    /// The provider holds it until the voice is verified there (ElevenLabs'
    /// `requires_verification`, FIX 1567): no finished clone yet.
    pub awaiting_verification: bool,
}

/// One clone call's multipart form, as data: its path, then its text fields
/// and its files in the order they go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneForm {
    pub path: &'static str,
    pub texts: Vec<(&'static str, String)>,
    pub files: Vec<CloneFile>,
}

/// One file of a [`CloneForm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneFile {
    /// The form field it goes under.
    pub field: &'static str,
    /// Named by its place rather than its register.
    pub file_name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// The form that makes a provider voice named `name` from `clips`. Cartesia
/// takes one clip, made of every clip that joins into one (FIX 1567), and
/// must be told its `language`; ElevenLabs takes them all.
pub fn clone_form(
    wire: HostedWire,
    name: &str,
    clips: &[VoiceRegisterClip],
    language: Option<&str>,
) -> LlmResult<CloneForm> {
    match wire {
        HostedWire::Cartesia => cartesia::clone_form(name, clips, language),
        HostedWire::ElevenLabs => elevenlabs::clone_form(name, clips),
    }
}

/// The provider voice a clone call's reply `body` names.
pub fn cloned_voice(wire: HostedWire, body: &JsonValue) -> LlmResult<VendorVoice> {
    match wire {
        HostedWire::Cartesia => cartesia::cloned_voice(body),
        HostedWire::ElevenLabs => elevenlabs::cloned_voice(body),
    }
}

/// The path of the provider voice `vendor_voice_id`; refused unless the id
/// is safe in a URL path.
pub fn voice_path(wire: HostedWire, vendor_voice_id: &str) -> LlmResult<String> {
    match wire {
        HostedWire::Cartesia => cartesia::voice_path(vendor_voice_id),
        HostedWire::ElevenLabs => elevenlabs::voice_path(vendor_voice_id),
    }
}

/// A provider voice id: no separators, whitespace or credentials.
pub(crate) fn url_safe(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The voice id at `field` of a clone reply. The id is later interpolated
/// into URL paths, so one that is not safe there is no answer.
pub(crate) fn voice_id(body: &JsonValue, field: &str) -> LlmResult<String> {
    let id = body
        .get(field)
        .and_then(JsonValue::as_str)
        .filter(|id| url_safe(id))
        .map(str::to_owned)
        .ok_or(FatalLlmError::EmptyResponse)?;
    Ok(id)
}

/// One clip as the form file at `index` under `field`, named by its place
/// rather than its register.
pub(crate) fn clip_file(field: &'static str, index: usize, clip: &VoiceRegisterClip) -> CloneFile {
    let extension: String = match clip.media_type.as_str() {
        "audio/mpeg" => "mp3".to_owned(),
        other => other
            .trim_start_matches("audio/")
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect(),
    };
    CloneFile {
        field,
        file_name: format!("clip-{index}.{extension}"),
        media_type: clip.media_type.clone(),
        bytes: clip.audio.clone(),
    }
}
