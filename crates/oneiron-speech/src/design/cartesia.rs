//! Cartesia's clone wire: `POST /voices/clone` makes a voice from one clip,
//! told its language, and `DELETE /voices/{id}` deletes it. Cartesia holds
//! no voice for verification. Every call names
//! [`CARTESIA_VERSION`](crate::tts::cartesia::CARTESIA_VERSION).
use oneiron::llm::media::wav::{WavClip, pcm16_wav};
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{FatalLlmError, LlmResult};
use serde_json::Value as JsonValue;

use super::hosted::{CloneFile, CloneForm, VendorVoice, clip_file, url_safe, voice_id};

/// The form that makes a provider voice named `name`, spoken in `language`,
/// from `clips`: one clip, made of every clip that joins into one (FIX 1567).
pub fn clone_form(
    name: &str,
    clips: &[VoiceRegisterClip],
    language: Option<&str>,
) -> LlmResult<CloneForm> {
    let first = clips.first().ok_or(FatalLlmError::InvalidRequest)?;
    let language = language
        .filter(|language| !language.trim().is_empty())
        .ok_or(FatalLlmError::InvalidRequest)?;
    let clip = match joined_wav(clips) {
        Some(joined) => CloneFile {
            field: "clip",
            file_name: "clip-0.wav".to_owned(),
            media_type: "audio/wav".to_owned(),
            bytes: joined,
        },
        None => clip_file("clip", 0, first),
    };
    Ok(CloneForm {
        path: "/voices/clone",
        texts: vec![("name", name.to_owned()), ("language", language.to_owned())],
        files: vec![clip],
    })
}

/// The voice a clone reply names, at its `id`; never awaiting verification.
pub fn cloned_voice(body: &JsonValue) -> LlmResult<VendorVoice> {
    Ok(VendorVoice {
        id: voice_id(body, "id")?,
        awaiting_verification: false,
    })
}

/// The path of the provider voice `id`; refused unless `id` is safe there.
pub fn voice_path(id: &str) -> LlmResult<String> {
    if !url_safe(id) {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(format!("/voices/{id}"))
}

/// Every clip as one PCM16 WAV, their samples joined in order: Cartesia
/// clones from one clip (FIX 1567). `None` unless there are several and
/// each is a PCM16 WAV of whole frames at one rate and channel count; the
/// first clip goes alone then, as before.
fn joined_wav(clips: &[VoiceRegisterClip]) -> Option<Vec<u8>> {
    let wavs = clips
        .iter()
        .map(|clip| WavClip::parse(&clip.audio).filter(WavClip::is_pcm16))
        .collect::<Option<Vec<_>>>()?;
    let (first, rest) = wavs.split_first()?;
    let frame = usize::from(first.channels) * 2;
    let joins = |wav: &WavClip<'_>| {
        wav.sample_rate == first.sample_rate
            && wav.channels == first.channels
            && frame > 0
            && wav.data.len().is_multiple_of(frame)
    };
    if rest.is_empty() || !wavs.iter().all(joins) {
        return None;
    }
    let samples: Vec<u8> = wavs.iter().flat_map(|wav| wav.data).copied().collect();
    pcm16_wav(first.sample_rate, first.channels, &samples)
}
