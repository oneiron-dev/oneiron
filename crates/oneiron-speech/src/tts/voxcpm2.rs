//! The VoxCPM2 worker's voice-socket codec (`deploy/voxcpm2`, OF-410), as the
//! server's own-server speech rung speaks it: one `ai.speech` call is one
//! socket connection (`GET /v1/voice`) and one generation. The host opens the
//! socket, sends `start` once with the reference transcript and clip as their
//! own binary frames, then one `text` frame per render, and reads each
//! render's `audio` frames until its `usage`. This module is pure and sans-IO:
//! it cuts the text into renders whose frames fit, frames each request, and
//! checks each reply's pins. The host pins the target, uploads under the bank's
//! current reference, spools the audio and settles the call.
//!
//! The consent-fenced cascade adapter on the same worker,
//! `oneiron::voice_cascade::voxcpm2`, stays in core: it sends inside the
//! vault's voice consent fence.
use oneiron::llm::media::wav::pcm16_wav;
use oneiron::voice_cascade::our_voice::{OUR_VOICE_PATH, VoiceClientFrame};
use oneiron::voice_cascade::speakable_pieces;
use oneiron::voice_cascade::voxcpm2::{VoiceServingLimits, VoxCpm2PcmBody};
use oneiron::{FatalLlmError, LlmError, LlmResult, RetryableLlmError};
use serde_json::Value as JsonValue;

/// One `ai.speech` call is one socket connection and one generation.
pub const VOICE_GENERATION: u64 = 1;

/// The voice socket URL for a provider base URL: its loopback origin spoken
/// as `ws`, plus the voice path. The base is trimmed of any trailing slash
/// and must start `http://`, as a `voxcpm2` entry's does.
pub fn voice_socket_url(base_url: &str) -> LlmResult<String> {
    let base = base_url.trim_end_matches('/');
    let Some(rest) = base.strip_prefix("http://") else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    if rest.is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(format!("ws://{rest}{OUR_VOICE_PATH}"))
}

/// The bytes `text` takes as a JSON string, without its quotes.
fn escaped_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |quoted| quoted.len().saturating_sub(2))
}

/// The renders `text` goes as, so every `text` frame stays within the
/// worker's decoder bound `max_header_bytes`. The text is cut within
/// `max_text_bytes` first, then each piece splits again until its frame fits.
/// Refused only when not one character fits.
pub fn text_pieces<'t>(text: &'t str, limits: VoiceServingLimits) -> LlmResult<Vec<&'t str>> {
    let max_text = usize::try_from(limits.max_text_bytes).unwrap_or(usize::MAX);
    let max_header = usize::try_from(limits.max_header_bytes).unwrap_or(usize::MAX);
    let pieces = speakable_pieces(text, max_text);
    // Every text frame differs from the empty-text one only by its text.
    let overhead = VoiceClientFrame::Text {
        generation: VOICE_GENERATION,
        text: String::new(),
    }
    .to_json()
    .len();
    let fits = |piece: &str| overhead.saturating_add(escaped_len(piece)) <= max_header;
    let mut fitted = Vec::with_capacity(pieces.len());
    for piece in pieces {
        split_to_fit(piece, &fits, &mut fitted)?;
    }
    Ok(fitted)
}

/// `piece` as pieces whose frame `fits`, in order: one that does not is
/// split again within half its length.
fn split_to_fit<'t>(
    piece: &'t str,
    fits: &dyn Fn(&str) -> bool,
    out: &mut Vec<&'t str>,
) -> LlmResult<()> {
    if fits(piece) {
        out.push(piece);
        return Ok(());
    }
    // One character whose frame does not fit cannot go.
    if piece.chars().nth(1).is_none() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    for part in speakable_pieces(piece, piece.len() / 2) {
        split_to_fit(part, fits, out)?;
    }
    Ok(())
}

/// The generation's `start` frame for `target`, carrying the reference
/// transcript's and clip's byte counts. Refused when the frame or the
/// transcript passes the effective decoder bound `max_header_bytes`; the
/// clip itself still goes whole, however long (Rule 5).
pub fn start_frame(
    target: &JsonValue,
    transcript: &str,
    audio: &[u8],
    max_header_bytes: u64,
) -> LlmResult<String> {
    let start = VoiceClientFrame::Start {
        generation: VOICE_GENERATION,
        target: target.clone(),
        transcript_bytes: transcript.len() as u64,
        reference_bytes: audio.len() as u64,
    }
    .to_json();
    if start.len() as u64 > max_header_bytes || transcript.len() as u64 > max_header_bytes {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(start)
}

/// Whether a `started` frame answers this call's `start`: its generation,
/// its target, its rate and its mono channel.
pub fn started_matches(meta: &JsonValue, target: &JsonValue, sample_rate: u32) -> bool {
    meta.get("generation").and_then(JsonValue::as_u64) == Some(VOICE_GENERATION)
        && meta["target"] == *target
        && meta["sample_rate"].as_u64() == Some(u64::from(sample_rate))
        && meta["channels"].as_u64() == Some(1)
}

/// An `error` frame's code as the call's error: a failed render may go
/// again, as a 503 did; every other code refuses the call, as a 400 did.
pub fn worker_error(code: &str) -> LlmError {
    if code == "render_failed" {
        RetryableLlmError::ServerError.into()
    } else {
        FatalLlmError::InvalidRequest.into()
    }
}

/// The header of one mono WAV at `sample_rate` holding every render's
/// audio, with room for it: the header [`pcm16_wav`] writes for an empty
/// clip, its RIFF and data lengths the joined audio's. `None` when the
/// joined audio overflows a WAV's 32-bit lengths.
pub fn joined_wav_header(sample_rate: u32, renders: &[VoxCpm2PcmBody]) -> Option<Vec<u8>> {
    let data = u32::try_from(renders.iter().map(VoxCpm2PcmBody::len).sum::<u64>()).ok()?;
    let riff = data.checked_add(36)?;
    let mut wav = pcm16_wav(sample_rate, 1, &[])?;
    wav.get_mut(4..8)?.copy_from_slice(&riff.to_le_bytes());
    wav.get_mut(40..44)?.copy_from_slice(&data.to_le_bytes());
    wav.reserve_exact(data as usize);
    Some(wav)
}
