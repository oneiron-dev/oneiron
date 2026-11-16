//! The VoxCPM2 worker's render wire (`deploy/voxcpm2`, OF-410), as the
//! server's own-server speech rung speaks it. `GET /ready` names the warm
//! target a render must pin. `POST /render` sends a length-prefixed JSON
//! header, the reference transcript as a frame of its own when the worker
//! takes one (FIX 3758), then the clip's WAV; the worker answers with a
//! header for the same target and mono PCM16. This module cuts the text into
//! renders whose headers fit, frames each request, and reads each reply's
//! framing as it arrives. The host pins the target, uploads under the bank's
//! current reference, spools the audio and settles the call.
//!
//! The consent-fenced cascade adapter on the same worker,
//! `oneiron::voice_cascade::voxcpm2`, stays in core: it sends inside the
//! vault's voice consent fence.
use oneiron::llm::media::wav::pcm16_wav;
use oneiron::voice_cascade::speakable_pieces;
use oneiron::voice_cascade::voxcpm2::{VoiceServingLimits, VoxCpm2PcmBody};
use oneiron::{FatalLlmError, LlmResult};
use serde_json::{Value as JsonValue, json};

/// Where a render's reference transcript rides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptPlacement {
    /// In the JSON header, beside the text: every worker takes this.
    Header,
    /// As its own frame of `transcript_bytes` bytes between the header and
    /// the clip, for a worker whose `/ready` says it takes one.
    Frame,
}

/// A render's reference transcript and where it rides.
#[derive(Clone, Copy, Debug)]
pub struct Transcript<'a> {
    pub text: &'a str,
    pub placement: TranscriptPlacement,
}

/// One render's JSON header: the pinned target, the text, and the reference
/// transcript when it rides here, else its byte length.
pub fn render_header(
    target: &JsonValue,
    text: &str,
    transcript: Transcript<'_>,
) -> LlmResult<Vec<u8>> {
    let header = match transcript.placement {
        TranscriptPlacement::Header => json!({
            "target": target,
            "text": text,
            "transcript": transcript.text,
        }),
        TranscriptPlacement::Frame => json!({
            "target": target,
            "text": text,
            "transcript_bytes": transcript.text.len(),
        }),
    };
    serde_json::to_vec(&header).map_err(|_| FatalLlmError::InvalidRequest.into())
}

/// The bytes `text` takes as a JSON string, without its quotes.
fn escaped_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |quoted| quoted.len().saturating_sub(2))
}

/// The renders `text` goes as, and where their reference transcript rides,
/// so every render's header stays within the worker's decoder bound
/// `max_header` (FIX 3758). The transcript rides in the header while every
/// piece within `max_text` fits beside it, as before; past that, as a frame
/// of its own when the worker takes one; else the pieces split again until
/// each header fits. Refused only when not one character fits.
pub fn header_pieces<'t>(
    target: &JsonValue,
    text: &'t str,
    transcript: &'t str,
    limits: VoiceServingLimits,
    takes_frame: bool,
) -> LlmResult<(Transcript<'t>, Vec<&'t str>)> {
    let max_text = usize::try_from(limits.max_text_bytes).unwrap_or(usize::MAX);
    let max_header = usize::try_from(limits.max_header_bytes).unwrap_or(usize::MAX);
    let pieces = speakable_pieces(text, max_text);
    // Every header differs from the empty-text one only by its text.
    let fits_beside = |transcript: Transcript<'_>| -> LlmResult<_> {
        let overhead = render_header(target, "", transcript)?.len();
        Ok(move |piece: &str| overhead.saturating_add(escaped_len(piece)) <= max_header)
    };
    let inline = Transcript {
        text: transcript,
        placement: TranscriptPlacement::Header,
    };
    let fits = fits_beside(inline)?;
    if pieces.iter().all(|&piece| fits(piece)) {
        return Ok((inline, pieces));
    }
    let transcript = if takes_frame {
        Transcript {
            text: transcript,
            placement: TranscriptPlacement::Frame,
        }
    } else {
        inline
    };
    let fits = fits_beside(transcript)?;
    let mut fitted = Vec::with_capacity(pieces.len());
    for piece in pieces {
        split_to_fit(piece, &fits, &mut fitted)?;
    }
    Ok((transcript, fitted))
}

/// `piece` as pieces whose header `fits`, in order: one that does not is
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
    // One character that does not fit beside the transcript cannot go.
    if piece.chars().nth(1).is_none() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    for part in speakable_pieces(piece, piece.len() / 2) {
        split_to_fit(part, fits, out)?;
    }
    Ok(())
}

/// One render's request body: the JSON header's 4-byte big-endian length,
/// the header, the reference transcript when it rides as a frame of its own,
/// then the clip's `audio`. Refused when the header passes the effective
/// JSON header decoder bound `max_header_bytes`, its wire's own: the pieces
/// were cut to fit within it.
pub fn render_body(
    target: &JsonValue,
    text: &str,
    transcript: Transcript<'_>,
    max_header_bytes: u64,
    audio: &[u8],
) -> LlmResult<Vec<u8>> {
    let header = render_header(target, text, transcript)?;
    if header.len() as u64 > max_header_bytes {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let length = u32::try_from(header.len()).map_err(|_| FatalLlmError::InvalidRequest)?;
    let framed = match transcript.placement {
        TranscriptPlacement::Header => &[][..],
        TranscriptPlacement::Frame => transcript.text.as_bytes(),
    };
    let mut body = Vec::with_capacity(4 + header.len() + framed.len() + audio.len());
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(&header);
    body.extend_from_slice(framed);
    body.extend_from_slice(audio);
    Ok(body)
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

/// One render's framed reply, read as it arrives: a 4-byte big-endian
/// header length, the JSON header, then the mono PCM16, which
/// [`RenderReply::push`] hands back for the host to keep.
pub struct RenderReply<'a> {
    /// The target the call pinned: the header must name it.
    target: &'a JsonValue,
    /// The warm target's rate: the header must name it.
    sample_rate: u32,
    /// The effective JSON header decoder bound.
    max_header_bytes: u64,
    /// The length prefix, then the header, until both are whole.
    head: Vec<u8>,
    /// The header's length, once its prefix is in.
    header: Option<usize>,
}

impl<'a> RenderReply<'a> {
    /// The reply to a render that pinned `target` on a worker speaking at
    /// `sample_rate`, under the effective header bound `max_header_bytes`.
    #[must_use]
    pub fn new(target: &'a JsonValue, sample_rate: u32, max_header_bytes: u64) -> Self {
        Self {
            target,
            sample_rate,
            max_header_bytes,
            head: Vec::with_capacity(4),
            header: None,
        }
    }
}

impl RenderReply<'_> {
    /// Takes the reply's next bytes and answers the audio among them. The
    /// header's length is checked against the effective bound before a byte
    /// of the header is held, and the header against the target this call
    /// pinned before any audio is handed back.
    pub fn push<'b>(&mut self, mut bytes: &'b [u8]) -> LlmResult<&'b [u8]> {
        let length = match self.header {
            Some(length) => length,
            None => {
                let take = (4 - self.head.len()).min(bytes.len());
                self.head.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                let Ok(prefix) = <[u8; 4]>::try_from(self.head.as_slice()) else {
                    return Ok(&[]);
                };
                let n = u32::from_be_bytes(prefix);
                if n == 0 || u64::from(n) > self.max_header_bytes {
                    return Err(FatalLlmError::EmptyResponse.into());
                }
                let length = n as usize;
                self.header = Some(length);
                length
            }
        };
        if self.head.len() < 4 + length {
            let take = (4 + length - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.head.len() < 4 + length {
                return Ok(&[]);
            }
            self.check_header()?;
        }
        Ok(bytes)
    }

    /// Whether the header came whole: a reply that ended before it did
    /// holds no render.
    #[must_use]
    pub fn header_whole(&self) -> bool {
        self.header
            .is_some_and(|length| self.head.len() >= 4 + length)
    }

    /// The audio must be for the very target this call pinned.
    fn check_header(&self) -> LlmResult<()> {
        let meta: JsonValue =
            serde_json::from_slice(&self.head[4..]).map_err(|_| FatalLlmError::EmptyResponse)?;
        if meta["target"] != *self.target
            || meta["sample_rate"].as_u64() != Some(u64::from(self.sample_rate))
            || meta["channels"].as_u64() != Some(1)
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(())
    }
}
