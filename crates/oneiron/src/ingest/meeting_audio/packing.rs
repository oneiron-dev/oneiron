//! Silence removal with source-clock maps and boundary-only 90–120 second packs.

use super::{AudioError, AudioResult, Pcm16, SourceSpan, SpeechPack, SpeechSpan};

const PAD_MS: u64 = 250;
const MIN_PACK_MS: u64 = 90_000;
const MAX_PACK_MS: u64 = 120_000;

/// Keep every speech sample once. Padding meets at silence midpoints, so it
/// neither duplicates audio nor crosses another utterance. Overlapping/touching
/// VAD spans are indivisible. A >120s uninterrupted utterance remains intact.
///
/// Prefer 90–120s of padded audio. Short tails and boundary-limited short packs
/// are unavoidable for some span sequences; never cut speech to meet a target.
/// Padding alone never causes an `oversize_no_boundary` exception.
pub fn pack_speech(spans: &[SpeechSpan], duration_ms: u64) -> AudioResult<Vec<SpeechPack>> {
    if duration_ms == 0 {
        return Err(AudioError::InvalidAudio);
    }
    let mut speech: Vec<SpeechSpan> = Vec::new();
    let mut previous_start = 0;
    for span in spans {
        if span.start_ms >= span.end_ms
            || span.end_ms > duration_ms
            || span.start_ms < previous_start
        {
            return Err(AudioError::InvalidVad);
        }
        previous_start = span.start_ms;
        if let Some(previous) = speech.last_mut()
            && span.start_ms <= previous.end_ms
        {
            previous.end_ms = previous.end_ms.max(span.end_ms);
            continue;
        }
        speech.push(*span);
    }
    if speech.is_empty() {
        return Err(AudioError::NoSpeech);
    }
    let mut padded = Vec::with_capacity(speech.len());
    for (index, span) in speech.iter().enumerate() {
        let left = index.checked_sub(1).map_or(0, |previous| {
            speech[previous].end_ms + (span.start_ms - speech[previous].end_ms) / 2
        });
        let right = speech.get(index + 1).map_or(duration_ms, |next| {
            span.end_ms + (next.start_ms - span.end_ms) / 2
        });
        let mut start = span.start_ms.saturating_sub(PAD_MS).max(left);
        let mut end = span.end_ms.saturating_add(PAD_MS).min(right);
        if span.end_ms - span.start_ms <= MAX_PACK_MS && end - start > MAX_PACK_MS {
            let trim_right = (end - start - MAX_PACK_MS).min(end - span.end_ms);
            end -= trim_right;
            start += (end - start).saturating_sub(MAX_PACK_MS);
        }
        padded.push((start, end));
    }
    // These intervals do not overlap and lie within duration_ms; their sum fits.
    let mut remaining_ms: u64 = padded.iter().map(|(start, end)| end - start).sum();
    let mut packs = Vec::new();
    let mut pack = empty_pack(1);
    for (span, (start, end)) in speech.iter().zip(padded) {
        let audio_ms = end - start;
        if !pack.source_spans.is_empty()
            && (audio_ms > MAX_PACK_MS.saturating_sub(pack.audio_ms)
                || (pack.audio_ms >= MIN_PACK_MS
                    && remaining_ms > MAX_PACK_MS.saturating_sub(pack.audio_ms)))
        {
            packs.push(pack);
            pack = empty_pack(packs.len() + 1);
        }
        remaining_ms -= audio_ms;
        let pack_start_ms = pack.audio_ms;
        pack.audio_ms += audio_ms;
        pack.speech_ms += span.end_ms - span.start_ms;
        pack.oversize_no_boundary = pack.speech_ms > MAX_PACK_MS;
        pack.source_spans.push(SourceSpan {
            source_start_ms: start,
            source_end_ms: end,
            pack_start_ms,
            pack_end_ms: pack.audio_ms,
        });
    }
    packs.push(pack);
    Ok(packs)
}

fn empty_pack(index: usize) -> SpeechPack {
    SpeechPack {
        pack_id: format!("pack-{index:04}"),
        speech_ms: 0,
        audio_ms: 0,
        oversize_no_boundary: false,
        source_spans: Vec::new(),
    }
}

pub(super) fn packed_audio(audio: &Pcm16, pack: &SpeechPack) -> AudioResult<Pcm16> {
    let mut samples = Vec::new();
    for span in &pack.source_spans {
        let start = sample_index(span.source_start_ms, audio.samples.len())?;
        let end = sample_index(span.source_end_ms, audio.samples.len())?;
        samples.extend_from_slice(
            audio
                .samples
                .get(start..end)
                .ok_or(AudioError::InvalidAudio)?,
        );
    }
    Ok(Pcm16 { samples })
}

fn sample_index(ms: u64, max: usize) -> AudioResult<usize> {
    Ok(
        usize::try_from(ms.checked_mul(16).ok_or(AudioError::InvalidAudio)?)
            .map_err(|_| AudioError::InvalidAudio)?
            .min(max),
    )
}

/// A word crossing removed silence is refused, never stretched across a gap.
/// A seam with contiguous source audio is safe to cross (close VAD boundaries).
pub(super) fn source_times(pack: &SpeechPack, start: u64, end: u64) -> AudioResult<(u64, u64)> {
    if start >= end {
        return Err(AudioError::InvalidWords);
    }
    let Some(index) = pack
        .source_spans
        .iter()
        .position(|span| start >= span.pack_start_ms && start < span.pack_end_ms)
    else {
        return Err(AudioError::InvalidWords);
    };
    let first = &pack.source_spans[index];
    let source_start = first.source_start_ms + (start - first.pack_start_ms);
    for (offset, span) in pack.source_spans[index..].iter().enumerate() {
        if offset > 0 {
            let previous = &pack.source_spans[index + offset - 1];
            if previous.source_end_ms != span.source_start_ms {
                return Err(AudioError::WordCrossesPackSeam);
            }
        }
        if end <= span.pack_end_ms {
            return Ok((
                source_start,
                span.source_start_ms + (end - span.pack_start_ms),
            ));
        }
    }
    Err(AudioError::InvalidWords)
}
