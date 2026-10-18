//! Silence removal with source-clock maps and 90–120 second packs, cut at
//! speech boundaries, and inside an utterance only when it outlasts a pack.

use super::{AudioError, AudioResult, Pcm16, SourceSpan, SpeechPack, SpeechSpan};

const PAD_MS: u64 = 250;
const MIN_PACK_MS: u64 = 90_000;
const MAX_PACK_MS: u64 = 120_000;
/// How far before a pack's bound an utterance that outlasts it is searched
/// for its cut.
const CUT_SEARCH_MS: u64 = 10_000;
/// The frame the quietest point is measured over, and the samples per
/// millisecond of the 16 kHz recording.
const QUIET_FRAME_MS: u64 = 20;
const SAMPLES_PER_MS: u64 = 16;

/// [`pack_speech_cut`] with every cut at the pack's bound itself.
pub fn pack_speech(spans: &[SpeechSpan], duration_ms: u64) -> AudioResult<Vec<SpeechPack>> {
    pack_speech_cut(spans, duration_ms, |_, hi| hi)
}

/// Keep every speech sample once. Padding meets at silence midpoints, so it
/// neither duplicates audio nor crosses another utterance. Overlapping/touching
/// VAD spans are indivisible up to a pack: an uninterrupted utterance longer
/// than 120s is split into touching pieces of at most 120s (Rule 5), each cut
/// at `cut(lo, hi)`, a millisecond in the last [`CUT_SEARCH_MS`] before the
/// bound (the producer's is the quietest point there). The pieces partition
/// the utterance, so no sample is lost or repeated and no padding crosses a
/// cut; no pack is then longer than one ASR and alignment call takes.
///
/// Prefer 90–120s of padded audio. Short tails and boundary-limited short packs
/// are unavoidable for some span sequences; never cut speech only to meet the
/// 90s target. Padding alone never causes an `oversize_no_boundary` exception.
pub(super) fn pack_speech_cut(
    spans: &[SpeechSpan],
    duration_ms: u64,
    cut: impl Fn(u64, u64) -> u64,
) -> AudioResult<Vec<SpeechPack>> {
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
    let mut pieces = Vec::with_capacity(speech.len());
    for span in speech {
        let mut start = span.start_ms;
        while span.end_ms - start > MAX_PACK_MS {
            let hi = start + MAX_PACK_MS;
            let lo = hi - CUT_SEARCH_MS;
            let at = cut(lo, hi).clamp(lo, hi);
            pieces.push(SpeechSpan {
                start_ms: start,
                end_ms: at,
            });
            start = at;
        }
        pieces.push(SpeechSpan {
            start_ms: start,
            end_ms: span.end_ms,
        });
    }
    let speech = pieces;
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

/// The start of the quietest [`QUIET_FRAME_MS`] frame of `audio` between
/// `lo` and `hi` milliseconds, by summed absolute amplitude; the latest on a
/// tie, and `hi` when no whole frame fits.
pub(super) fn quietest_ms(audio: &Pcm16, lo: u64, hi: u64) -> u64 {
    let mut quietest = (u64::MAX, hi);
    let mut at = lo;
    while at + QUIET_FRAME_MS <= hi {
        let samples = usize::try_from(at * SAMPLES_PER_MS)
            .ok()
            .zip(usize::try_from((at + QUIET_FRAME_MS) * SAMPLES_PER_MS).ok())
            .and_then(|(from, to)| audio.samples.get(from..to));
        let Some(frame) = samples else {
            break;
        };
        let energy: u64 = frame
            .iter()
            .map(|sample| u64::from(sample.unsigned_abs()))
            .sum();
        if energy <= quietest.0 {
            quietest = (energy, at);
        }
        at += QUIET_FRAME_MS;
    }
    quietest.1
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
