//! Exclusive full-file speaker alignment and label-preserving turn assembly.

use super::{AudioError, AudioResult, SpeakerTrack, TranscriptTurn, TranscriptWord};

/// Reject overlapping tracks, unsorted segments and missing speaker labels.
/// Silence need not have a label; every emitted word must intersect a track.
/// Ties use the lexicographically smaller global label. Failure leaves all
/// input words untouched. IoU is compared exactly without floating point.
pub fn align_words_to_speakers(
    words: &mut [TranscriptWord],
    tracks: &[SpeakerTrack],
    duration_ms: u64,
) -> AudioResult<()> {
    let mut previous_end = 0;
    for track in tracks {
        if track.start_ms >= track.end_ms
            || track.start_ms < previous_end
            || track.end_ms > duration_ms
            || track.speaker_cluster.trim().is_empty()
        {
            return Err(AudioError::NonExclusiveTracks);
        }
        previous_end = track.end_ms;
    }
    previous_end = 0;
    let mut track_cursor = 0;
    let mut labels = Vec::with_capacity(words.len());
    for word in &*words {
        if word.start_ms >= word.end_ms || word.start_ms < previous_end || word.end_ms > duration_ms
        {
            return Err(AudioError::InvalidWords);
        }
        previous_end = word.end_ms;
        while tracks
            .get(track_cursor)
            .is_some_and(|track| track.end_ms <= word.start_ms)
        {
            track_cursor += 1;
        }
        let mut best: Option<(&SpeakerTrack, u64, u64)> = None;
        for track in &tracks[track_cursor..] {
            if track.start_ms >= word.end_ms {
                break;
            }
            let intersection = word
                .end_ms
                .min(track.end_ms)
                .saturating_sub(word.start_ms.max(track.start_ms));
            if intersection == 0 {
                continue;
            }
            // For intersecting intervals, union equals the outer span.
            let union = word.end_ms.max(track.end_ms) - word.start_ms.min(track.start_ms);
            let replace = best.is_none_or(|(old, old_intersection, old_union)| {
                let left = u128::from(intersection) * u128::from(old_union);
                let right = u128::from(old_intersection) * u128::from(union);
                left > right || (left == right && track.speaker_cluster < old.speaker_cluster)
            });
            if replace {
                best = Some((track, intersection, union));
            }
        }
        let label = best
            .map(|(track, _, _)| track.speaker_cluster.clone())
            .ok_or_else(|| AudioError::UnlabelledWord {
                word_id: word.word_id.clone(),
            })?;
        labels.push(label);
    }
    for (word, label) in words.iter_mut().zip(labels) {
        word.speaker_cluster = label;
    }
    Ok(())
}

pub(super) fn make_turns(words: &[TranscriptWord]) -> Vec<TranscriptTurn> {
    let mut turns: Vec<TranscriptTurn> = Vec::new();
    for word in words {
        if let Some(turn) = turns.last_mut()
            && turn.speaker_cluster == word.speaker_cluster
            && word.start_ms.saturating_sub(turn.end_ms) <= 2_000
        {
            turn.end_ms = word.end_ms;
            turn.text.push(' ');
            turn.text.push_str(&word.text);
            turn.source_word_ids.push(word.word_id.clone());
            continue;
        }
        turns.push(TranscriptTurn {
            turn_id: format!("turn-{:04}", turns.len() + 1),
            start_ms: word.start_ms,
            end_ms: word.end_ms,
            text: word.text.clone(),
            source_word_ids: vec![word.word_id.clone()],
            speaker_cluster: word.speaker_cluster.clone(),
        });
    }
    turns
}
