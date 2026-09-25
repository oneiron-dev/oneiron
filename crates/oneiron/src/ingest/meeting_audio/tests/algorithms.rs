use super::super::alignment::make_turns;
use super::super::cleanup::apply_cleanup;
use super::super::packing::{packed_audio, source_times};
use super::super::*;

fn span(start_ms: u64, end_ms: u64) -> SpeechSpan {
    SpeechSpan { start_ms, end_ms }
}

fn word(start_ms: u64, end_ms: u64, text: &str) -> TranscriptWord {
    TranscriptWord {
        word_id: format!("word-{start_ms}"),
        pack_id: "pack-1".into(),
        start_ms,
        end_ms,
        text: text.into(),
        confidence: None,
        speaker_cluster: "unassigned".into(),
    }
}

fn track(start_ms: u64, end_ms: u64, speaker: &str) -> SpeakerTrack {
    SpeakerTrack {
        start_ms,
        end_ms,
        speaker_cluster: speaker.into(),
    }
}

#[test]
fn boundary_packing_preserves_all_speech_without_duplicate_audio() {
    let spans = [
        span(1_000, 46_000),
        span(48_000, 93_000),
        span(95_000, 140_000),
        span(142_000, 187_000),
    ];
    let packs = pack_speech(&spans, 190_000).unwrap();
    assert_eq!(packs.len(), 2);
    assert!(
        packs
            .iter()
            .all(|p| (90_000..=120_000).contains(&p.audio_ms))
    );
    assert_eq!(packs.iter().map(|p| p.speech_ms).sum::<u64>(), 180_000);
    let source: Vec<_> = packs.iter().flat_map(|p| &p.source_spans).collect();
    for (speech, padded) in spans.iter().zip(&source) {
        assert_eq!(padded.source_start_ms, speech.start_ms - 250);
        assert_eq!(padded.source_end_ms, speech.end_ms + 250);
    }
    assert!(
        source
            .windows(2)
            .all(|w| w[0].source_end_ms <= w[1].source_start_ms)
    );
    for pack in &packs {
        assert!(!pack.oversize_no_boundary);
        assert_eq!(pack.source_spans.first().unwrap().pack_start_ms, 0);
        assert_eq!(pack.source_spans.last().unwrap().pack_end_ms, pack.audio_ms);
        assert!(
            pack.source_spans
                .windows(2)
                .all(|w| w[0].pack_end_ms == w[1].pack_start_ms)
        );
    }
}

#[test]
fn oversize_speech_is_intact_but_padding_alone_cannot_cause_oversize() {
    let long = pack_speech(&[span(1_000, 151_000)], 160_000).unwrap();
    assert_eq!(long.len(), 1);
    assert!(long[0].oversize_no_boundary);
    assert_eq!(long[0].speech_ms, 150_000);
    assert_eq!(long[0].source_spans[0].source_start_ms, 750);
    assert_eq!(long[0].source_spans[0].source_end_ms, 151_250);
    let exact = pack_speech(&[span(1_000, 121_000)], 130_000).unwrap();
    assert!(!exact[0].oversize_no_boundary);
    assert_eq!(exact[0].audio_ms, 120_000);
    assert_eq!(exact[0].source_spans[0].source_start_ms, 1_000);
    assert_eq!(exact[0].source_spans[0].source_end_ms, 121_000);
}

#[test]
fn short_tail_and_boundary_limited_pack_are_not_dropped() {
    let packs = pack_speech(
        &[
            span(0, 80_000),
            span(81_000, 161_000),
            span(162_000, 165_000),
        ],
        166_000,
    )
    .unwrap();
    assert_eq!(packs.len(), 2);
    assert!(packs.iter().all(|pack| pack.audio_ms < 90_000));
    assert_eq!(
        packs.iter().map(|pack| pack.speech_ms).sum::<u64>(),
        163_000
    );
    assert_eq!(
        packs
            .last()
            .unwrap()
            .source_spans
            .last()
            .unwrap()
            .source_end_ms,
        165_250
    );
}

#[test]
fn overlapping_vad_spans_merge_and_nested_disorder_is_refused() {
    let packs = pack_speech(&[span(100, 900), span(200, 400), span(800, 1_000)], 1_100).unwrap();
    assert_eq!(packs[0].source_spans.len(), 1);
    assert_eq!(packs[0].speech_ms, 900);
    assert_eq!(packs[0].audio_ms, 1_100);
    assert_eq!(
        pack_speech(&[span(100, 900), span(200, 400), span(150, 180)], 1_000),
        Err(AudioError::InvalidVad)
    );
    for bad in [[span(3, 3)], [span(4, 3)], [span(0, 1_001)]] {
        assert_eq!(pack_speech(&bad, 1_000), Err(AudioError::InvalidVad));
    }
    assert_eq!(pack_speech(&[], 1_000), Err(AudioError::NoSpeech));
    assert_eq!(pack_speech(&[], 0), Err(AudioError::InvalidAudio));
}

#[test]
fn audio_slices_and_word_clock_reconstruct_source_after_removed_silence() {
    let packs = pack_speech(&[span(100, 200), span(2_000, 2_100)], 2_200).unwrap();
    let pack = &packs[0];
    let audio = Pcm16 {
        samples: (0..35_200)
            .map(|n| i16::try_from(n % 1_009).unwrap())
            .collect(),
    };
    let packed = packed_audio(&audio, pack).unwrap();
    let expected: Vec<i16> = audio.samples[..7_200]
        .iter()
        .chain(&audio.samples[28_000..35_200])
        .copied()
        .collect();
    assert_eq!(packed.samples, expected);
    assert_eq!(source_times(pack, 100, 200).unwrap(), (100, 200));
    assert_eq!(source_times(pack, 700, 800).unwrap(), (2_000, 2_100));
    assert_eq!(
        source_times(pack, 449, 451),
        Err(AudioError::WordCrossesPackSeam)
    );
    assert_eq!(source_times(pack, 900, 901), Err(AudioError::InvalidWords));
}

#[test]
fn adjacent_pads_meet_once_and_contiguous_clock_seams_are_safe() {
    let packs = pack_speech(&[span(100, 200), span(300, 400)], 500).unwrap();
    let pack = &packs[0];
    assert_eq!(pack.source_spans[0].source_end_ms, 250);
    assert_eq!(pack.source_spans[1].source_start_ms, 250);
    assert_eq!(pack.audio_ms, 500);
    assert_eq!(source_times(pack, 240, 260).unwrap(), (240, 260));
}

#[test]
fn iou_not_raw_overlap_selects_the_speaker_and_keeps_turn_identity() {
    // 60ms intersection with a 1000ms track loses to 40ms/100ms IoU.
    let tracks = [track(0, 1_000, "long"), track(1_000, 1_040, "short")];
    let mut words = [word(940, 1_040, "yes")];
    align_words_to_speakers(&mut words, &tracks, 1_100).unwrap();
    assert_eq!(words[0].speaker_cluster, "short");
    let turns = make_turns(&words);
    assert_eq!(turns[0].speaker_cluster, "short");
    assert_eq!(turns[0].source_word_ids, [words[0].word_id.clone()]);
    let mut tied = [word(0, 20, "tie")];
    align_words_to_speakers(&mut tied, &[track(0, 10, "z"), track(10, 20, "a")], 20).unwrap();
    assert_eq!(tied[0].speaker_cluster, "a");
}

#[test]
fn alignment_refuses_track_overlap_or_uncovered_word_without_partial_mutation() {
    let mut words = [word(0, 10, "covered"), word(30, 40, "missing")];
    let before = words.clone();
    assert_eq!(
        align_words_to_speakers(&mut words, &[track(0, 20, "a")], 50),
        Err(AudioError::UnlabelledWord {
            word_id: "word-30".into()
        })
    );
    assert_eq!(words, before);
    for tracks in [
        vec![track(0, 20, "a"), track(19, 40, "b")],
        vec![track(0, 51, "a")],
        vec![track(0, 50, " ")],
    ] {
        assert_eq!(
            align_words_to_speakers(&mut words, &tracks, 50),
            Err(AudioError::NonExclusiveTracks)
        );
        assert_eq!(words, before);
    }
    let mut reversed = [word(30, 40, "late"), word(0, 10, "early")];
    assert_eq!(
        align_words_to_speakers(&mut reversed, &[track(0, 50, "a")], 50),
        Err(AudioError::InvalidWords)
    );
}

#[test]
fn cleanup_rejects_invention_deletion_reorder_symbol_changes_and_word_joining() {
    for (raw, cleaned) in [
        ("hello world", "Hello, world!"),
        ("日本語です", "日本語です。"),
        ("we can't", "We can't."),
    ] {
        validate_cleanup(raw, cleaned).unwrap();
    }
    for (raw, cleaned) in [
        ("we will not ship", "We will ship."),
        ("send draft", "Send approved draft."),
        ("Ada met Ben", "Ben met Ada"),
        ("therapist", "the rapist"),
        ("a b", "ab"),
        ("-5", "+5"),
        ("1.5", "15"),
        ("1.5", "1,5"),
        ("re-sign", "resign"),
        ("安全ではない", "安全です"),
        ("", ""),
    ] {
        assert_eq!(
            validate_cleanup(raw, cleaned),
            Err(AudioError::CleanupInventedContent)
        );
    }
    let mut words = [word(0, 10, "hello"), word(20, 30, "not")];
    words[0].speaker_cluster = "a".into();
    words[1].speaker_cluster = "b".into();
    let mut turns = make_turns(&words);
    let before = turns.clone();
    assert_eq!(
        apply_cleanup(&mut turns, vec!["Hello!".into(), "yes".into()]),
        Err(AudioError::CleanupInventedContent)
    );
    assert_eq!(turns, before);
    assert_eq!(
        apply_cleanup(&mut turns, vec!["hello not".into()]),
        Err(AudioError::CleanupChangedTurns)
    );
    assert_eq!(turns, before);
}
