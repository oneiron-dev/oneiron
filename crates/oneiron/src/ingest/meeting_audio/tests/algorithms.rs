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
        apply_cleanup(
            &mut turns,
            vec!["Hello!".into(), "yes".into()],
            &words,
            &Default::default(),
            None,
            None,
        ),
        Err(AudioError::CleanupInventedContent)
    );
    assert_eq!(turns, before);
    assert_eq!(
        apply_cleanup(
            &mut turns,
            vec!["hello not".into()],
            &words,
            &Default::default(),
            None,
            None,
        ),
        Err(AudioError::CleanupChangedTurns)
    );
    assert_eq!(turns, before);
}
