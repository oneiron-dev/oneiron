//! FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW: the main claim
//! extraction call's input is sized by the extraction model's lent window
//! less the prompt it carries, not by its TURN count alone. A TURN past the
//! room is read alone, its words whole; with no window lent, chunks stay by
//! count. A chunk whose built call passes the room (its bound relationship
//! lines) is split; host material keeps only the whole texts that fit; and a
//! room that holds no listing page is refused (review round 1 of #9809).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_extraction_room`

#![cfg(oneiron_test_support)]

use oneiron::test_doors::dreamer_extraction_room::{
    fitted_chunk_sizes, meso_extraction_transcripts, room_slice_transcripts,
};

/// The shipped prompt's frame (system text and worked examples) is 7,698
/// bytes; at the shipped estimate of 3 bytes a token, a 6,000-token window
/// leaves 10,302 bytes for a call's transcript: two of the 4,000-byte TURNs
/// below with their lines and listing, never three.
const WINDOW_TOKENS: u64 = 6_000;
const ROOM_BYTES: usize = 6_000 * 3 - 7_698;
const TURNS_PER_CHILD: usize = 16;

/// `count` TURNs of about `bytes` bytes each, every one naming owen and
/// numbered, so each reads apart.
fn turns(count: usize, bytes: usize) -> Vec<String> {
    let sentence = "owen enjoys green tea in the morning. ";
    (0..count)
        .map(|index| format!("note {index}: {}", sentence.repeat(bytes / sentence.len())))
        .collect()
}

/// The TURN lines a transcript holds: `[T<n> <speaker>] <words>`.
fn turn_lines(transcript: &str) -> usize {
    transcript
        .lines()
        .filter(|line| line.starts_with("[T"))
        .count()
}

/// Each of `words` read by exactly one call, whole.
fn assert_each_read_once(words: &[String], calls: &[String]) {
    for said in words {
        let readers = calls
            .iter()
            .filter(|call| call.contains(said.as_str()))
            .count();
        assert_eq!(readers, 1, "a TURN is read whole by one call: {calls:?}");
    }
}

#[test]
fn a_lent_window_splits_a_chunk_its_turns_overfill() {
    let words = turns(4, 4_000);
    let calls = meso_extraction_transcripts(&words, TURNS_PER_CHILD, Some(WINDOW_TOKENS))
        .expect("Meso pass with a lent window");
    let per_call: Vec<usize> = calls.iter().map(|call| turn_lines(call)).collect();
    assert_eq!(
        per_call,
        vec![2, 2],
        "four 4,000-byte TURNs fill a {ROOM_BYTES}-byte room two at a time"
    );
    for call in &calls {
        assert!(
            call.len() <= ROOM_BYTES,
            "a call's transcript fits its room: {} > {ROOM_BYTES}",
            call.len()
        );
    }
    assert_each_read_once(&words, &calls);
}

#[test]
fn a_turn_past_the_room_is_read_alone_and_whole() {
    let mut words = turns(3, 500);
    let long = format!("long {}", "owen walked the whole coast path. ".repeat(600));
    assert!(long.len() > ROOM_BYTES);
    words.insert(1, long.clone());
    let calls = meso_extraction_transcripts(&words, TURNS_PER_CHILD, Some(WINDOW_TOKENS))
        .expect("Meso pass with a lent window");
    let holders: Vec<&String> = calls
        .iter()
        .filter(|call| call.contains(long.as_str()))
        .collect();
    assert_eq!(holders.len(), 1, "the long TURN is read once: {calls:?}");
    assert_eq!(
        turn_lines(holders[0]),
        1,
        "the long TURN's call reads it alone"
    );
    assert_each_read_once(&words, &calls);
}

#[test]
fn with_no_window_lent_a_chunk_stays_one_call() {
    let words = turns(4, 4_000);
    let calls = meso_extraction_transcripts(&words, TURNS_PER_CHILD, None)
        .expect("Meso pass with no window lent");
    let per_call: Vec<usize> = calls.iter().map(|call| turn_lines(call)).collect();
    assert_eq!(
        per_call,
        vec![4],
        "with no window, TURNs chunk by count alone"
    );
    assert_each_read_once(&words, &calls);
}

#[test]
fn a_chunk_whose_built_call_passes_the_room_is_split() {
    // Two 5,099-byte TURN lines fit the room together by the estimate; ten
    // bound relationship lines it leaves out (195 bytes) pass it.
    assert_eq!(
        fitted_chunk_sizes(&[5_099, 5_099], TURNS_PER_CHILD, ROOM_BYTES, 195),
        vec![1, 1],
        "a built call past the room splits"
    );
    assert_eq!(
        fitted_chunk_sizes(&[5_099, 5_099], TURNS_PER_CHILD, ROOM_BYTES, 0),
        vec![2],
        "a built call within the room stays one"
    );
    assert_eq!(
        fitted_chunk_sizes(&[1_200; 8], TURNS_PER_CHILD, ROOM_BYTES, 800),
        vec![4, 4],
        "a split keeps the TURNs in order, half each"
    );
}

#[test]
fn host_material_past_the_room_keeps_only_the_whole_texts_that_fit() {
    let words = ["owen planted tulips", "owen painted the shed"];
    let kept = "owen keeps his garden plans in a notebook".to_owned();
    let past = format!("dropped {}", "garden notes ".repeat(1_000));
    assert!(past.len() > ROOM_BYTES);
    let calls = room_slice_transcripts(&words, &[kept.clone(), past], Some(ROOM_BYTES))
        .expect("native slices in a room");
    assert!(!calls.is_empty(), "the TURNs are read");
    for call in &calls {
        assert!(
            call.len() <= ROOM_BYTES,
            "a call's transcript fits its room: {} > {ROOM_BYTES}",
            call.len()
        );
        assert!(
            call.contains(kept.as_str()),
            "the text that fits rides: {call}"
        );
        assert!(
            !call.contains("dropped "),
            "the text past the room stays out"
        );
    }
}

#[test]
fn a_room_that_holds_no_listing_page_is_refused() {
    let error = room_slice_transcripts(&["owen planted tulips"], &[], Some(0))
        .expect_err("no room beside the prompt");
    assert!(
        format!("{error:?}").contains("larger window"),
        "the refusal names its bound: {error:?}"
    );
}
