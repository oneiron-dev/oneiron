//! FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW: the main claim
//! extraction call's input is sized by the extraction model's lent window
//! less the prompt it carries, not by its TURN count alone. A TURN past the
//! room is read alone, its words whole; with no window lent, chunks stay by
//! count. A chunk whose built call passes the room (its bound relationship
//! lines) is split; host material keeps only the whole texts that fit
//! (review round 1 of #9809). A single TURN whose built call passes drops
//! whole host texts, the last first; a call whose page as rendered (its
//! bound relationship lines too) fills the room is marked, and only a call
//! to the extraction model over it is refused: a relation reply the engine
//! authors still runs (review round 2 of #9809).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_extraction_room`

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::memory::extraction::{
    EncoderOutput, NerSpan, RelationLink, SpeakerLink, SpeakerTarget,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{TaggingMarkerConfig, TaggingMode};
use oneiron::test_doors::consolidation::{
    consolidate_tagged_turn_in_window, consolidate_unbound_turn_in_window,
    open_tagged_dreamer_vault,
};
use oneiron::test_doors::dreamer_extraction_room::{
    fitted_calls, fitted_chunk_sizes, meso_extraction_transcripts, room_slice_calls,
};

/// The shipped prompt's frame (system text and worked examples) is 7,698
/// bytes; at the shipped estimate of 3 bytes a token, a 6,000-token window
/// leaves 10,302 bytes for a call's transcript: two of the 4,000-byte TURNs
/// below with their lines and listing, never three.
const WINDOW_TOKENS: u64 = 6_000;
const ROOM_BYTES: usize = 6_000 * 3 - 7_698;
const TURNS_PER_CHILD: usize = 16;
/// 7,500 bytes at 3 a token: less than the shipped prompt's 7,698-byte
/// frame, so a call's transcript has no room at all.
const NO_ROOM_WINDOW_TOKENS: u64 = 2_500;

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
    let calls = room_slice_calls(&words, false, &[kept.clone(), past], Some(ROOM_BYTES))
        .expect("native slices in a room");
    assert!(!calls.is_empty(), "the TURNs are read");
    for call in calls.iter().map(|call| &call.transcript) {
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
fn a_room_that_holds_no_listing_page_marks_every_call() {
    let calls = room_slice_calls(&["owen planted tulips"], false, &[], Some(0))
        .expect("the slicing itself never refuses");
    assert!(!calls.is_empty(), "the TURN is read");
    assert!(
        calls.iter().all(|call| call.page_past_room),
        "no page fits a room of nothing: {calls:?}"
    );
}

#[test]
fn a_single_turn_past_the_room_drops_whole_host_texts_from_the_last() {
    // One 28-byte TURN line and 161 bytes of bound relationship lines the
    // estimate leaves out: with both texts the call is 10,389 bytes.
    assert_eq!(
        fitted_calls(&[28], TURNS_PER_CHILD, ROOM_BYTES, 161, &[100, 10_100]),
        vec![(1, 1)],
        "the last text goes, the first stays"
    );
    assert_eq!(
        fitted_calls(&[28], TURNS_PER_CHILD, ROOM_BYTES, 161, &[10_200]),
        vec![(1, 0)],
        "a TURN that fits alone is read with no text that passes the room"
    );
    assert_eq!(
        fitted_calls(&[3_000, 3_000], TURNS_PER_CHILD, ROOM_BYTES, 500, &[4_000]),
        vec![(1, 1), (1, 1)],
        "a chunk splits before it drops a text"
    );
}

/// The bytes of the listing page in a one-conversation `transcript`: the
/// lines after its conversation header and before its first TURN line.
fn page_bytes(transcript: &str) -> usize {
    transcript
        .lines()
        .skip_while(|line| !line.starts_with("conversation "))
        .skip(1)
        .take_while(|line| !line.starts_with("[T"))
        .map(|line| line.len() + 1)
        .sum()
}

#[test]
fn a_page_fills_the_room_as_rendered_with_its_bound_relationship() {
    let words = ["owen planted tulips"];
    let whole = room_slice_calls(&words, true, &[], None).expect("native slices, no room");
    let [call] = whole.as_slice() else {
        panic!("FIXTURE: one TURN is one call: {whole:?}");
    };
    assert!(
        call.transcript
            .lines()
            .any(|line| line.starts_with("relationship ")),
        "FIXTURE: the call lists its words' relationship: {}",
        call.transcript
    );
    let page = page_bytes(&call.transcript);
    let at_page = room_slice_calls(&words, true, &[], Some(page)).expect("native slices");
    assert!(
        !at_page.is_empty() && at_page.iter().all(|call| call.page_past_room),
        "a {page}-byte page with its relationship line fills a {page}-byte room: {at_page:?}"
    );
    let past_page = room_slice_calls(&words, true, &[], Some(page + 1)).expect("native slices");
    assert!(
        !past_page.is_empty() && past_page.iter().all(|call| !call.page_past_room),
        "a {page}-byte page leaves a {}-byte room a byte: {past_page:?}",
        page + 1
    );
}

const READER: &str = "reader";
const CHECKPOINT: &str = "0123456789abcdef";
const WORDS: &str = "I work at Acme";
const PREDICATE: &str = "work.employer";

/// A vault whose tagger saves its tags, maps `PERSON`, and maps the
/// `works_at` relation to [`PREDICATE`] (as tests/jointie_relation_extraction.rs).
fn tagged_vault(dir: &tempfile::TempDir) -> oneiron::Vault {
    let tagging = TaggingMarkerConfig::new(CHECKPOINT)
        .expect("checkpoint")
        .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
        .with_relations(BTreeMap::from([(
            "works_at".to_owned(),
            PREDICATE.to_owned(),
        )]))
        .with_mode(TaggingMode::Save);
    open_tagged_dreamer_vault(dir.path(), READER, tagging).expect("fixture vault")
}

/// A relation-capable tagger's answer for [`WORDS`]: `I`, the turn's
/// speaker; `Acme`; and one `works_at` relation from `I` to `Acme`.
fn works_at_tags() -> EncoderOutput {
    let span = |start: usize, end: usize, label: &str| NerSpan {
        message: 0,
        start,
        end,
        label: label.to_owned(),
        confidence: 0.9,
    };
    EncoderOutput {
        spans: vec![span(0, 1, "PRONOUN"), span(10, 14, "ORG")],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: vec![SpeakerLink {
            span: 0,
            target: SpeakerTarget::Speaker,
            confidence: 0.9,
        }],
        mood_parts: Vec::new(),
        relations: Some(vec![RelationLink {
            head: 0,
            tail: 1,
            label: "works_at".to_owned(),
            confidence: 0.9,
        }]),
        stack_sha16: None,
    }
}

/// The scripted model's reply: a claim no relation would file.
fn decoy() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Acme", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "decoy.value",
            "value": "model",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Acme"}],
        }],
    })
    .to_string()
}

#[test]
fn a_window_with_no_room_runs_a_relation_reply_and_refuses_the_model() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = tagged_vault(&dir);
    let pass = consolidate_tagged_turn_in_window(
        &vault,
        WORDS,
        &works_at_tags(),
        &decoy(),
        Some(NO_ROOM_WINDOW_TOKENS),
    )
    .expect("a slice its relations cover sends no prompt, so no window refuses it");
    assert!(
        pass.call_relationships.is_empty(),
        "a covered slice calls no model: {:?}",
        pass.call_relationships
    );
    let [claim] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let body = vault
        .get_claim(claim)
        .expect("claim read")
        .expect("the landed claim");
    assert_eq!(
        body.predicate, PREDICATE,
        "the relation reply's claim lands"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = tagged_vault(&dir);
    consolidate_unbound_turn_in_window(&vault, WORDS, &decoy(), Some(NO_ROOM_WINDOW_TOKENS))
        .expect_err("an untagged slice needs the model, and its window holds no page");
}
