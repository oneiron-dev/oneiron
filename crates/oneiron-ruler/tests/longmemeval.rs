use oneiron_ruler::longmemeval::{
    ABSTENTION, ConvertError, LmeQuestion, PackMeta, SPLIT_CONTRACT, SliceCounts, Split,
    SplitEntry, convert, draw_split, lme_time, parse_dataset,
};
use oneiron_ruler::pack::{Slice, sha256_hex};

const CATEGORIES: [&str; 5] = [
    "single-session-user",
    "single-session-assistant",
    "single-session-preference",
    "multi-session",
    "temporal-reasoning",
];

const PREFIXES: [&str; 5] = ["ssu", "ssa", "ssp", "ms", "tr"];

fn mini_questions() -> (Vec<LmeQuestion>, String) {
    let bytes = include_bytes!("fixtures/longmemeval_mini.json");
    let questions = parse_dataset(bytes).expect("the mini fixture parses");
    let dataset_sha256 = sha256_hex(bytes);
    (questions, dataset_sha256)
}

fn mini_meta(dataset_sha256: &str) -> PackMeta {
    PackMeta {
        pack_id: "mini".to_owned(),
        revision: "1".to_owned(),
        dataset: "LongMemEval-S".to_owned(),
        dataset_sha256: dataset_sha256.to_owned(),
        license: "MIT".to_owned(),
    }
}

fn split_of(assignments: [Slice; 3], dataset_sha256: &str) -> Split {
    Split {
        contract: SPLIT_CONTRACT.to_owned(),
        dataset: "LongMemEval-S".to_owned(),
        dataset_sha256: dataset_sha256.to_owned(),
        entries: vec![
            SplitEntry {
                question_id: "mini_ssu_1".to_owned(),
                category: "single-session-user".to_owned(),
                slice: assignments[0],
            },
            SplitEntry {
                question_id: "mini_ku_1".to_owned(),
                category: "knowledge-update".to_owned(),
                slice: assignments[1],
            },
            SplitEntry {
                question_id: "mini_ssu_2_abs".to_owned(),
                category: ABSTENTION.to_owned(),
                slice: assignments[2],
            },
        ],
    }
}

fn fifty_questions() -> Vec<LmeQuestion> {
    let mut questions = Vec::new();
    for (category, prefix) in CATEGORIES.iter().zip(PREFIXES.iter()) {
        for index in 0..10 {
            questions.push(LmeQuestion {
                question_id: format!("{prefix}-{index:02}"),
                question_type: (*category).to_owned(),
                question: "What did Owen say?".to_owned(),
                question_date: "2023/05/20 (Sat) 02:21".to_owned(),
                haystack_session_ids: Vec::new(),
                haystack_dates: Vec::new(),
                haystack_sessions: Vec::new(),
                answer_session_ids: Vec::new(),
            });
        }
    }
    questions
}

#[test]
fn longmemeval_grades_evidence_turns() {
    let (questions, dataset_sha256) = mini_questions();
    let split = split_of(
        [Slice::Search, Slice::Search, Slice::Search],
        &dataset_sha256,
    );
    let meta = mini_meta(&dataset_sha256);
    let pack = convert(&questions, &split, Slice::Search, &meta, None).unwrap();
    assert_eq!(pack.queries.len(), 3);
    let grade_of = |query_id: &str, source_ref: &str| -> Option<u8> {
        let query = pack
            .queries
            .iter()
            .find(|query| query.query_id == query_id)
            .unwrap();
        let record = pack
            .records
            .iter()
            .find(|record| record.source_ref == source_ref)
            .unwrap();
        query.qrels.get(&record.record_id).copied()
    };
    assert_eq!(grade_of("mini_ssu_1", "answer_mini_ssu_1#2"), Some(2));
    assert_eq!(grade_of("mini_ssu_1", "answer_mini_ssu_1#0"), Some(1));
    assert_eq!(grade_of("mini_ssu_1", "answer_mini_ssu_1#1"), Some(1));
    assert_eq!(grade_of("mini_ssu_1", "answer_mini_ssu_1#3"), Some(1));
    assert_eq!(grade_of("mini_ssu_1", "shared_filler_1#0"), None);
    assert_eq!(grade_of("mini_ssu_1", "shared_filler_1#2"), None);
    assert_eq!(grade_of("mini_ku_1", "answer_mini_ku_1_new#1"), Some(2));
    assert_eq!(grade_of("mini_ku_1", "answer_mini_ku_1_new#0"), Some(1));
    assert_eq!(grade_of("mini_ku_1", "answer_mini_ku_1_old#1"), Some(1));
    assert_eq!(grade_of("mini_ku_1", "answer_mini_ku_1_old#0"), Some(1));
    let abstention = pack
        .queries
        .iter()
        .find(|query| query.query_id == "mini_ssu_2_abs")
        .unwrap();
    assert_eq!(abstention.category, ABSTENTION);
    assert!(abstention.qrels.is_empty());
    assert!(abstention.expect_empty);
}

#[test]
fn longmemeval_slice_file_holds_only_its_own_haystacks() {
    let (questions, dataset_sha256) = mini_questions();
    let meta = mini_meta(&dataset_sha256);
    let split = split_of(
        [Slice::Search, Slice::HeldOut, Slice::Sealed],
        &dataset_sha256,
    );
    let pack = convert(&questions, &split, Slice::Search, &meta, None).unwrap();
    assert_eq!(pack.queries.len(), 1);
    assert_eq!(pack.queries[0].query_id, "mini_ssu_1");
    assert_eq!(pack.corpora.len(), 1);
    assert_eq!(pack.corpora[0].corpus_id, "mini_ssu_1");
    for record in &pack.records {
        assert!(!record.source_ref.starts_with("answer_mini_ku_1"));
        assert!(!record.source_ref.starts_with("answer_mini_abs_1"));
        assert!(!record.source_ref.starts_with("filler_mini_3"));
    }
    let texts: Vec<&str> = pack
        .records
        .iter()
        .map(|record| record.text.as_str())
        .collect();
    let joined = texts.join("\n");
    assert!(!joined.contains("Sapporo"));
    assert!(!joined.contains("Osaka"));
    assert!(!joined.contains("dog"));
    assert!(!pack.queries[0].text.contains("dog"));

    let split_both = split_of(
        [Slice::Search, Slice::Search, Slice::Sealed],
        &dataset_sha256,
    );
    let pack_both = convert(&questions, &split_both, Slice::Search, &meta, None).unwrap();
    assert_eq!(pack_both.records.len(), 10);
    let shared = pack_both
        .records
        .iter()
        .filter(|record| record.source_ref.starts_with("shared_filler_1#"))
        .count();
    assert_eq!(shared, 2);
    for corpus_id in ["mini_ssu_1", "mini_ku_1"] {
        let corpus = pack_both
            .corpora
            .iter()
            .find(|corpus| corpus.corpus_id == corpus_id)
            .unwrap();
        let session = corpus
            .sessions
            .iter()
            .find(|session| session.session_id == "shared_filler_1")
            .unwrap();
        assert_eq!(session.record_ids.len(), 2);
        for id in &session.record_ids {
            let named = pack_both.records.iter().any(|record| {
                record.record_id == *id && record.source_ref.starts_with("shared_filler_1#")
            });
            assert!(named);
        }
    }
    let time_of = |corpus_id: &str| -> String {
        let corpus = pack_both
            .corpora
            .iter()
            .find(|corpus| corpus.corpus_id == corpus_id)
            .unwrap();
        corpus
            .sessions
            .iter()
            .find(|session| session.session_id == "shared_filler_1")
            .unwrap()
            .time
            .clone()
    };
    assert_eq!(time_of("mini_ssu_1"), "2023-01-05T09:00:00Z");
    assert_eq!(time_of("mini_ku_1"), "2023-03-01T08:15:00Z");
    assert!(
        pack_both
            .records
            .iter()
            .all(|record| !record.text.trim().is_empty())
    );
    assert!(
        pack_both
            .records
            .iter()
            .all(|record| record.source_ref != "shared_filler_1#1")
    );
}

#[test]
fn longmemeval_split_is_seeded_and_stratified() {
    let questions = fifty_questions();
    assert_eq!(questions.len(), 50);
    let counts = SliceCounts {
        search: 10,
        held_out: 30,
        sealed: 10,
    };
    let digest = "f".repeat(64);
    let first = draw_split(&questions, "LongMemEval-S", &digest, 42, counts).unwrap();
    let again = draw_split(&questions, "LongMemEval-S", &digest, 42, counts).unwrap();
    assert_eq!(first, again);
    let other = draw_split(&questions, "LongMemEval-S", &digest, 43, counts).unwrap();
    assert_ne!(first.entries, other.entries);
    for (slice, want) in [
        (Slice::Search, 10),
        (Slice::HeldOut, 30),
        (Slice::Sealed, 10),
    ] {
        let got = first
            .entries
            .iter()
            .filter(|entry| entry.slice == slice)
            .count();
        assert_eq!(got, want);
    }
    for category in CATEGORIES {
        for (slice, want) in [(Slice::Search, 2), (Slice::HeldOut, 6), (Slice::Sealed, 2)] {
            let got = first
                .entries
                .iter()
                .filter(|entry| entry.category == category && entry.slice == slice)
                .count();
            assert!(
                (got as i32 - want).abs() <= 1,
                "category {category} slice {slice}: got {got}"
            );
        }
    }
    let picks = first.first_of_each_category(Slice::Search, &CATEGORIES);
    assert_eq!(picks.len(), CATEGORIES.len());
    for (pick, category) in picks.iter().zip(CATEGORIES.iter()) {
        let entry = first
            .entries
            .iter()
            .find(|entry| entry.question_id == *pick)
            .unwrap();
        assert_eq!(entry.slice, Slice::Search);
        assert_eq!(entry.category.as_str(), *category);
    }
}

#[test]
fn longmemeval_time_converts() {
    assert_eq!(
        lme_time("2023/05/20 (Sat) 02:21").unwrap(),
        "2023-05-20T02:21:00Z"
    );
    assert!(lme_time("2023/13/01 (Mon) 00:00").is_err());
    assert!(lme_time("garbage").is_err());
}

#[test]
fn longmemeval_refuses_counts_that_do_not_sum() {
    let questions = fifty_questions();
    let digest = "f".repeat(64);
    let counts = SliceCounts {
        search: 10,
        held_out: 30,
        sealed: 9,
    };
    assert!(matches!(
        draw_split(&questions, "LongMemEval-S", &digest, 42, counts),
        Err(ConvertError::CountsMismatch { .. })
    ));
}

/// The mini fixture with `mini_ssu_1`'s haystack session at `position` named
/// once more, under a later date; `edit` changes the copy's first turn.
fn with_repeated_session(position: usize, edit: bool) -> (Vec<LmeQuestion>, String, String) {
    let (mut questions, dataset_sha256) = mini_questions();
    let question = questions
        .iter_mut()
        .find(|question| question.question_id == "mini_ssu_1")
        .expect("the mini fixture holds mini_ssu_1");
    let session_id = question.haystack_session_ids[position].clone();
    let mut copy = question.haystack_sessions[position].clone();
    if edit {
        copy[0].content.push_str(" (edited)");
    }
    question.haystack_session_ids.push(session_id.clone());
    question
        .haystack_dates
        .push("2023/06/01 (Thu) 09:00".to_owned());
    question.haystack_sessions.push(copy);
    (questions, dataset_sha256, session_id)
}

#[test]
fn longmemeval_skips_an_identical_repeated_distractor_session() {
    let (questions, dataset_sha256, session_id) = with_repeated_session(0, false);
    assert_eq!(session_id, "shared_filler_1");
    let split = split_of(
        [Slice::Search, Slice::HeldOut, Slice::Sealed],
        &dataset_sha256,
    );
    let meta = mini_meta(&dataset_sha256);
    let pack = convert(&questions, &split, Slice::Search, &meta, None).unwrap();
    let corpus = pack
        .corpora
        .iter()
        .find(|corpus| corpus.corpus_id == "mini_ssu_1")
        .unwrap();
    let sessions: Vec<&str> = corpus
        .sessions
        .iter()
        .map(|session| session.session_id.as_str())
        .collect();
    assert_eq!(sessions, ["shared_filler_1", "answer_mini_ssu_1"]);
    let question = questions
        .iter()
        .find(|question| question.question_id == "mini_ssu_1")
        .unwrap();
    let first_date = lme_time(&question.haystack_dates[0]).unwrap();
    assert_eq!(corpus.sessions[0].time, first_date);
}

#[test]
fn longmemeval_refuses_a_repeated_answer_session_or_a_changed_copy() {
    for (position, edit) in [(1, false), (0, true)] {
        let (questions, dataset_sha256, session_id) = with_repeated_session(position, edit);
        let split = split_of(
            [Slice::Search, Slice::HeldOut, Slice::Sealed],
            &dataset_sha256,
        );
        let meta = mini_meta(&dataset_sha256);
        let refused = convert(&questions, &split, Slice::Search, &meta, None);
        let Err(ConvertError::DuplicateSessionInHaystack {
            session_id: repeated,
            ..
        }) = &refused
        else {
            panic!(
                "position {position} edit {edit}: want DuplicateSessionInHaystack, got {:?}",
                refused.as_ref().err()
            );
        };
        assert_eq!(repeated, &session_id);
    }
}
