//! TREC passage collections become pack slices: three slices of passages by
//! article, fills, and malformed lines naming their line.

use oneiron_ruler::longmemeval::PackMeta;
use oneiron_ruler::pack::{PackSlice, RecordKind, Slice, load_slice, sha256_hex, write_slice};
use oneiron_ruler::trec_collection::*;

fn meta() -> PackMeta {
    PackMeta {
        pack_id: "trec-mini".to_owned(),
        revision: "1".to_owned(),
        dataset: "miracl+mr-tydi fixture".to_owned(),
        dataset_sha256: sha256_hex(b"trec-mini"),
        license: "Apache-2.0".to_owned(),
    }
}

fn make_split(
    slice: Slice,
    collection: &str,
    language: &str,
    name: &str,
    files: [&[u8]; 3],
) -> TrecSplit {
    let time = if collection == MIRACL {
        "2022-04-01T00:00:00Z"
    } else {
        "2020-07-01T00:00:00Z"
    };
    let topics = parse_topics(files[0]).expect("topics parse");
    let qrels = parse_qrels(files[1]).expect("qrels parse");
    let passages = parse_passages(files[2]).expect("passages parse");
    TrecSplit {
        slice,
        collection: collection.to_owned(),
        language: language.to_owned(),
        split: name.to_owned(),
        time: time.to_owned(),
        topics,
        qrels,
        passages,
    }
}

fn all_splits() -> Vec<TrecSplit> {
    let search = default_slice(MIRACL, "train").expect("miracl train is search");
    let held_out = default_slice(MIRACL, "dev").expect("miracl dev is held out");
    let sealed = default_slice(MR_TYDI, "test").expect("mr-tydi test is sealed");
    let ja_passages: &[u8] = include_bytes!("fixtures/trec/miracl-ja.passages.jsonl");
    let ja_train_topics: &[u8] = include_bytes!("fixtures/trec/miracl-ja-train.topics.tsv");
    let ja_train_qrels: &[u8] = include_bytes!("fixtures/trec/miracl-ja-train.qrels");
    let ja_dev_topics: &[u8] = include_bytes!("fixtures/trec/miracl-ja-dev.topics.tsv");
    let ja_dev_qrels: &[u8] = include_bytes!("fixtures/trec/miracl-ja-dev.qrels");
    let en_passages: &[u8] = include_bytes!("fixtures/trec/miracl-en.passages.jsonl");
    let en_train_topics: &[u8] = include_bytes!("fixtures/trec/miracl-en-train.topics.tsv");
    let en_train_qrels: &[u8] = include_bytes!("fixtures/trec/miracl-en-train.qrels");
    let en_dev_topics: &[u8] = include_bytes!("fixtures/trec/miracl-en-dev.topics.tsv");
    let en_dev_qrels: &[u8] = include_bytes!("fixtures/trec/miracl-en-dev.qrels");
    let tydi_passages: &[u8] = include_bytes!("fixtures/trec/mr-tydi-ja.passages.jsonl");
    let tydi_topics: &[u8] = include_bytes!("fixtures/trec/mr-tydi-ja-test.topics.tsv");
    let tydi_qrels: &[u8] = include_bytes!("fixtures/trec/mr-tydi-ja-test.qrels");
    vec![
        make_split(
            search,
            MIRACL,
            "ja",
            "train",
            [ja_train_topics, ja_train_qrels, ja_passages],
        ),
        make_split(
            held_out,
            MIRACL,
            "ja",
            "dev",
            [ja_dev_topics, ja_dev_qrels, ja_passages],
        ),
        make_split(
            search,
            MIRACL,
            "en",
            "train",
            [en_train_topics, en_train_qrels, en_passages],
        ),
        make_split(
            held_out,
            MIRACL,
            "en",
            "dev",
            [en_dev_topics, en_dev_qrels, en_passages],
        ),
        make_split(
            sealed,
            MR_TYDI,
            "ja",
            "test",
            [tydi_topics, tydi_qrels, tydi_passages],
        ),
    ]
}

fn corpus_source_refs(pack: &PackSlice, corpus_id: &str) -> Vec<String> {
    let corpus = pack
        .corpora
        .iter()
        .find(|corpus| corpus.corpus_id == corpus_id)
        .expect("the corpus exists");
    let mut refs: Vec<String> = Vec::new();
    for session in &corpus.sessions {
        for id in &session.record_ids {
            let record = pack
                .records
                .iter()
                .find(|record| record.record_id == *id)
                .expect("the record exists");
            refs.push(record.source_ref.clone());
        }
    }
    refs.sort();
    refs
}

fn fill_passages() -> Vec<TrecPassage> {
    let mut passages = Vec::new();
    for n in 0..20 {
        let docid = format!("600#{n}");
        let text = format!("passage {n}");
        passages.push(TrecPassage {
            docid,
            title: String::new(),
            text,
        });
    }
    passages
}

fn fill_split(passages: Vec<TrecPassage>) -> TrecSplit {
    TrecSplit {
        slice: Slice::Search,
        collection: MIRACL.to_owned(),
        language: "xx".to_owned(),
        split: "train".to_owned(),
        time: "2022-04-01T00:00:00Z".to_owned(),
        topics: vec![TrecTopic {
            query_id: "q1".to_owned(),
            text: "fill check".to_owned(),
        }],
        qrels: vec![
            TrecQrel {
                query_id: "q1".to_owned(),
                docid: "600#0".to_owned(),
                grade: 1,
            },
            TrecQrel {
                query_id: "q1".to_owned(),
                docid: "600#1".to_owned(),
                grade: 0,
            },
        ],
        passages,
    }
}

fn ja_train(all: &mut [TrecSplit]) -> &mut TrecSplit {
    all.iter_mut()
        .find(|split| {
            split.collection == MIRACL && split.language == "ja" && split.split == "train"
        })
        .expect("the ja train split exists")
}

#[test]
fn trec_collection_becomes_three_slices_of_passages_by_article() {
    assert_eq!(default_slice(MIRACL, "train"), Some(Slice::Search));
    assert_eq!(default_slice(MIRACL, "dev"), Some(Slice::HeldOut));
    assert_eq!(default_slice(MR_TYDI, "test"), Some(Slice::Sealed));
    assert_eq!(default_slice(MIRACL, "test"), None);

    let all = all_splits();
    let search = convert(&all, Slice::Search, &meta(), None).expect("search converts");
    let search_ids: Vec<&str> = search
        .pack
        .queries
        .iter()
        .map(|query| query.query_id.as_str())
        .collect();
    assert_eq!(
        search_ids,
        [
            "miracl-ja-train:q1",
            "miracl-ja-train:q2",
            "miracl-ja-train:q3",
            "miracl-en-train:q9",
        ]
    );
    assert_eq!(search.left_out, ["miracl-ja-train:q4"]);
    let corpora: Vec<&str> = search
        .pack
        .corpora
        .iter()
        .map(|corpus| corpus.corpus_id.as_str())
        .collect();
    assert_eq!(corpora, ["miracl-ja-train", "miracl-en-train"]);
    assert_eq!(search.pack.records.len(), 10);
    assert_eq!(
        corpus_source_refs(&search.pack, "miracl-ja-train"),
        [
            "100#0", "100#1", "100#2", "200#10", "200#2", "300#0", "300#1", "300#2",
        ]
    );
    let corpus = search
        .pack
        .corpora
        .iter()
        .find(|corpus| corpus.corpus_id == "miracl-ja-train")
        .expect("the ja train corpus exists");
    let sessions: Vec<&str> = corpus
        .sessions
        .iter()
        .map(|session| session.session_id.as_str())
        .collect();
    assert_eq!(sessions, ["100", "200", "300"]);
    let tea = corpus
        .sessions
        .iter()
        .find(|session| session.session_id == "200")
        .expect("the 200 session exists");
    let tea_ids: Vec<&str> = tea.record_ids.iter().map(String::as_str).collect();
    assert_eq!(tea_ids, ["miracl-ja-train:200#2", "miracl-ja-train:200#10"]);
    for id in ["miracl-ja-train:100#0", "miracl-en-train:100#0"] {
        let found = search
            .pack
            .records
            .iter()
            .any(|record| record.record_id == id);
        assert!(found, "record {id} exists");
    }
    for record in &search.pack.records {
        assert_eq!(record.kind, RecordKind::Passage);
        assert_eq!(record.speaker, PASSAGE_SPEAKER);
        let (_, docid) = record
            .record_id
            .split_once(':')
            .expect("the record id holds a docid");
        assert_eq!(record.source_ref, docid);
    }
    let beam = search
        .pack
        .records
        .iter()
        .find(|record| record.record_id == "miracl-ja-train:100#1")
        .expect("the beam record exists");
    assert_eq!(beam.text, "灯台 灯台の光は二十キロ先まで届く。");
    let ja = search
        .pack
        .queries
        .iter()
        .filter(|query| query.category == "miracl-ja")
        .count();
    let en = search
        .pack
        .queries
        .iter()
        .filter(|query| query.category == "miracl-en")
        .count();
    assert_eq!(ja, 3);
    assert_eq!(en, 1);
    let second = search
        .pack
        .queries
        .iter()
        .find(|query| query.query_id == "miracl-ja-train:q2")
        .expect("q2 exists");
    assert_eq!(second.qrels.len(), 2);
    assert_eq!(second.qrels.get("miracl-ja-train:200#2"), Some(&1));
    assert_eq!(second.qrels.get("miracl-ja-train:200#10"), Some(&1));
    for query in &search.pack.queries {
        assert_eq!(query.now, "2022-04-01T00:00:00Z");
    }

    let held = convert(&all, Slice::HeldOut, &meta(), None).expect("held out converts");
    let held_ids: Vec<&str> = held
        .pack
        .queries
        .iter()
        .map(|query| query.query_id.as_str())
        .collect();
    assert_eq!(
        held_ids,
        [
            "miracl-ja-dev:q5",
            "miracl-ja-dev:q6",
            "miracl-ja-dev:q7",
            "miracl-ja-dev:q8",
            "miracl-en-dev:q10",
        ]
    );
    for id in &held_ids {
        let is_ja = id.starts_with("miracl-ja-dev:");
        let is_en = id.starts_with("miracl-en-dev:");
        assert!(is_ja || is_en, "id {id} has a dev prefix");
    }
    assert_eq!(held.pack.records.len(), 8);
    assert_eq!(
        corpus_source_refs(&held.pack, "miracl-ja-dev"),
        ["100#0", "100#2", "200#1", "200#10", "300#0", "300#1"]
    );
    assert!(held.left_out.is_empty());

    let fill = Some(Fill {
        seed: 7,
        per_corpus: 1,
    });
    let sealed = convert(&all, Slice::Sealed, &meta(), fill).expect("sealed converts");
    let sealed_ids: Vec<&str> = sealed
        .pack
        .queries
        .iter()
        .map(|query| query.query_id.as_str())
        .collect();
    assert_eq!(
        sealed_ids,
        [
            "mr-tydi-ja-test:t1",
            "mr-tydi-ja-test:t2",
            "mr-tydi-ja-test:t3",
        ]
    );
    for query in &sealed.pack.queries {
        assert_eq!(query.category, "mr-tydi-ja");
    }
    assert_eq!(sealed.pack.records.len(), 5);
    assert_eq!(
        corpus_source_refs(&sealed.pack, "mr-tydi-ja-test"),
        ["400#0", "400#1", "500#0", "500#1", "500#2"]
    );
    assert!(sealed.left_out.is_empty());

    let digest = split_digest(&all).expect("the digest computes");
    assert_eq!(search.pack.source.split_sha256, digest);
    assert_eq!(held.pack.source.split_sha256, digest);
    assert_eq!(sealed.pack.source.split_sha256, digest);
    search.pack.validate().expect("search validates");
    held.pack.validate().expect("held out validates");
    sealed.pack.validate().expect("sealed validates");

    for pack in [&search.pack, &held.pack, &sealed.pack] {
        let dir = tempfile::tempdir().expect("a temp dir");
        let written = write_slice(dir.path(), pack, None).expect("the slice writes");
        let loaded = load_slice(dir.path(), pack.slice).expect("the slice loads");
        assert_eq!(loaded.slice, *pack);
        assert_eq!(loaded.pack_digest, written);
        let fresh = pack.pack_digest().expect("the digest computes");
        assert_eq!(loaded.pack_digest, fresh);
    }
}

#[test]
fn a_split_without_judged_negatives_needs_a_fill() {
    let all = all_splits();
    let result = convert(&all, Slice::Sealed, &meta(), None);
    let Err(TrecError::NoJudgedNegatives { corpus_id }) = result else {
        panic!("sealed without a fill must report no judged negatives");
    };
    assert_eq!(corpus_id, "mr-tydi-ja-test");
}

#[test]
fn the_same_seed_gives_the_same_pack_digest() {
    let fill = Some(Fill {
        seed: 7,
        per_corpus: 5,
    });
    let splits = [fill_split(fill_passages())];
    let first = convert(&splits, Slice::Search, &meta(), fill).expect("the fill converts");
    let again = convert(&splits, Slice::Search, &meta(), fill).expect("the fill converts again");
    assert_eq!(
        first.pack.pack_digest().expect("the digest computes"),
        again.pack.pack_digest().expect("the digest computes")
    );
    assert_eq!(first.pack.records.len(), 7);
    for id in ["miracl-xx-train:600#0", "miracl-xx-train:600#1"] {
        let found = first
            .pack
            .records
            .iter()
            .any(|record| record.record_id == id);
        assert!(found, "record {id} exists");
    }

    let mut reversed = fill_passages();
    reversed.reverse();
    let flipped = [fill_split(reversed)];
    let third =
        convert(&flipped, Slice::Search, &meta(), fill).expect("the reversed fill converts");
    assert_eq!(
        third.pack.pack_digest().expect("the digest computes"),
        first.pack.pack_digest().expect("the digest computes")
    );

    let reseed = Some(Fill {
        seed: 8,
        per_corpus: 5,
    });
    let other = convert(&flipped, Slice::Search, &meta(), reseed).expect("the reseed converts");
    assert_ne!(
        other.pack.pack_digest().expect("the digest computes"),
        first.pack.pack_digest().expect("the digest computes")
    );
    assert_eq!(other.pack.records.len(), 7);
    for id in ["miracl-xx-train:600#0", "miracl-xx-train:600#1"] {
        let found = other
            .pack
            .records
            .iter()
            .any(|record| record.record_id == id);
        assert!(found, "record {id} exists");
    }
}

#[test]
fn a_qrel_naming_a_passage_outside_the_collection_is_refused() {
    let mut all = all_splits();
    ja_train(&mut all).qrels.push(TrecQrel {
        query_id: "q1".to_owned(),
        docid: "999#0".to_owned(),
        grade: 1,
    });
    let result = convert(&all, Slice::Search, &meta(), None);
    let Err(TrecError::UnknownPassage {
        corpus_id,
        query_id,
        docid,
    }) = result
    else {
        panic!("a qrel outside the collection must fail");
    };
    assert_eq!(corpus_id, "miracl-ja-train");
    assert_eq!(query_id, "q1");
    assert_eq!(docid, "999#0");
}

#[test]
fn malformed_trec_lines_name_their_line() {
    assert!(matches!(
        parse_qrels(b"q1 0 100#0 1\nq1 0 100#1\n"),
        Err(TrecError::BadQrelLine { line: 2 })
    ));
    assert!(matches!(
        parse_qrels(b"q1 0 100#0 4\n"),
        Err(TrecError::BadQrelLine { line: 1 })
    ));
    assert!(matches!(
        parse_topics(b"q1\tok\nq2\n"),
        Err(TrecError::BadTopicLine { line: 2 })
    ));
    assert!(matches!(
        parse_passages(b"{\"docid\": \"1#0\", \"text\": \"a\"}\nnot json\n"),
        Err(TrecError::BadPassageLine { line: 2, .. })
    ));
    let mut all = all_splits();
    ja_train(&mut all).passages.push(TrecPassage {
        docid: "7".to_owned(),
        title: String::new(),
        text: "nowhere".to_owned(),
    });
    assert!(matches!(
        convert(&all, Slice::Search, &meta(), None),
        Err(TrecError::BadDocid { .. })
    ));
}
