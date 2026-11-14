//! TREC-shaped passage collections (MIRACL, Mr.TyDi) in, one pack slice out.
//!
//! A record is one passage, a session is one article (its passages in `#n`
//! order), a corpus is one split's judged pool (every passage a kept query of
//! that split judged, relevant or not), plus an optional seeded fill of
//! unjudged passages. Pure: no IO, no clock, no network.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

use crate::longmemeval::PackMeta;
use crate::pack::{
    Corpus, CorpusSession, PACK_CONTRACT, PackError, PackSlice, PackSource, Query, Record,
    RecordKind, Slice, sha256_hex,
};

/// The MIRACL collection name.
pub const MIRACL: &str = "miracl";
/// The Mr.TyDi collection name.
pub const MR_TYDI: &str = "mr-tydi";
/// The speaker of every passage record.
pub const PASSAGE_SPEAKER: &str = "document";

/// One TREC topic: a query id and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrecTopic {
    /// The query id. Unique in the split.
    pub query_id: String,
    /// The query text.
    pub text: String,
}

/// One TREC qrel line: grade 0 is judged non-relevant, 1..=3 relevant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrecQrel {
    /// The query id. Names a topic of the split.
    pub query_id: String,
    /// The judged passage. `<article>#<n>`.
    pub docid: String,
    /// The judgement: 0 is judged non-relevant, 1..=3 relevant.
    pub grade: u8,
}

/// One collection passage. `docid` is `<article>#<n>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrecPassage {
    /// The passage id. `<article>#<n>`.
    pub docid: String,
    /// The article title. May be empty.
    pub title: String,
    /// The passage text.
    pub text: String,
}

/// One split of one language of one collection, and the slice it goes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrecSplit {
    /// The slice this split converts into.
    pub slice: Slice,
    /// The collection name, e.g. `miracl`.
    pub collection: String,
    /// The language code, e.g. `ja`.
    pub language: String,
    /// The split name, e.g. `train`.
    pub split: String,
    /// The collection's dump date, `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: String,
    /// The split's topics.
    pub topics: Vec<TrecTopic>,
    /// The split's judgements.
    pub qrels: Vec<TrecQrel>,
    /// The judged pool, or any superset (the fill draws from the rest).
    pub passages: Vec<TrecPassage>,
}

/// A seeded fill: up to `per_corpus` unjudged passages added to every corpus of the slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fill {
    /// The seed keying the fill order.
    pub seed: u64,
    /// How many unjudged passages each corpus takes at most.
    pub per_corpus: usize,
}

/// A converted slice and the query ids left out of it (no relevant passage judged).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrecConversion {
    /// The converted slice.
    pub pack: PackSlice,
    /// `<corpus_id>:<qid>` of every topic with no relevant passage judged.
    pub left_out: Vec<String>,
}

/// Every way a TREC collection read or conversion can fail.
#[derive(Debug, Error)]
pub enum TrecError {
    /// A topic line is not `<qid>` TAB `<text>` with both sides non-blank.
    #[error("bad topic line {line}")]
    BadTopicLine {
        /// The 1-based line number.
        line: usize,
    },
    /// A qrel line is not `<qid> <iteration> <docid> <grade>` with grade 0..=3.
    #[error("bad qrel line {line}")]
    BadQrelLine {
        /// The 1-based line number.
        line: usize,
    },
    /// A passage line is not a JSON object with `docid` and `text`.
    #[error("bad passage line {line}: {message}")]
    BadPassageLine {
        /// The 1-based line number.
        line: usize,
        /// What the JSON read said.
        message: String,
    },
    /// A collection, language or split name breaks `^[a-z][a-z0-9-]*$`.
    #[error("bad name for {field}: {value}")]
    BadName {
        /// Which name broke the rule.
        field: &'static str,
        /// The bad value.
        value: String,
    },
    /// Two splits share a corpus id.
    #[error("duplicate split: {corpus_id}")]
    DuplicateSplit {
        /// The repeated id.
        corpus_id: String,
    },
    /// Two topics of one split share a query id.
    #[error("duplicate topic {query_id} in {corpus_id}")]
    DuplicateTopic {
        /// The split.
        corpus_id: String,
        /// The repeated id.
        query_id: String,
    },
    /// One query judges one passage twice.
    #[error("duplicate qrel {query_id} {docid} in {corpus_id}")]
    DuplicateQrel {
        /// The split.
        corpus_id: String,
        /// The query.
        query_id: String,
        /// The twice-judged passage.
        docid: String,
    },
    /// A qrel names a query the split has no topic for.
    #[error("qrel for unknown topic {query_id} in {corpus_id}")]
    QrelForUnknownTopic {
        /// The split.
        corpus_id: String,
        /// The missing query.
        query_id: String,
    },
    /// A docid is not `<article>#<n>` with a numeric `n`.
    #[error("bad docid {docid} in {corpus_id}")]
    BadDocid {
        /// The split.
        corpus_id: String,
        /// The bad docid.
        docid: String,
    },
    /// One docid carries two different texts.
    #[error("conflicting passage {docid} in {corpus_id}")]
    ConflictingPassage {
        /// The split.
        corpus_id: String,
        /// The contested docid.
        docid: String,
    },
    /// A kept query judges a passage the collection does not hold.
    #[error("query {query_id} in {corpus_id} names unknown passage {docid}")]
    UnknownPassage {
        /// The split.
        corpus_id: String,
        /// The query.
        query_id: String,
        /// The missing passage.
        docid: String,
    },
    /// A split's kept queries judged no passage non-relevant.
    #[error("no judged negatives in {corpus_id}")]
    NoJudgedNegatives {
        /// The split.
        corpus_id: String,
    },
    /// The slice keeps no query.
    #[error("empty slice: {slice}")]
    EmptySlice {
        /// The empty slice.
        slice: Slice,
    },
    /// The converted slice fails pack validation.
    #[error(transparent)]
    Pack(#[from] PackError),
    /// A value has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
}

/// Parse TREC topics: `<qid>` TAB `<text>` per line. Blank lines are skipped;
/// the qid is the text before the first tab, both sides trimmed and non-empty.
pub fn parse_topics(bytes: &[u8]) -> Result<Vec<TrecTopic>, TrecError> {
    let mut topics = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_no = index + 1;
        let Ok(text) = str::from_utf8(line) else {
            return Err(TrecError::BadTopicLine { line: line_no });
        };
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text.trim().is_empty() {
            continue;
        }
        let Some((qid, topic_text)) = text.split_once('\t') else {
            return Err(TrecError::BadTopicLine { line: line_no });
        };
        let qid = qid.trim();
        let topic_text = topic_text.trim();
        if qid.is_empty() || topic_text.is_empty() {
            return Err(TrecError::BadTopicLine { line: line_no });
        }
        topics.push(TrecTopic {
            query_id: qid.to_owned(),
            text: topic_text.to_owned(),
        });
    }
    Ok(topics)
}

/// Parse TREC qrels: `<qid> <iteration> <docid> <grade>` per line over ASCII
/// whitespace, so tabs and spaces both work. The grade is 0..=3.
pub fn parse_qrels(bytes: &[u8]) -> Result<Vec<TrecQrel>, TrecError> {
    let mut qrels = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_no = index + 1;
        let Ok(text) = str::from_utf8(line) else {
            return Err(TrecError::BadQrelLine { line: line_no });
        };
        if text.trim().is_empty() {
            continue;
        }
        let mut parts = text.split_ascii_whitespace();
        let fields = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        );
        let (Some(qid), Some(_iteration), Some(docid), Some(grade_text), None) = fields else {
            return Err(TrecError::BadQrelLine { line: line_no });
        };
        let grade: u8 = match grade_text.parse() {
            Ok(grade) if grade <= 3 => grade,
            _ => {
                return Err(TrecError::BadQrelLine { line: line_no });
            }
        };
        qrels.push(TrecQrel {
            query_id: qid.to_owned(),
            docid: docid.to_owned(),
            grade,
        });
    }
    Ok(qrels)
}

/// Parse collection passages: JSON lines, each an object with `docid` and
/// `text` plus an optional `title`. Unknown keys are accepted.
pub fn parse_passages(bytes: &[u8]) -> Result<Vec<TrecPassage>, TrecError> {
    let mut passages = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_no = index + 1;
        let text = match str::from_utf8(line) {
            Ok(text) => text,
            Err(error) => {
                let message = error.to_string();
                return Err(TrecError::BadPassageLine {
                    line: line_no,
                    message,
                });
            }
        };
        if text.trim().is_empty() {
            continue;
        }
        let parsed: PassageLine = match serde_json::from_str(text) {
            Ok(parsed) => parsed,
            Err(error) => {
                let message = error.to_string();
                return Err(TrecError::BadPassageLine {
                    line: line_no,
                    message,
                });
            }
        };
        passages.push(TrecPassage {
            docid: parsed.docid,
            title: parsed.title,
            text: parsed.text,
        });
    }
    Ok(passages)
}

/// The slice a split converts into: tune on MIRACL train, judge on MIRACL dev
/// (the split Pyserini's published MIRACL baselines use), seal on a second
/// collection. Anything else has no slice.
pub fn default_slice(collection: &str, split: &str) -> Option<Slice> {
    match (collection, split) {
        (MIRACL, "train") => Some(Slice::Search),
        (MIRACL, "dev") => Some(Slice::HeldOut),
        (MR_TYDI, "test") => Some(Slice::Sealed),
        _ => None,
    }
}

/// The corpus id of a split: `<collection>-<language>-<split>`.
pub fn corpus_id(split: &TrecSplit) -> String {
    let collection = split.collection.as_str();
    let language = split.language.as_str();
    let name = split.split.as_str();
    format!("{collection}-{language}-{name}")
}

/// The split digest: sha256 (lowercase hex) of the RFC 8785 canonical bytes
/// of a JSON array with one object per split, sorted by corpus id. All given
/// splits count, whatever their slice, so the three slice files of one
/// conversion carry the same digest.
pub fn split_digest(splits: &[TrecSplit]) -> Result<String, TrecError> {
    let mut entries: Vec<(String, serde_json::Value)> = Vec::with_capacity(splits.len());
    for split in splits {
        let id = corpus_id(split);
        let mut qids: Vec<&str> = Vec::with_capacity(split.topics.len());
        for topic in &split.topics {
            qids.push(topic.query_id.as_str());
        }
        qids.sort();
        let name = split.slice.as_str();
        let entry = serde_json::json!({
            "corpus_id": id.as_str(),
            "slice": name,
            "query_ids": qids,
        });
        entries.push((id, entry));
    }
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    let values: Vec<serde_json::Value> = entries.into_iter().map(|(_, entry)| entry).collect();
    let array = serde_json::Value::Array(values);
    let canonical = serde_json_canonicalizer::to_vec(&array)
        .map_err(|error| TrecError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

/// Convert the splits assigned to `slice` into a pack slice. Every split is
/// name-checked first, whatever its slice; splits of other slices only feed
/// the shared split digest. A topic is kept when some qrel grades it relevant;
/// the rest are reported in `left_out` and judge nothing.
pub fn convert(
    splits: &[TrecSplit],
    slice: Slice,
    meta: &PackMeta,
    fill: Option<Fill>,
) -> Result<TrecConversion, TrecError> {
    check_split_names(splits)?;
    let digest = split_digest(splits)?;
    let mut records: Vec<Record> = Vec::new();
    let mut corpora: Vec<Corpus> = Vec::new();
    let mut queries: Vec<Query> = Vec::new();
    let mut left_out: Vec<String> = Vec::new();
    for split in splits {
        if split.slice != slice {
            continue;
        }
        let id = corpus_id(split);
        let converted = convert_split(split, slice, &id, fill, &mut left_out)?;
        if let Some((corpus, mut split_records, mut split_queries)) = converted {
            records.append(&mut split_records);
            corpora.push(corpus);
            queries.append(&mut split_queries);
        }
    }
    if queries.is_empty() {
        return Err(TrecError::EmptySlice { slice });
    }
    let pack = PackSlice {
        contract: PACK_CONTRACT.to_owned(),
        pack_id: meta.pack_id.clone(),
        revision: meta.revision.clone(),
        slice,
        source: PackSource {
            dataset: meta.dataset.clone(),
            dataset_sha256: meta.dataset_sha256.clone(),
            license: meta.license.clone(),
            split_sha256: digest,
        },
        embedding: None,
        records,
        corpora,
        queries,
    };
    pack.validate()?;
    Ok(TrecConversion { pack, left_out })
}

/// One JSON passage line. Unknown keys are accepted.
#[derive(Deserialize)]
struct PassageLine {
    docid: String,
    #[serde(default)]
    title: String,
    text: String,
}

/// True for `^[a-z][a-z0-9-]*$`: a lowercase letter, then letters, digits
/// and dashes.
fn is_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for byte in bytes {
        let ok = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
        if !ok {
            return false;
        }
    }
    true
}

/// Check every split's names and corpus ids before anything else.
fn check_split_names(splits: &[TrecSplit]) -> Result<(), TrecError> {
    let mut known: BTreeSet<String> = BTreeSet::new();
    for split in splits {
        let fields: [(&'static str, &str); 3] = [
            ("collection", split.collection.as_str()),
            ("language", split.language.as_str()),
            ("split", split.split.as_str()),
        ];
        for (field, value) in fields {
            if !is_name(value) {
                return Err(TrecError::BadName {
                    field,
                    value: value.to_owned(),
                });
            }
        }
        let id = corpus_id(split);
        if !known.insert(id.clone()) {
            return Err(TrecError::DuplicateSplit { corpus_id: id });
        }
    }
    Ok(())
}

/// Check a split's topics and qrels: qids are unique, every qrel names a
/// topic, and no (qid, docid) pair is judged twice.
fn check_topics_qrels(split: &TrecSplit, corpus_id: &str) -> Result<(), TrecError> {
    let mut topics: BTreeSet<&str> = BTreeSet::new();
    for topic in &split.topics {
        let qid = topic.query_id.as_str();
        if !topics.insert(qid) {
            return Err(TrecError::DuplicateTopic {
                corpus_id: corpus_id.to_owned(),
                query_id: topic.query_id.clone(),
            });
        }
    }
    let mut pairs: BTreeSet<(&str, &str)> = BTreeSet::new();
    for qrel in &split.qrels {
        let qid = qrel.query_id.as_str();
        if !topics.contains(qid) {
            return Err(TrecError::QrelForUnknownTopic {
                corpus_id: corpus_id.to_owned(),
                query_id: qrel.query_id.clone(),
            });
        }
        let docid = qrel.docid.as_str();
        if !pairs.insert((qid, docid)) {
            return Err(TrecError::DuplicateQrel {
                corpus_id: corpus_id.to_owned(),
                query_id: qrel.query_id.clone(),
                docid: qrel.docid.clone(),
            });
        }
    }
    Ok(())
}

/// Split a docid at the last `#` into its article and passage number.
fn split_docid(docid: &str) -> Option<(&str, u32)> {
    let (article, num) = docid.rsplit_once('#')?;
    if article.is_empty() {
        return None;
    }
    let n: u32 = num.parse().ok()?;
    Some((article, n))
}

/// Index a split's passages by docid. Repeating a docid is fine when the
/// title and text agree; every qrel docid must parse as well.
fn index_passages<'a>(
    split: &'a TrecSplit,
    corpus_id: &str,
) -> Result<BTreeMap<&'a str, &'a TrecPassage>, TrecError> {
    let mut passages: BTreeMap<&'a str, &'a TrecPassage> = BTreeMap::new();
    for passage in &split.passages {
        let docid = passage.docid.as_str();
        if split_docid(docid).is_none() {
            return Err(TrecError::BadDocid {
                corpus_id: corpus_id.to_owned(),
                docid: passage.docid.clone(),
            });
        }
        if let Some(seen) = passages.get(docid) {
            if seen.title != passage.title || seen.text != passage.text {
                return Err(TrecError::ConflictingPassage {
                    corpus_id: corpus_id.to_owned(),
                    docid: passage.docid.clone(),
                });
            }
        } else {
            passages.insert(docid, passage);
        }
    }
    for qrel in &split.qrels {
        let docid = qrel.docid.as_str();
        if split_docid(docid).is_none() {
            return Err(TrecError::BadDocid {
                corpus_id: corpus_id.to_owned(),
                docid: qrel.docid.clone(),
            });
        }
    }
    Ok(passages)
}

/// The text a passage record embeds: title and text joined by one space when
/// the title is non-blank, else the text alone. Both sides trimmed.
fn record_text(passage: &TrecPassage) -> String {
    let title = passage.title.trim();
    let text = passage.text.trim();
    if title.is_empty() {
        text.to_owned()
    } else {
        format!("{title} {text}")
    }
}

/// The fill rank of a passage: lower sorts first.
fn fill_rank(seed: u64, docid: &str) -> String {
    let keyed = format!("{seed}:{docid}");
    sha256_hex(keyed.as_bytes())
}

/// Convert one split: its corpus, its records in session order, and its
/// queries. Splits with no kept topic add nothing.
fn convert_split(
    split: &TrecSplit,
    slice: Slice,
    corpus_id: &str,
    fill: Option<Fill>,
    left_out: &mut Vec<String>,
) -> Result<Option<(Corpus, Vec<Record>, Vec<Query>)>, TrecError> {
    check_topics_qrels(split, corpus_id)?;
    let passages = index_passages(split, corpus_id)?;
    let mut kept: BTreeSet<&str> = BTreeSet::new();
    for qrel in &split.qrels {
        if qrel.grade >= 1 {
            kept.insert(qrel.query_id.as_str());
        }
    }
    for topic in &split.topics {
        let qid = topic.query_id.as_str();
        if kept.contains(qid) {
            continue;
        }
        left_out.push(format!("{corpus_id}:{qid}"));
    }
    if kept.is_empty() {
        return Ok(None);
    }
    let mut by_topic: BTreeMap<&str, Vec<&TrecQrel>> = BTreeMap::new();
    for qrel in &split.qrels {
        by_topic
            .entry(qrel.query_id.as_str())
            .or_default()
            .push(qrel);
    }
    let mut first_judge: BTreeMap<&str, &str> = BTreeMap::new();
    for topic in &split.topics {
        let qid = topic.query_id.as_str();
        if !kept.contains(qid) {
            continue;
        }
        if let Some(qrels) = by_topic.get(qid) {
            for &qrel in qrels {
                first_judge.entry(qrel.docid.as_str()).or_insert(qid);
            }
        }
    }
    for (&docid, &qid) in &first_judge {
        if !passages.contains_key(docid) {
            return Err(TrecError::UnknownPassage {
                corpus_id: corpus_id.to_owned(),
                query_id: qid.to_owned(),
                docid: docid.to_owned(),
            });
        }
    }
    let mut pool: BTreeSet<&str> = first_judge.keys().copied().collect();
    match fill {
        None => {
            let has_negative = split
                .qrels
                .iter()
                .any(|qrel| qrel.grade == 0 && kept.contains(qrel.query_id.as_str()));
            if !has_negative {
                return Err(TrecError::NoJudgedNegatives {
                    corpus_id: corpus_id.to_owned(),
                });
            }
        }
        Some(fill) => {
            let mut candidates: Vec<(String, &str)> = Vec::new();
            for (&docid, &passage) in &passages {
                if pool.contains(docid) {
                    continue;
                }
                if record_text(passage).trim().is_empty() {
                    continue;
                }
                candidates.push((fill_rank(fill.seed, docid), docid));
            }
            candidates.sort_unstable();
            for (_, docid) in candidates.into_iter().take(fill.per_corpus) {
                pool.insert(docid);
            }
        }
    }
    let mut articles: BTreeMap<&str, Vec<(&str, u32, &TrecPassage)>> = BTreeMap::new();
    for (&docid, &passage) in &passages {
        if !pool.contains(docid) {
            continue;
        }
        let Some((article, num)) = split_docid(docid) else {
            return Err(TrecError::BadDocid {
                corpus_id: corpus_id.to_owned(),
                docid: docid.to_owned(),
            });
        };
        articles
            .entry(article)
            .or_default()
            .push((docid, num, passage));
    }
    let mut split_records: Vec<Record> = Vec::new();
    let mut sessions: Vec<CorpusSession> = Vec::new();
    for (article, mut members) in articles {
        members.sort_by_key(|member| member.1);
        let mut record_ids: Vec<String> = Vec::with_capacity(members.len());
        for (docid, _, passage) in members {
            let record_id = format!("{corpus_id}:{docid}");
            record_ids.push(record_id.clone());
            split_records.push(Record {
                record_id,
                kind: RecordKind::Passage,
                speaker: PASSAGE_SPEAKER.to_owned(),
                text: record_text(passage),
                source_ref: docid.to_owned(),
            });
        }
        sessions.push(CorpusSession {
            session_id: article.to_owned(),
            time: split.time.clone(),
            record_ids,
        });
    }
    let collection = split.collection.as_str();
    let language = split.language.as_str();
    let category = format!("{collection}-{language}");
    let mut split_queries: Vec<Query> = Vec::new();
    for topic in &split.topics {
        let qid = topic.query_id.as_str();
        if !kept.contains(qid) {
            continue;
        }
        let mut qrels: BTreeMap<String, u8> = BTreeMap::new();
        if let Some(qrels_of) = by_topic.get(qid) {
            for &qrel in qrels_of {
                if qrel.grade >= 1 {
                    let docid = qrel.docid.as_str();
                    let record_id = format!("{corpus_id}:{docid}");
                    qrels.insert(record_id, qrel.grade);
                }
            }
        }
        split_queries.push(Query {
            query_id: format!("{corpus_id}:{qid}"),
            slice,
            corpus_id: corpus_id.to_owned(),
            category: category.clone(),
            text: topic.text.clone(),
            now: split.time.clone(),
            qrels,
            expect_empty: false,
        });
    }
    let corpus = Corpus {
        corpus_id: corpus_id.to_owned(),
        sessions,
    };
    Ok(Some((corpus, split_records, split_queries)))
}
