//! The LongMemEval-S converter: public questions in, one pack slice out.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pack::{
    Corpus, CorpusSession, PACK_CONTRACT, PackError, PackSlice, PackSource, Query, Record,
    RecordKind, Slice, sha256_hex,
};

/// The contract string every split file carries.
pub const SPLIT_CONTRACT: &str = "oneiron.retrieval_split.v1";

/// The category of abstention questions: the right answer is no result.
pub const ABSTENTION: &str = "abstention";

/// The category whose stale answers must lose to the latest answer.
const KNOWLEDGE_UPDATE: &str = "knowledge-update";

/// One LongMemEval-S question. Upstream rows carry more keys (like `answer`),
/// so unknown keys are accepted.
#[derive(Clone, Debug, Deserialize)]
pub struct LmeQuestion {
    /// The question id. Unique in the dataset.
    pub question_id: String,
    /// The upstream question type, e.g. `single-session-user`.
    pub question_type: String,
    /// The question text.
    pub question: String,
    /// `2023/05/20 (Sat) 02:21`: the date the question was asked.
    pub question_date: String,
    /// One id per haystack session.
    pub haystack_session_ids: Vec<String>,
    /// One date per haystack session, same format as `question_date`.
    pub haystack_dates: Vec<String>,
    /// One turn list per haystack session.
    pub haystack_sessions: Vec<Vec<LmeTurn>>,
    /// The haystack sessions that answer the question.
    pub answer_session_ids: Vec<String>,
}

/// One turn of a LongMemEval-S haystack session.
#[derive(Clone, Debug, Deserialize)]
pub struct LmeTurn {
    /// `user` or `assistant`.
    pub role: String,
    /// The turn text. Blank turns are skipped by the converter.
    pub content: String,
    /// True when the turn carries the answer.
    #[serde(default)]
    pub has_answer: bool,
}

/// A seeded assignment of every question to a slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Split {
    /// Must equal [`SPLIT_CONTRACT`].
    pub contract: String,
    /// The dataset that was split.
    pub dataset: String,
    /// 64 lowercase hex: sha256 of the dataset file.
    pub dataset_sha256: String,
    /// One entry per question, in deal order.
    pub entries: Vec<SplitEntry>,
}

/// One question's place in a split.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitEntry {
    /// The question id.
    pub question_id: String,
    /// The category the question was dealt under.
    pub category: String,
    /// The slice the question belongs to.
    pub slice: Slice,
}

/// How many questions each slice takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliceCounts {
    /// Questions for [`Slice::Search`].
    pub search: usize,
    /// Questions for [`Slice::HeldOut`].
    pub held_out: usize,
    /// Questions for [`Slice::Sealed`].
    pub sealed: usize,
}

/// The manifest header a conversion writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackMeta {
    /// The pack id.
    pub pack_id: String,
    /// The pack revision.
    pub revision: String,
    /// The source dataset.
    pub dataset: String,
    /// 64 lowercase hex: sha256 of the dataset file.
    pub dataset_sha256: String,
    /// The dataset license.
    pub license: String,
}

/// Every way a LongMemEval-S read, split or conversion can fail.
#[derive(Debug, Error)]
pub enum ConvertError {
    /// The three haystack vectors of a question have unequal lengths.
    #[error("mismatched haystack for question {question_id}")]
    MismatchedHaystack {
        /// The question.
        question_id: String,
    },
    /// Two questions share an id.
    #[error("duplicate question: {question_id}")]
    DuplicateQuestion {
        /// The repeated id.
        question_id: String,
    },
    /// The slice counts do not add up to the question count.
    #[error("slice counts mismatch: expected {expected}, found {found}")]
    CountsMismatch {
        /// The wanted count.
        expected: usize,
        /// The count at hand.
        found: usize,
    },
    /// A LongMemEval date is malformed or out of range.
    #[error("bad time: {value}")]
    BadTime {
        /// The bad value.
        value: String,
    },
    /// A requested question is not in the converted slice.
    #[error("question not in slice: {question_id}")]
    QuestionNotInSlice {
        /// The question.
        question_id: String,
    },
    /// The split names a question the dataset does not hold.
    #[error("unknown question: {question_id}")]
    UnknownQuestion {
        /// The missing question.
        question_id: String,
    },
    /// The split entry and the question disagree on the category.
    #[error("split category mismatch for {question_id}: expected {expected}, found {found}")]
    SplitCategoryMismatch {
        /// The question.
        question_id: String,
        /// The category the split entry claims.
        expected: String,
        /// The category the question has.
        found: String,
    },
    /// The split was drawn from another dataset file.
    #[error("split is for another dataset: expected {expected}, found {found}")]
    SplitOfAnotherDataset {
        /// The dataset the conversion targets.
        expected: String,
        /// The dataset the split names.
        found: String,
    },
    /// One haystack names a session twice.
    #[error("duplicate session {session_id} in haystack of {question_id}")]
    DuplicateSessionInHaystack {
        /// The question.
        question_id: String,
        /// The repeated session.
        session_id: String,
    },
    /// An answer session id is missing from the haystack.
    #[error("question {question_id} misses answer session {session_id}")]
    MissingAnswerSession {
        /// The question.
        question_id: String,
        /// The missing session.
        session_id: String,
    },
    /// A non-abstention question grades nothing.
    #[error("question {question_id} has no evidence")]
    NoEvidence {
        /// The question.
        question_id: String,
    },
    /// The dataset is not valid JSON for this shape.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The converted slice fails pack validation.
    #[error(transparent)]
    Pack(#[from] PackError),
    /// A value has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
}

/// Parse a LongMemEval-S dataset file: a JSON array of questions.
pub fn parse_dataset(bytes: &[u8]) -> Result<Vec<LmeQuestion>, ConvertError> {
    let questions: Vec<LmeQuestion> = serde_json::from_slice(bytes)?;
    let mut known = BTreeSet::new();
    for question in &questions {
        if !known.insert(question.question_id.as_str()) {
            return Err(ConvertError::DuplicateQuestion {
                question_id: question.question_id.clone(),
            });
        }
        if question.haystack_session_ids.len() != question.haystack_sessions.len()
            || question.haystack_dates.len() != question.haystack_sessions.len()
        {
            return Err(ConvertError::MismatchedHaystack {
                question_id: question.question_id.clone(),
            });
        }
    }
    Ok(questions)
}

/// The split category of a question: [`ABSTENTION`] when the question id ends
/// with `_abs`, else the upstream question type.
pub fn category(question: &LmeQuestion) -> String {
    if question.question_id.ends_with("_abs") {
        ABSTENTION.to_owned()
    } else {
        question.question_type.clone()
    }
}

/// Convert LongMemEval time text (`2023/05/20 (Sat) 02:21`) to pack time
/// (`2023-05-20T02:21:00Z`). The date is the first token, the clock is the
/// last token; the weekday in between is ignored.
pub fn lme_time(value: &str) -> Result<String, ConvertError> {
    let bad = || ConvertError::BadTime {
        value: value.to_owned(),
    };
    let mut tokens = value.split_whitespace();
    let Some(date) = tokens.next() else {
        return Err(bad());
    };
    let clock = tokens.last().unwrap_or(date);
    let date_bytes = date.as_bytes();
    let clock_bytes = clock.as_bytes();
    let shape_ok = date_bytes.len() == 10
        && date_bytes[4] == b'/'
        && date_bytes[7] == b'/'
        && clock_bytes.len() == 5
        && clock_bytes[2] == b':';
    if !shape_ok {
        return Err(bad());
    }
    for position in [0, 1, 2, 3, 5, 6, 8, 9] {
        if !date_bytes[position].is_ascii_digit() {
            return Err(bad());
        }
    }
    for position in [0, 1, 3, 4] {
        if !clock_bytes[position].is_ascii_digit() {
            return Err(bad());
        }
    }
    let two = |text: &str| -> u32 {
        let mut out = 0u32;
        for byte in text.bytes() {
            out = out * 10 + u32::from(byte - b'0');
        }
        out
    };
    let year = &date[0..4];
    let month = &date[5..7];
    let day = &date[8..10];
    let hour = &clock[0..2];
    let minute = &clock[3..5];
    if !(1..=12).contains(&two(month))
        || !(1..=31).contains(&two(day))
        || two(hour) > 23
        || two(minute) > 59
    {
        return Err(bad());
    }
    Ok(format!("{year}-{month}-{day}T{hour}:{minute}:00Z"))
}

/// Deal every question into a slice: group ids by category, sort each group,
/// shuffle each group with one SplitMix64 stream, concatenate the groups, and
/// deal the line by largest deficit so each slice takes exactly its count.
/// The same seed reproduces the same split anywhere.
pub fn draw_split(
    questions: &[LmeQuestion],
    dataset: &str,
    dataset_sha256: &str,
    seed: u64,
    counts: SliceCounts,
) -> Result<Split, ConvertError> {
    let total = counts
        .search
        .saturating_add(counts.held_out)
        .saturating_add(counts.sealed);
    if total != questions.len() {
        return Err(ConvertError::CountsMismatch {
            expected: questions.len(),
            found: total,
        });
    }
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for question in questions {
        groups
            .entry(category(question))
            .or_default()
            .push(question.question_id.clone());
    }
    let mut random = SplitMix64 { state: seed };
    for ids in groups.values_mut() {
        ids.sort();
        let len = ids.len();
        for i in (1..len).rev() {
            let j = (random.next_u64() % (i as u64 + 1)) as usize;
            ids.swap(i, j);
        }
    }
    let mut ordered: Vec<(String, String)> = Vec::with_capacity(questions.len());
    for (group, ids) in &groups {
        for id in ids {
            ordered.push((id.clone(), group.clone()));
        }
    }
    let target = [counts.search, counts.held_out, counts.sealed];
    let order = [Slice::Search, Slice::HeldOut, Slice::Sealed];
    let mut assigned = [0usize; 3];
    let mut entries = Vec::with_capacity(ordered.len());
    for (index, (question_id, group)) in ordered.iter().enumerate() {
        let step = index as i128 + 1;
        let size = ordered.len() as i128;
        let mut choice = 0usize;
        let mut choice_deficit = i128::MIN;
        for (s, target_s) in target.iter().enumerate() {
            let deficit = *target_s as i128 * step - assigned[s] as i128 * size;
            if deficit > choice_deficit {
                choice_deficit = deficit;
                choice = s;
            }
        }
        assigned[choice] += 1;
        entries.push(SplitEntry {
            question_id: question_id.clone(),
            category: group.clone(),
            slice: order[choice],
        });
    }
    for (s, target_s) in target.iter().enumerate() {
        if assigned[s] != *target_s {
            return Err(ConvertError::CountsMismatch {
                expected: *target_s,
                found: assigned[s],
            });
        }
    }
    Ok(Split {
        contract: SPLIT_CONTRACT.to_owned(),
        dataset: dataset.to_owned(),
        dataset_sha256: dataset_sha256.to_owned(),
        entries,
    })
}

/// The split digest: sha256 (lowercase hex) of the RFC 8785 canonical bytes
/// of the split. Pack manifests pin it as `split_sha256`.
pub fn split_digest(split: &Split) -> Result<String, ConvertError> {
    let value = serde_json::to_value(split)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| ConvertError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

impl Split {
    /// The slice a question was dealt into, or None when it is not in the split.
    pub fn slice_of(&self, question_id: &str) -> Option<Slice> {
        self.entries
            .iter()
            .find(|entry| entry.question_id == question_id)
            .map(|entry| entry.slice)
    }

    /// For each wanted category in the given order, the first entry (in
    /// entries order) with that category and slice.
    pub fn first_of_each_category(&self, slice: Slice, categories: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        for wanted in categories {
            let found = self
                .entries
                .iter()
                .find(|entry| entry.slice == slice && entry.category == *wanted);
            if let Some(entry) = found {
                out.push(entry.question_id.clone());
            }
        }
        out
    }
}

/// Convert the questions a split assigns to `slice` into a pack slice. With
/// `only`, convert just those ids (each must sit in the converted slice).
/// Records keep first-seen order across the file; the slice holds only its
/// own questions and the sessions they read.
pub fn convert(
    questions: &[LmeQuestion],
    split: &Split,
    slice: Slice,
    meta: &PackMeta,
    only: Option<&[String]>,
) -> Result<PackSlice, ConvertError> {
    if split.dataset_sha256 != meta.dataset_sha256 {
        return Err(ConvertError::SplitOfAnotherDataset {
            expected: meta.dataset_sha256.clone(),
            found: split.dataset_sha256.clone(),
        });
    }
    let by_id: BTreeMap<&str, &LmeQuestion> = questions
        .iter()
        .map(|question| (question.question_id.as_str(), question))
        .collect();
    let mut wanted: Vec<&SplitEntry> = Vec::new();
    match only {
        None => {
            for entry in &split.entries {
                if entry.slice == slice {
                    wanted.push(entry);
                }
            }
        }
        Some(ids) => {
            for id in ids {
                let entry = split
                    .entries
                    .iter()
                    .find(|entry| entry.question_id == *id)
                    .ok_or_else(|| ConvertError::QuestionNotInSlice {
                        question_id: id.clone(),
                    })?;
                if entry.slice != slice {
                    return Err(ConvertError::QuestionNotInSlice {
                        question_id: id.clone(),
                    });
                }
                wanted.push(entry);
            }
        }
    }
    let mut records: Vec<Record> = Vec::new();
    let mut known_records: BTreeSet<String> = BTreeSet::new();
    let mut corpora: Vec<Corpus> = Vec::new();
    let mut queries: Vec<Query> = Vec::new();
    for entry in wanted {
        let Some(question) = by_id.get(entry.question_id.as_str()).copied() else {
            return Err(ConvertError::UnknownQuestion {
                question_id: entry.question_id.clone(),
            });
        };
        if category(question) != entry.category {
            return Err(ConvertError::SplitCategoryMismatch {
                question_id: entry.question_id.clone(),
                expected: entry.category.clone(),
                found: category(question),
            });
        }
        if question.haystack_session_ids.len() != question.haystack_sessions.len()
            || question.haystack_dates.len() != question.haystack_sessions.len()
        {
            return Err(ConvertError::MismatchedHaystack {
                question_id: entry.question_id.clone(),
            });
        }
        let mut sessions: Vec<HaystackSession> = Vec::new();
        let mut seen_sessions = BTreeSet::new();
        for (h, session_id) in question.haystack_session_ids.iter().enumerate() {
            if !seen_sessions.insert(session_id.as_str()) {
                return Err(ConvertError::DuplicateSessionInHaystack {
                    question_id: entry.question_id.clone(),
                    session_id: session_id.clone(),
                });
            }
            let time = lme_time(&question.haystack_dates[h])?;
            let mut turns: Vec<(String, bool)> = Vec::new();
            for (t, turn) in question.haystack_sessions[h].iter().enumerate() {
                if turn.content.trim().is_empty() {
                    continue;
                }
                let key = serde_json::json!([session_id, t, turn.role, turn.content]);
                let canonical = serde_json_canonicalizer::to_vec(&key)
                    .map_err(|error| ConvertError::Canonical(error.to_string()))?;
                let digest = sha256_hex(&canonical);
                let short = digest[..16].to_owned();
                let record_id = format!("lme-{short}");
                if known_records.insert(record_id.clone()) {
                    records.push(Record {
                        record_id: record_id.clone(),
                        kind: RecordKind::Turn,
                        speaker: turn.role.clone(),
                        text: turn.content.clone(),
                        source_ref: format!("{session_id}#{t}"),
                    });
                }
                turns.push((record_id, turn.has_answer));
            }
            if !turns.is_empty() {
                sessions.push(HaystackSession {
                    session_id: session_id.clone(),
                    time,
                    turns,
                });
            }
        }
        let mut corpus_sessions: Vec<CorpusSession> = Vec::new();
        for session in &sessions {
            corpus_sessions.push(CorpusSession {
                session_id: session.session_id.clone(),
                time: session.time.clone(),
                record_ids: session.turns.iter().map(|turn| turn.0.clone()).collect(),
            });
        }
        corpora.push(Corpus {
            corpus_id: entry.question_id.clone(),
            sessions: corpus_sessions,
        });
        let mut qrels: BTreeMap<String, u8> = BTreeMap::new();
        let expect_empty = entry.category == ABSTENTION;
        if !expect_empty {
            for answer_id in &question.answer_session_ids {
                let known = sessions
                    .iter()
                    .any(|session| session.session_id == *answer_id);
                if !known {
                    return Err(ConvertError::MissingAnswerSession {
                        question_id: entry.question_id.clone(),
                        session_id: answer_id.clone(),
                    });
                }
            }
            let mut latest_answer: Option<usize> = None;
            for (h, session) in sessions.iter().enumerate() {
                if !question.answer_session_ids.contains(&session.session_id) {
                    continue;
                }
                let take = match latest_answer {
                    None => true,
                    Some(prev) => {
                        let prev_time = sessions[prev].time.as_str();
                        (session.time.as_str(), h) > (prev_time, prev)
                    }
                };
                if take {
                    latest_answer = Some(h);
                }
            }
            for (h, session) in sessions.iter().enumerate() {
                if !question.answer_session_ids.contains(&session.session_id) {
                    continue;
                }
                let is_latest = latest_answer == Some(h);
                for (record_id, has_answer) in &session.turns {
                    let grade = if *has_answer && (entry.category != KNOWLEDGE_UPDATE || is_latest)
                    {
                        2
                    } else {
                        1
                    };
                    qrels.insert(record_id.clone(), grade);
                }
            }
            if qrels.is_empty() {
                return Err(ConvertError::NoEvidence {
                    question_id: entry.question_id.clone(),
                });
            }
        }
        queries.push(Query {
            query_id: entry.question_id.clone(),
            slice,
            corpus_id: entry.question_id.clone(),
            category: entry.category.clone(),
            text: question.question.clone(),
            now: lme_time(&question.question_date)?,
            qrels,
            expect_empty,
        });
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
            split_sha256: split_digest(split)?,
        },
        embedding: None,
        records,
        corpora,
        queries,
    };
    pack.validate()?;
    Ok(pack)
}

/// SplitMix64: the tiny PRNG behind the seeded shuffle.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// One haystack session that kept at least one non-blank turn: its id, its
/// pack time, and its (record id, has-answer) turns.
struct HaystackSession {
    session_id: String,
    time: String,
    turns: Vec<(String, bool)>,
}
