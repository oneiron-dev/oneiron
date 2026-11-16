//! The lives screen's JSON report: one row per question per grade per system,
//! with its accuracy and its latency together (ARCH-0042 #lives-bench: "Each
//! row reports accuracy and latency together"), and a summary per grade.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::super::report::Host;
use super::super::stats::{Sample, Summary};
use super::corpus::{Life, Question, Set};
use super::score;

#[derive(Serialize)]
pub(super) struct Report {
    pub(super) bench: &'static str,
    pub(super) label: Option<String>,
    pub(super) started_unix: u64,
    pub(super) host: Host,
    pub(super) server: Server,
    /// The flags, by name; `--server-env` values are never echoed.
    pub(super) plan: Value,
    pub(super) corpus: CorpusInfo,
    pub(super) systems: Vec<System>,
}

/// What served the Oneiron store.
#[derive(Serialize)]
pub(super) struct Server {
    /// `spawned` (the shipped binary, the measuring mode) or `in_process`
    /// (the engine linked into this bench with its test-support features:
    /// for checking the harness, never a published number).
    pub(super) mode: &'static str,
    pub(super) bin: Option<String>,
    pub(super) bytes: Option<u64>,
    /// `agent` (a minted full-access agent) or `owner` (a slip minted for the
    /// embedded owner).
    pub(super) principal: &'static str,
    /// `none`, `local`, or `endpoint <model-id@revision>`.
    pub(super) embedder: String,
}

#[derive(Serialize)]
pub(super) struct FileDigest {
    pub(super) path: String,
    pub(super) sha256: String,
}

#[derive(Serialize)]
pub(super) struct LifeInfo {
    /// The key rows name: `life_id`, or `life_id~N` for a repeated id.
    pub(super) life: String,
    pub(super) life_id: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) lang: String,
    pub(super) turns: usize,
    pub(super) questions: usize,
}

#[derive(Serialize)]
pub(super) struct CorpusInfo {
    pub(super) files: Vec<FileDigest>,
    /// The picked lives, in ingest order; `--life` with these keys takes the
    /// same set in another run.
    pub(super) lives: Vec<LifeInfo>,
    /// Turns of the picked lives: what every system is given.
    pub(super) documents: usize,
}

/// One system's run over the picked lives.
#[derive(Serialize)]
pub(super) struct System {
    pub(super) name: String,
    /// `measured`, or `not_ready` (with `reason`, and no rows) for a system
    /// whose adapter failed to reset, take any turn or settle.
    pub(super) status: &'static str,
    pub(super) reason: Option<String>,
    /// Turns the system took in (a failed write is not counted).
    pub(super) documents: usize,
    pub(super) ingest: Summary,
    pub(super) settle_seconds: f64,
    pub(super) drain_seconds: Option<f64>,
    pub(super) disk_mib: Option<f64>,
    pub(super) summary: Vec<GradeSummary>,
    pub(super) rows: Vec<Row>,
}

/// One question asked of one system at one grade.
#[derive(Serialize)]
pub(super) struct Row {
    pub(super) system: String,
    pub(super) life: String,
    pub(super) qid: String,
    /// `native` or `ja_cross`.
    pub(super) set: &'static str,
    pub(super) lang: String,
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) grade: String,
    /// The `as_of` the question was asked at: the end of its life's last day.
    pub(super) as_of: u64,
    /// The bench's round trip.
    pub(super) ms: f64,
    /// An external system's own timing of its call, as its adapter reports
    /// it (`None` for Oneiron, whose `ms` is already on loopback).
    pub(super) system_ms: Option<f64>,
    pub(super) items: usize,
    pub(super) partial: bool,
    pub(super) error: Option<String>,
    pub(super) scored: bool,
    pub(super) unscored_reason: Option<&'static str>,
    /// Scored rows only.
    pub(super) answer_in_context: Option<bool>,
    pub(super) evidence_rank: Option<usize>,
    pub(super) evidence_turn: Option<String>,
    pub(super) texts_digest: String,
}

/// What one system answered to one question.
pub(super) struct Answer {
    pub(super) ms: f64,
    pub(super) system_ms: Option<f64>,
    pub(super) partial: bool,
    /// Each returned item's texts, in rank order.
    pub(super) items: Vec<Vec<String>>,
    pub(super) error: Option<String>,
}

impl Row {
    /// The row for `answer` from `system` at `grade` to `question` of `life`.
    pub(super) fn of(
        system: &str,
        grade: &str,
        life: &Life,
        set: Set,
        question: &Question,
        answer: Answer,
    ) -> Self {
        let unscored_reason = score::unscored_reason(question);
        let scored = unscored_reason
            .is_none()
            .then(|| score::score(life, question, &answer.items));
        Self {
            system: system.to_owned(),
            life: life.key.clone(),
            qid: question.qid.clone(),
            set: set.name(),
            lang: life.lang.clone(),
            kind: question.kind.clone(),
            grade: grade.to_owned(),
            as_of: life.end,
            ms: answer.ms,
            system_ms: answer.system_ms,
            items: answer.items.len(),
            partial: answer.partial,
            error: answer.error,
            scored: scored.is_some(),
            unscored_reason,
            answer_in_context: scored.as_ref().map(|s| s.answer_in_context),
            evidence_rank: scored.as_ref().and_then(|s| s.evidence_rank),
            evidence_turn: scored.and_then(|s| s.evidence_turn),
            texts_digest: score::texts_digest(&answer.items),
        }
    }
}

/// Scored rows and their hits, for one slice.
#[derive(Default, Serialize)]
pub(super) struct Tally {
    pub(super) scored: usize,
    pub(super) answer_in_context: usize,
    pub(super) evidence_hit: usize,
}

impl Tally {
    fn add(&mut self, row: &Row) {
        if row.scored {
            self.scored += 1;
            self.answer_in_context += usize::from(row.answer_in_context == Some(true));
            self.evidence_hit += usize::from(row.evidence_rank.is_some());
        }
    }
}

#[derive(Serialize)]
pub(super) struct GradeSummary {
    pub(super) grade: String,
    pub(super) rows: usize,
    pub(super) errors: usize,
    pub(super) scored: usize,
    pub(super) answer_in_context: usize,
    pub(super) answer_in_context_rate: Option<f64>,
    /// Scored rows whose top k held a gold evidence turn.
    pub(super) evidence_hit: usize,
    pub(super) evidence_hit_rate: Option<f64>,
    pub(super) by_type: BTreeMap<String, Tally>,
    pub(super) by_set: BTreeMap<String, Tally>,
    /// Over every row of the grade, with canon's corpus-size floor
    /// (ARCH-0042 #speedup-integrity-h: no latency below 1,000 documents).
    pub(super) latency: Summary,
    /// The same over the rows' `system_ms`, when the system reports it.
    pub(super) system_latency: Option<Summary>,
}

/// The floored summary of the rows' `system_ms`, when any row has one.
fn system_latency(rows: &[&Row], documents: usize) -> Option<Summary> {
    let samples = rows
        .iter()
        .filter_map(|row| {
            row.system_ms.map(|ms| Sample {
                ms,
                error: row.error.clone(),
                partial: row.partial,
                items: row.items,
            })
        })
        .collect::<Vec<_>>();
    (!samples.is_empty()).then(|| Summary::of(&samples, 0.0).below_corpus_floor(documents))
}

fn rate(hits: usize, of: usize) -> Option<f64> {
    (of > 0).then(|| hits as f64 / of as f64)
}

/// One summary per grade, in `grades` order; `seconds` is each grade's
/// wall time and `documents` the store's size.
pub(super) fn summarize(
    rows: &[Row],
    grades: &[String],
    seconds: &BTreeMap<String, f64>,
    documents: usize,
) -> Vec<GradeSummary> {
    grades
        .iter()
        .map(|grade| {
            let of_grade = rows
                .iter()
                .filter(|r| &r.grade == grade)
                .collect::<Vec<_>>();
            let mut all = Tally::default();
            let mut by_type = BTreeMap::<String, Tally>::new();
            let mut by_set = BTreeMap::<String, Tally>::new();
            for row in &of_grade {
                all.add(row);
                by_type.entry(row.kind.clone()).or_default().add(row);
                by_set.entry(row.set.to_owned()).or_default().add(row);
            }
            let samples = of_grade
                .iter()
                .map(|row| Sample {
                    ms: row.ms,
                    error: row.error.clone(),
                    partial: row.partial,
                    items: row.items,
                })
                .collect::<Vec<_>>();
            GradeSummary {
                grade: grade.clone(),
                rows: of_grade.len(),
                errors: of_grade.iter().filter(|r| r.error.is_some()).count(),
                scored: all.scored,
                answer_in_context: all.answer_in_context,
                answer_in_context_rate: rate(all.answer_in_context, all.scored),
                evidence_hit: all.evidence_hit,
                evidence_hit_rate: rate(all.evidence_hit, all.scored),
                by_type,
                by_set,
                latency: Summary::of(&samples, seconds.get(grade).copied().unwrap_or(0.0))
                    .below_corpus_floor(documents),
                system_latency: system_latency(&of_grade, documents),
            }
        })
        .collect()
}
