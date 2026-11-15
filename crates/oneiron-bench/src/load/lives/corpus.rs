//! The lives corpus: the synthetic-lives generation run's JSONL as it is (one
//! life per line), every turn's conversation, time and text as each system
//! ingests it, and the screen's seeded pick.
//!
//! A life needs `life_id`, `lang` and `days[].date`, `days[].sessions[].sid`
//! and `days[].sessions[].turns[]` (`{id, role: user|assistant|tool, text}`;
//! a tool turn carries `tool` and `lines` instead of `text`), plus
//! `questions[]` and `questions_ja[]` (`{qid, type, question, answer_span,
//! evidence, support}`). Every other field is ignored: `persona`, `plan`,
//! `filter_items`, `meta`, and the `ledger`, which is the generator's answer
//! key, so no system ever ingests it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::super::corpus::Rng;

#[derive(Deserialize)]
struct LifeLine {
    life_id: String,
    lang: String,
    days: Vec<DayLine>,
    #[serde(default)]
    questions: Option<Vec<Question>>,
    #[serde(default)]
    questions_ja: Option<Vec<Question>>,
}

#[derive(Deserialize)]
struct DayLine {
    date: String,
    sessions: Vec<SessionLine>,
}

#[derive(Deserialize)]
struct SessionLine {
    sid: String,
    turns: Vec<TurnLine>,
}

#[derive(Deserialize)]
struct TurnLine {
    id: String,
    role: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    lines: Option<Vec<String>>,
}

/// One question as the generation run wrote it.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Question {
    pub(super) qid: String,
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) question: String,
    #[serde(default)]
    pub(super) answer_span: Option<String>,
    /// Turn ids (`d2s1t04`), or tool lines inside a turn (`d2s1t04:L02`).
    #[serde(default)]
    pub(super) evidence: Vec<String>,
    /// `string` when the answer span was checked against the evidence text.
    #[serde(default)]
    pub(super) support: Option<String>,
}

/// Which question list a question came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Set {
    /// `questions`: in the life's own language.
    Native,
    /// `questions_ja`: Japanese questions about the life.
    JaCross,
}

impl Set {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::JaCross => "ja_cross",
        }
    }
}

/// Who said a turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Role {
    User,
    Assistant,
    Tool,
}

/// One turn as every system ingests it.
#[derive(Clone, Debug)]
pub(super) struct Turn {
    pub(super) id: String,
    pub(super) role: Role,
    /// The text; a tool turn's is its tool name and its lines, one per line.
    pub(super) text: String,
    /// The session's conversation: 32 hex, the same for every system.
    pub(super) conversation: String,
    /// Unix seconds: the day's date at 09:00 UTC, plus 2 h per session of the
    /// day, plus 20 s per turn of the session, and always after the turn
    /// before it in the life.
    pub(super) at: u64,
}

/// One life, keyed for this run.
#[derive(Clone, Debug)]
pub(super) struct Life {
    /// `life_id`, or `life_id~N` for its Nth copy when the files read hold
    /// two lives under one id (the 2026-10-14 run has 12 such ids).
    pub(super) key: String,
    pub(super) life_id: String,
    pub(super) lang: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) turns: Vec<Turn>,
    pub(super) questions: Vec<(Set, Question)>,
    /// Midnight UTC after the life's last day.
    pub(super) end: u64,
}

impl Life {
    /// The text of the turn `evidence` names (`d2s1t04` or `d2s1t04:L02`).
    pub(super) fn evidence_text(&self, evidence: &str) -> Option<(&str, &str)> {
        let id = evidence.split_once(':').map_or(evidence, |(turn, _)| turn);
        self.turns
            .iter()
            .find(|turn| turn.id == id)
            .map(|turn| (turn.id.as_str(), turn.text.as_str()))
    }
}

/// A file read, with its digest for the report.
pub(super) struct File {
    pub(super) path: String,
    pub(super) sha256: String,
}

pub(super) struct Corpus {
    pub(super) files: Vec<File>,
    pub(super) lives: Vec<Life>,
}

/// Which lives the screen takes.
pub(super) enum Pick {
    /// Every life read (the full run).
    All,
    /// These life keys, in this order.
    Named(Vec<String>),
    /// Lives in a seeded shuffle of the key order until there are at least
    /// `lives` of them and they hold at least `min_turns` turns (ASK
    /// L9-36-STORE = B: latency only counts past canon's 1,000-document
    /// floor), or the corpus ends.
    Sample {
        lives: usize,
        seed: u64,
        min_turns: usize,
    },
}

/// The 32-hex conversation id of session `sid` of life `key`.
fn conversation_ref(key: &str, sid: &str) -> String {
    let hash = blake3::hash(format!("lives-v1/{key}/{sid}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    // Set the top bits so no id lands on the engine's reserved low ids, as
    // the load corpus does.
    bytes[0] |= 0x40;
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Unix seconds at midnight UTC of `YYYY-MM-DD`.
fn midnight(date: &str) -> Option<u64> {
    let mut parts = date.splitn(3, '-').map(str::parse::<i64>);
    let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day))) =
        (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    u64::try_from(days_from_civil(year, month, day) * 86_400).ok()
}

/// The `lives-*.jsonl` files under each path (a file is taken as it is).
fn files_of(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut found = std::fs::read_dir(path)
                .map_err(|e| format!("--lives {}: {e}", path.display()))?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("lives-") && n.ends_with(".jsonl"))
                })
                .collect::<Vec<_>>();
            if found.is_empty() {
                return Err(format!(
                    "--lives {}: no lives-*.jsonl inside",
                    path.display()
                ));
            }
            found.sort();
            files.extend(found);
        } else {
            files.push(path.clone());
        }
    }
    Ok(files)
}

fn turn_of(turn: TurnLine, conversation: &str, at: u64, whose: &str) -> Result<Turn, String> {
    let missing = |field: &str| format!("{whose}: turn {} has no `{field}`", turn.id);
    let (role, text) = match turn.role.as_str() {
        "user" => (
            Role::User,
            turn.text.clone().ok_or_else(|| missing("text"))?,
        ),
        "assistant" => (
            Role::Assistant,
            turn.text.clone().ok_or_else(|| missing("text"))?,
        ),
        "tool" => {
            let name = turn.tool.clone().ok_or_else(|| missing("tool"))?;
            let lines = turn.lines.clone().ok_or_else(|| missing("lines"))?;
            (Role::Tool, format!("{name}\n{}", lines.join("\n")))
        }
        other => {
            return Err(format!(
                "{whose}: turn {} has role `{other}`; a turn is user, assistant or tool",
                turn.id
            ));
        }
    };
    Ok(Turn {
        id: turn.id,
        role,
        text,
        conversation: conversation.to_owned(),
        at,
    })
}

/// One life line under `key`, refused with its file, line, life id and
/// missing field.
fn life_of(value: serde_json::Value, key: String, file: &str, line: usize) -> Result<Life, String> {
    let whose = format!(
        "{file}:{line}: life {}",
        value["life_id"].as_str().unwrap_or("?")
    );
    let parsed: LifeLine = serde_json::from_value(value).map_err(|e| format!("{whose}: {e}"))?;
    let mut turns = Vec::new();
    let mut last_at = 0;
    let mut end = 0;
    for day in parsed.days {
        let day_start = midnight(&day.date)
            .ok_or_else(|| format!("{whose}: day date `{}` is not YYYY-MM-DD", day.date))?;
        end = end.max(day_start + 86_400);
        for (session_index, session) in day.sessions.into_iter().enumerate() {
            let conversation = conversation_ref(&key, &session.sid);
            let session_start = day_start + 9 * 3_600 + 2 * 3_600 * session_index as u64;
            for (turn_index, turn) in session.turns.into_iter().enumerate() {
                let at = (session_start + 20 * turn_index as u64).max(last_at + 1);
                last_at = at;
                turns.push(turn_of(turn, &conversation, at, &whose)?);
            }
        }
    }
    let questions = parsed
        .questions
        .unwrap_or_default()
        .into_iter()
        .map(|q| (Set::Native, q))
        .chain(
            parsed
                .questions_ja
                .unwrap_or_default()
                .into_iter()
                .map(|q| (Set::JaCross, q)),
        )
        .collect();
    Ok(Life {
        key,
        life_id: parsed.life_id,
        lang: parsed.lang,
        file: file.to_owned(),
        line,
        turns,
        questions,
        end: end.max(last_at + 1),
    })
}

/// Reads every life under `paths`, keying repeated ids `id~2`, `id~3`, ...
/// in read order (files in the order given, a directory's sorted by name).
pub(super) fn read(paths: &[PathBuf]) -> Result<Corpus, String> {
    let mut corpus = Corpus {
        files: Vec::new(),
        lives: Vec::new(),
    };
    let mut seen = BTreeMap::<String, usize>::new();
    for path in files_of(paths)? {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = path.display().to_string();
        let text = std::str::from_utf8(&bytes).map_err(|e| format!("{name}: {e}"))?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|e| format!("{name}:{}: {e}", index + 1))?;
            // The key names the conversations, so two lives under one id
            // never share a conversation.
            let key = match value["life_id"].as_str() {
                Some(id) => {
                    let copies = seen.entry(id.to_owned()).or_default();
                    *copies += 1;
                    if *copies > 1 {
                        format!("{id}~{copies}")
                    } else {
                        id.to_owned()
                    }
                }
                None => String::new(),
            };
            corpus.lives.push(life_of(value, key, &name, index + 1)?);
        }
        corpus.files.push(File {
            path: name,
            sha256: Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        });
    }
    Ok(corpus)
}

/// The lives the screen ingests, in ingest order.
pub(super) fn pick(mut lives: Vec<Life>, pick: &Pick) -> Result<Vec<Life>, String> {
    lives.sort_by(|a, b| a.key.cmp(&b.key));
    match pick {
        Pick::All => Ok(lives),
        Pick::Named(keys) => {
            let mut chosen = Vec::new();
            for key in keys {
                if chosen.iter().any(|life: &Life| &life.key == key) {
                    continue;
                }
                let life = lives
                    .iter()
                    .find(|life| &life.key == key)
                    .ok_or_else(|| format!("--life {key}: no such life in the files read"))?;
                chosen.push(life.clone());
            }
            Ok(chosen)
        }
        Pick::Sample {
            lives: wanted,
            seed,
            min_turns,
        } => {
            let mut rng = Rng::new(*seed);
            for i in (1..lives.len()).rev() {
                let j = ((rng.unit() * (i + 1) as f64) as usize).min(i);
                lives.swap(i, j);
            }
            let mut chosen = Vec::new();
            let mut turns = 0;
            for life in lives {
                if chosen.len() >= *wanted && turns >= *min_turns {
                    break;
                }
                turns += life.turns.len();
                chosen.push(life);
            }
            Ok(chosen)
        }
    }
}
