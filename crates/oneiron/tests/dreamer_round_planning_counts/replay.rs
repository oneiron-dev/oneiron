//! Witness-run replay data, with diagnostics that never include message text.
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayAuthor {
    User,
    Companion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayRun {
    pub(crate) author: ReplayAuthor,
    pub(crate) occurred_at: u64,
    pub(crate) texts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayConversation {
    pub(crate) world: String,
    pub(crate) day: u64,
    pub(crate) runs: Vec<ReplayRun>,
}

/// Line zero identifies a directory, filename, or whole-file error.
/// A fixed reason prevents parser errors from echoing private input values.
pub(crate) fn replay_error(path: &Path, line: usize, reason: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}:{line}: {reason}", path.display()),
    )
}

pub(crate) fn replay_file_key(path: &Path) -> io::Result<(String, u64)> {
    let invalid = || replay_error(path, 0, "expected a world.day.jsonl filename");
    let filename = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(invalid)?;
    let mut parts = filename.split('.');
    let world = parts.next().ok_or_else(invalid)?;
    let day = parts.next().ok_or_else(invalid)?;
    if parts.next() != Some("jsonl")
        || parts.next().is_some()
        || world.is_empty()
        || !world
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || day.is_empty()
        || !day.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let day = day.parse::<u64>().map_err(|_| invalid())?;
    Ok((world.to_owned(), day))
}

pub(crate) fn parse_replay_run(path: &Path, line: usize, input: &str) -> io::Result<ReplayRun> {
    let value: Value =
        serde_json::from_str(input).map_err(|_| replay_error(path, line, "invalid JSON object"))?;
    let object = value
        .as_object()
        .ok_or_else(|| replay_error(path, line, "expected a run object"))?;
    let author = match object.get("author").and_then(Value::as_str) {
        Some("user") => ReplayAuthor::User,
        Some("companion") => ReplayAuthor::Companion,
        _ => return Err(replay_error(path, line, "missing or unknown author")),
    };
    let occurred_at = object
        .get("occurred_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| replay_error(path, line, "missing or invalid occurred_at"))?;
    let values = object
        .get("texts")
        .and_then(Value::as_array)
        .filter(|texts| !texts.is_empty())
        .ok_or_else(|| replay_error(path, line, "missing or empty texts array"))?;
    let texts = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| replay_error(path, line, "a text is not a string"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(ReplayRun {
        author,
        occurred_at,
        texts,
    })
}

/// Reads regular JSONL files only, sorted by world and numeric day.
/// Other regular filenames are rejected rather than silently omitted.
pub(crate) fn read_replay_dir(path: &Path) -> io::Result<Vec<ReplayConversation>> {
    let entries =
        fs::read_dir(path).map_err(|_| replay_error(path, 0, "cannot read replay directory"))?;
    let mut conversations = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| replay_error(path, 0, "cannot read directory entry"))?;
        let file_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|_| replay_error(&file_path, 0, "cannot read entry type"))?;
        if !file_type.is_file() {
            continue;
        }
        let (world, day) = replay_file_key(&file_path)?;
        if !seen.insert((world.clone(), day)) {
            return Err(replay_error(
                &file_path,
                0,
                "duplicate world and numeric day",
            ));
        }
        let file = File::open(&file_path)
            .map_err(|_| replay_error(&file_path, 0, "cannot open replay file"))?;
        let mut runs = Vec::new();
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = index + 1;
            let line =
                line.map_err(|_| replay_error(&file_path, line_number, "cannot read UTF-8 run"))?;
            if !line.trim().is_empty() {
                runs.push(parse_replay_run(&file_path, line_number, &line)?);
            }
        }
        if runs.is_empty() {
            return Err(replay_error(&file_path, 0, "replay file has no runs"));
        }
        conversations.push(ReplayConversation { world, day, runs });
    }
    if conversations.is_empty() {
        return Err(replay_error(
            path,
            0,
            "replay directory has no conversations",
        ));
    }
    conversations
        .sort_by(|left, right| left.world.cmp(&right.world).then(left.day.cmp(&right.day)));
    Ok(conversations)
}

/// A base-word encoding makes each conversation's sentence suffix distinct.
pub(crate) fn conversation_words(mut index: usize) -> String {
    const WORDS: [&str; 8] = [
        "amber", "birch", "cedar", "dune", "elm", "fern", "grove", "heath",
    ];
    let mut words = Vec::new();
    loop {
        words.push(WORDS[index % WORDS.len()]);
        index /= WORDS.len();
        if index == 0 {
            break;
        }
    }
    words.join(" ")
}

/// Builds deterministic conversations without copying any replay input.
/// Different conversations have different sentence suffixes; intentional
/// cross-conversation repeats can be assigned explicitly by a window test.
pub(crate) fn synthetic_conversations(counts: &[(&str, u64, usize)]) -> Vec<ReplayConversation> {
    const TOPICS: [&str; 4] = ["garden", "river", "library", "station"];
    const ACTIONS: [&str; 4] = ["map", "measure", "record", "compare"];
    let mut counts = counts.to_vec();
    counts.sort_unstable_by_key(|&(world, day, _)| (world, day));
    counts.iter().enumerate().map(|(conversation_index, &(world, day, count))| {
        let identity = conversation_words(conversation_index);
        let runs = (0..count).map(|run_index| ReplayRun {
            author: if run_index % 2 == 0 { ReplayAuthor::User } else { ReplayAuthor::Companion },
            occurred_at: 1_000 + run_index as u64,
            texts: (0..=run_index % 2).map(|message_index| format!(
                "owen and yuki {} the {} together and record a clear observation about the route beside the water for conversation {} run {} message {}.",
                ACTIONS[run_index % ACTIONS.len()], TOPICS[run_index % TOPICS.len()],
                identity, run_index, message_index,
            )).collect(),
        }).collect();
        ReplayConversation { world: world.to_owned(), day, runs }
    }).collect()
}
