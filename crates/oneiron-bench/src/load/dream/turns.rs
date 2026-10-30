//! The recorded corpus `load dream` seeds: one JSON line per turn (world,
//! person, day, conversation_ref, speaker runs with message ids and times,
//! saved notes), the selection the flags name, the bodies of its writes, and
//! the fixed query set the recall loop rotates over.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
pub(super) struct Turn {
    pub(super) world: String,
    pub(super) person: String,
    pub(super) day: u32,
    pub(super) conversation_ref: String,
    pub(super) runs: Vec<SpeakerRun>,
    #[serde(default)]
    pub(super) notes: Vec<Note>,
}

/// One speaker's consecutive messages: one witnessed TURN.
#[derive(Deserialize)]
pub(super) struct SpeakerRun {
    pub(super) author: String,
    pub(super) texts: Vec<String>,
    pub(super) at: u64,
    #[serde(default)]
    pub(super) ids: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct Note {
    key: Option<String>,
    value: Option<String>,
}

impl Note {
    pub(super) fn pair(&self) -> Option<(&str, &str)> {
        Some((self.key.as_deref()?, self.value.as_deref()?))
    }
}

/// Which worlds and days to seed; `None` keeps all.
#[derive(Default)]
pub(super) struct Selection {
    /// A world's full name, or its prefix before the first `-` (`w1`).
    pub(super) worlds: Option<Vec<String>>,
    pub(super) days: Option<BTreeSet<u32>>,
}

impl Selection {
    fn keeps(&self, turn: &Turn) -> bool {
        let world = self.worlds.as_ref().is_none_or(|names| {
            names.iter().any(|name| {
                turn.world == *name
                    || turn
                        .world
                        .strip_prefix(name.as_str())
                        .is_some_and(|rest| rest.starts_with('-'))
            })
        });
        world
            && self
                .days
                .as_ref()
                .is_none_or(|days| days.contains(&turn.day))
    }
}

/// `--days`: `1-6`, `2,4` or `3`.
pub(super) fn days(value: &str) -> Result<BTreeSet<u32>, String> {
    let mut days = BTreeSet::new();
    for part in value.split(',').map(str::trim) {
        let day = |text: &str| {
            text.trim()
                .parse::<u32>()
                .map_err(|_| format!("--days: `{part}` is not a day or a range like 1-6"))
        };
        match part.split_once('-') {
            Some((first, last)) => days.extend(day(first)?..=day(last)?),
            None => {
                days.insert(day(part)?);
            }
        }
    }
    Ok(days)
}

/// The selected turns of the corpus at `path`, in file order.
pub(super) fn read(path: &Path, selection: &Selection) -> Result<Vec<Turn>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut turns = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let turn: Turn =
            serde_json::from_str(line).map_err(|e| format!("corpus line {}: {e}", index + 1))?;
        if selection.keeps(&turn) {
            turns.push(turn);
        }
    }
    if turns.is_empty() {
        return Err("the corpus selection holds no turns".into());
    }
    Ok(turns)
}

/// What the selection holds, for the report.
#[derive(Debug, Serialize)]
pub(super) struct Counts {
    pub(super) worlds: Vec<String>,
    pub(super) days: Vec<u32>,
    pub(super) turns: usize,
    pub(super) runs: usize,
    pub(super) messages: usize,
    pub(super) notes: usize,
    /// One Meso partition each, at most: the round plans by conversation.
    pub(super) conversations: usize,
}

impl Counts {
    pub(super) fn of(turns: &[Turn]) -> Self {
        let mut worlds = Vec::new();
        for turn in turns {
            if !worlds.contains(&turn.world) {
                worlds.push(turn.world.clone());
            }
        }
        Self {
            worlds,
            days: turns
                .iter()
                .map(|t| t.day)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            turns: turns.len(),
            runs: turns.iter().map(|t| t.runs.len()).sum(),
            messages: turns
                .iter()
                .flat_map(|t| &t.runs)
                .map(|r| r.texts.len())
                .sum(),
            notes: turns
                .iter()
                .flat_map(|t| &t.notes)
                .filter(|n| n.pair().is_some())
                .count(),
            conversations: turns
                .iter()
                .map(|t| t.conversation_ref.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
        }
    }
}

/// One speaker run as `vault.witness` takes it, with the corpus' own
/// conversation and message ids, so two runs write the same rows. No
/// `turn_ref`: each run mints its TURN, and only a minted TURN joins the
/// open sitting (`memory/witness/base.rs`).
pub(super) fn witness_body(turn: &Turn, run: &SpeakerRun) -> Value {
    let messages = run
        .texts
        .iter()
        .enumerate()
        .map(|(order, content)| {
            let mut message = json!({
                "author": run.author,
                "message_type": "text",
                "content": content,
                "is_visible": true,
                "order": order,
            });
            if let Some(id) = run.ids.get(order) {
                message["id"] = json!(id);
            }
            message
        })
        .collect::<Vec<_>>();
    json!({
        "conversation_ref": turn.conversation_ref,
        "occurred_at": run.at,
        "messages": messages,
    })
}

/// One saved note as `vault.claims.upsert` takes it, on the turn's
/// conversation, at the turn's last time.
pub(super) fn note_body(turn: &Turn, key: &str, value: &str) -> Value {
    let at = turn.runs.last().map_or(0, |r| r.at);
    json!({
        "predicate": predicate_of(key),
        "subject_ref": turn.conversation_ref,
        "value": value,
        "occurred_at": at,
        "learned_at": at,
        "confidence": 0.9,
        "source": "user_stated",
    })
}

/// A note key as a claim predicate: `note.` and its lower-case ASCII words
/// joined by `_`.
fn predicate_of(key: &str) -> String {
    let slug = key
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("_");
    format!("note.{}", slug.chars().take(48).collect::<String>())
}

/// Words a query carries no signal in.
const STOPWORDS: [&str; 40] = [
    "the", "and", "for", "with", "that", "this", "from", "have", "has", "are", "was", "were",
    "will", "you", "your", "our", "but", "not", "all", "can", "its", "into", "about", "every",
    "each", "they", "them", "then", "than", "what", "when", "which", "who", "she", "her", "his",
    "him", "just", "also", "been",
];

/// The lower-case content words of `text`: three letters or more, not all
/// digits, not a stopword.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| {
            word.chars().count() >= 3
                && !word.chars().all(|c| c.is_ascii_digit())
                && !STOPWORDS.contains(&word.as_str())
        })
}

/// The recall loop's fixed queries, built without a model and in corpus
/// order, so two runs compare: each person's full name, then rounds over
/// the people, each round adding one note per person: the person's name
/// with that note value's two rarest content words (rarest over every
/// message and note value of the selection). At most `cap`, no repeats.
pub(super) fn queries(turns: &[Turn], cap: usize) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for turn in turns {
        let texts = turn.runs.iter().flat_map(|r| &r.texts).map(String::as_str);
        let values = turn.notes.iter().filter_map(|n| n.pair().map(|(_, v)| v));
        for word in texts.chain(values).flat_map(words) {
            *seen.entry(word).or_default() += 1;
        }
    }
    let mut people: Vec<(&str, Vec<String>)> = Vec::new();
    for turn in turns {
        let at = match people.iter().position(|(name, _)| *name == turn.person) {
            Some(at) => at,
            None => {
                people.push((turn.person.as_str(), Vec::new()));
                people.len() - 1
            }
        };
        let name = words(&turn.person).collect::<BTreeSet<_>>();
        for (_, value) in turn.notes.iter().filter_map(Note::pair) {
            let mut rare: Vec<(usize, usize, String)> = Vec::new();
            for (position, word) in words(value).enumerate() {
                if !name.contains(&word) && !rare.iter().any(|(_, _, w)| *w == word) {
                    rare.push((seen.get(&word).copied().unwrap_or(0), position, word));
                }
            }
            rare.sort();
            let picked = rare
                .into_iter()
                .take(2)
                .map(|(_, _, w)| w)
                .collect::<Vec<_>>();
            if !picked.is_empty() {
                people[at]
                    .1
                    .push(format!("{} {}", turn.person, picked.join(" ")));
            }
        }
    }
    let mut queries = Vec::new();
    let mut add = |query: String| {
        if queries.len() < cap && !queries.contains(&query) {
            queries.push(query);
        }
    };
    for (name, _) in &people {
        add((*name).to_owned());
    }
    let rounds = people
        .iter()
        .map(|(_, notes)| notes.len())
        .max()
        .unwrap_or(0);
    for round in 0..rounds {
        for (_, notes) in &people {
            if let Some(query) = notes.get(round) {
                add(query.clone());
            }
        }
    }
    queries
}
