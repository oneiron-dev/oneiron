//! The fold word references a recorded fold answer keeps (FIX 18924).
//!
//! A fold answer's outcome keeps its JSON under `json`. When the JSON
//! copies a fold's accepted summary, the outcome also keeps `words`: for
//! each such fold, its run, its number and the records the summary was
//! written from. The entry holds no words. An answer with none keeps no
//! `words` key, and one recorded before the key reads back with none. An
//! answer a withdrawal took keeps the same entry on its erased outcome.

use rmpv::Value;

use super::super::replay::CodeRunBridgeCall;
use super::super::support::{
    decode_array, entity_id_value, entity_value, expect_map, map_get, request_map, u64_value,
};
use super::super::types::FoldWordRef;
use crate::Result;

const KIND: &str = "kind";
const FOLD: &str = "fold";
const WORDS: &str = "words";

/// `words` as a fold answer's outcome keeps them.
pub(super) fn fold_words_value(words: &[FoldWordRef]) -> Value {
    Value::Array(
        words
            .iter()
            .map(|word| {
                request_map(vec![
                    ("source_run", entity_id_value(word.source_run)),
                    ("fold", Value::from(word.fold)),
                    (
                        "sources",
                        Value::Array(word.sources.iter().copied().map(entity_id_value).collect()),
                    ),
                ])
            })
            .collect(),
    )
}

fn decode_fold_word(value: &Value) -> Result<FoldWordRef> {
    let entries = expect_map(value, "fold word reference must be a map")?;
    Ok(FoldWordRef {
        source_run: entity_value(map_get(entries, "source_run")?)?,
        fold: u64_value(map_get(entries, "fold")?)?,
        sources: decode_array(map_get(entries, "sources")?, entity_value)?,
    })
}

fn entry<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

/// The folds a fold answer's outcome `entries` name; none when it keeps no
/// `words` key.
pub(super) fn decode_fold_words(entries: &[(Value, Value)]) -> Result<Vec<FoldWordRef>> {
    entry(entries, WORDS).map_or_else(
        || Ok(Vec::new()),
        |words| decode_array(words, decode_fold_word),
    )
}

/// The folds the recorded fold answer `outcome` copies the words of, read
/// without decoding its JSON. `None` for any other outcome, and for a fold
/// answer whose `words` entry does not decode.
pub(in crate::code_run) fn answer_fold_words(outcome: &Value) -> Option<Vec<FoldWordRef>> {
    let Value::Map(entries) = outcome else {
        return None;
    };
    if entry(entries, KIND)?.as_str() != Some(FOLD) {
        return None;
    }
    decode_fold_words(entries).ok()
}

/// The folds whose words the live fold answers among `calls` copy, each
/// once, in call order (FIX 18924). An erased answer copies none, and an
/// answer whose `words` entry does not decode names none here.
pub(crate) fn recorded_fold_words(calls: &[CodeRunBridgeCall]) -> Vec<FoldWordRef> {
    let mut words = Vec::new();
    for call in calls {
        for word in answer_fold_words(&call.outcome).unwrap_or_default() {
            push_fold_word(&mut words, word);
        }
    }
    words
}

/// Adds `word` to `words` unless they already name it (FIX 18924).
pub(crate) fn push_fold_word(words: &mut Vec<FoldWordRef>, word: FoldWordRef) {
    if !words.contains(&word) {
        words.push(word);
    }
}

/// Keeps `words`, the folds an answer a withdrawal took copied, on its
/// erased outcome: the record still says whose words it held, and holds
/// none of them.
pub(in crate::code_run) fn keep_erased_fold_words(outcome: &mut Value, words: &[FoldWordRef]) {
    let Value::Map(entries) = outcome else {
        return;
    };
    if !words.is_empty() {
        entries.push((Value::from(WORDS), fold_words_value(words)));
    }
}
