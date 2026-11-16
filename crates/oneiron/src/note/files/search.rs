//! The name tier of a Files world search (ARCH-0027 #files-world: "Search
//! goes by name first and meaning second"): how one file's name and path
//! match a query, in the classes a search lists files by.

use serde::{Deserialize, Serialize};

/// The mark a continuation part of a long file's text carries after the
/// file's path in its source's ledger: `<path>/#part<n>` (FIX 6942). The
/// part's row is the same file as the row at `<path>`. A real file named
/// `#part<n>` in a folder at `<path>` has the same path; a folder and a file
/// never share one, so the ledger's row at `<path>` tells them apart.
pub const FILES_PART_MARK: &str = "/#part";

/// How a file's name matches a search query, best first. Names compare in
/// Unicode lower case; the query's words are split at whitespace.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NameMatch {
    /// The query is the file's whole name, or its name without its last
    /// extension.
    Exact,
    /// The file's name starts with the query.
    Prefix,
    /// Every word of the query is in the file's name.
    NameWords,
    /// Every word of the query is in the file's path under its folder.
    PathWords,
}

/// The file path a ledger row's path names when it has a continuation
/// part's shape (`<path>/#part<n>`): `<path>`. The row is that file's part
/// only when its source's ledger holds a file at `<path>`; else it is a file
/// of its own, named `#part<n>`.
#[must_use]
pub fn part_file_path(path: &str) -> Option<&str> {
    path.rsplit_once(FILES_PART_MARK)
        .filter(|(file, number)| {
            !file.is_empty()
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map(|(file, _)| file)
}

/// How the file at `path` (under its folder, `/`-separated) matches
/// `query`; `None` when it does not, or when the query holds no word.
#[must_use]
pub fn name_match(path: &str, query: &str) -> Option<NameMatch> {
    let query = query.trim().to_lowercase();
    let words: Vec<&str> = query.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    let path = path.to_lowercase();
    let name = path.rsplit('/').next().unwrap_or(path.as_str());
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    if name == query || (!stem.is_empty() && stem == query) {
        Some(NameMatch::Exact)
    } else if name.starts_with(query.as_str()) {
        Some(NameMatch::Prefix)
    } else if words.iter().all(|word| name.contains(word)) {
        Some(NameMatch::NameWords)
    } else if words.iter().all(|word| path.contains(word)) {
        Some(NameMatch::PathWords)
    } else {
        None
    }
}

/// How many characters a search hit's snippet holds at most.
pub const FILES_SNIPPET_CHARS: usize = 240;

/// The words of a file's `text` a search hit shows for `query`: from a
/// little before the first query word the text holds (compared in lower
/// case), else from its start; at most [`FILES_SNIPPET_CHARS`] characters,
/// on one line.
#[must_use]
pub fn text_excerpt(text: &str, query: &str) -> String {
    let start = first_word_at(text, query).map_or(0, |at| {
        text[..at]
            .char_indices()
            .rev()
            .nth(FILES_SNIPPET_CHARS / 5)
            .map_or(0, |(index, _)| index)
    });
    let window: String = text[start..].chars().take(FILES_SNIPPET_CHARS).collect();
    window.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Where the first of `query`'s words starts in `text`, when lower case
/// keeps the text's byte offsets.
fn first_word_at(text: &str, query: &str) -> Option<usize> {
    let lower = text.to_lowercase();
    if lower.len() != text.len() {
        return None;
    }
    query
        .split_whitespace()
        .filter_map(|word| lower.find(word.to_lowercase().as_str()))
        .min()
        .filter(|at| text.is_char_boundary(*at))
}
