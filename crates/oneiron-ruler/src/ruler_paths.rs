//! The ruler paths: commits that touch them cannot be judged by the ruler (RESEARCH-0651 Tier 0).
//!
//! A candidate whose commit changes any ruler path cannot be judged by the
//! ruler it changed: `scorecard compare --repo` reads the ruler paths file at
//! the BASE commit and rejects the candidate. The shipped list is compiled in;
//! the engine reads the file at the base commit instead.

use thiserror::Error;

/// The file's path inside the repository.
pub const RULER_PATHS_FILE: &str = "crates/oneiron-ruler/RULER-PATHS.txt";
/// The shipped list, compiled in (include_str!("../RULER-PATHS.txt")).
pub const SHIPPED_RULER_PATHS: &str = include_str!("../RULER-PATHS.txt");

/// The parsed ruler paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulerPaths {
    /// The entries in file order.
    entries: Vec<String>,
}

impl RulerPaths {
    /// Parses the ruler paths file.
    ///
    /// Each line is trimmed; blank lines and lines starting with '#' are
    /// skipped. Refuse (RulerPathsError) an entry that starts with '/',
    /// contains a "..", "\\" or "./" component, or an empty list (`Empty`).
    pub fn parse(text: &str) -> Result<Self, RulerPathsError> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            if !is_valid_entry(entry) {
                return Err(RulerPathsError::BadEntry {
                    entry: entry.to_owned(),
                });
            }
            entries.push(entry.to_owned());
        }
        if entries.is_empty() {
            return Err(RulerPathsError::Empty);
        }
        Ok(Self { entries })
    }

    /// The entries in file order.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// True when the ruler paths cover `path`.
    ///
    /// An entry ending in '/' matches by prefix; any other entry matches only
    /// the identical path.
    pub fn matches(&self, path: &str) -> bool {
        self.entries.iter().any(|entry| {
            if entry.ends_with('/') {
                path.starts_with(entry.as_str())
            } else {
                path == entry.as_str()
            }
        })
    }

    /// The changed paths that match, sorted and deduplicated.
    pub fn touched<S: AsRef<str>>(&self, changed: &[S]) -> Vec<String> {
        let mut hits = Vec::new();
        for path in changed {
            let text = path.as_ref();
            if self.matches(text) {
                hits.push(text.to_owned());
            }
        }
        hits.sort();
        hits.dedup();
        hits
    }
}

/// Every way the ruler paths can fail to parse.
#[derive(Debug, Error)]
pub enum RulerPathsError {
    /// The file holds no entries.
    #[error("no ruler paths")]
    Empty,
    /// An entry is absolute or escapes its directory.
    #[error("bad ruler path entry: {entry}")]
    BadEntry {
        /// The bad entry.
        entry: String,
    },
}

/// True when the entry is relative and stays inside the repository.
fn is_valid_entry(entry: &str) -> bool {
    if entry.starts_with('/') {
        return false;
    }
    if entry.contains('\\') {
        return false;
    }
    !entry
        .split('/')
        .any(|component| component == ".." || component == ".")
}
