//! Structural document segments used by indexing and birth fingerprints.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsSegment {
    pub section: String,
    pub block: String,
    pub text: String,
}
/// The same structural units feed indexing, summaries and blob fingerprints.
pub fn docs_semantic_segments(text: &str) -> Vec<DocsSegment> {
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut section = 0usize;
    let mut occurrences = std::collections::BTreeMap::new();
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|text| {
            if text.starts_with('#') {
                section += 1;
            }
            let digest = blake3::hash(text.as_bytes()).to_hex().to_string();
            let occurrence = occurrences.entry(digest.clone()).or_insert(0usize);
            let block = format!("{digest}:{occurrence}");
            *occurrence += 1;
            DocsSegment {
                section: section.to_string(),
                block,
                text: text.to_owned(),
            }
        })
        .collect()
}
