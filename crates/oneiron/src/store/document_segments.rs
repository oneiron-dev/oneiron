//! Structural document segments used by indexing and birth fingerprints.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsSegment {
    pub section: String,
    pub block: String,
    pub text: String,
}
/// The most bytes of text one segment carries into its ASSET_TEXT payload:
/// the store's 64 KiB body chunk. A longer structural unit is split.
pub const DOCS_SEGMENT_MAX_BYTES: usize = 64 * 1024;

/// The same structural units feed indexing, summaries and blob fingerprints.
/// A unit is its block `{content hash}:{occurrence}`. A unit longer than
/// [`DOCS_SEGMENT_MAX_BYTES`] becomes pieces `{content hash}:{occurrence}:{index}`
/// that concatenate back to it, so an unchanged unit names the same pieces on
/// every import.
pub fn docs_semantic_segments(text: &str) -> Vec<DocsSegment> {
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut section = 0usize;
    let mut occurrences = std::collections::BTreeMap::new();
    let mut segments = Vec::new();
    for unit in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        if unit.starts_with('#') {
            section += 1;
        }
        let digest = blake3::hash(unit.as_bytes()).to_hex().to_string();
        let occurrence = occurrences.entry(digest.clone()).or_insert(0usize);
        let block = format!("{digest}:{occurrence}");
        *occurrence += 1;
        let pieces = bounded_pieces(unit);
        if pieces.len() == 1 {
            segments.push(DocsSegment {
                section: section.to_string(),
                block,
                text: unit.to_owned(),
            });
            continue;
        }
        for (index, piece) in pieces.into_iter().enumerate() {
            segments.push(DocsSegment {
                section: section.to_string(),
                block: format!("{block}:{index}"),
                text: piece.to_owned(),
            });
        }
    }
    segments
}

/// `unit` in pieces of at most [`DOCS_SEGMENT_MAX_BYTES`], each ending after
/// the last line break in its second half, else the last space there, else
/// at the last character boundary that fits.
fn bounded_pieces(unit: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut rest = unit;
    while rest.len() > DOCS_SEGMENT_MAX_BYTES {
        let mut limit = DOCS_SEGMENT_MAX_BYTES;
        while !rest.is_char_boundary(limit) {
            limit -= 1;
        }
        let window = &rest[..limit];
        let half = limit / 2;
        let cut = [b'\n', b' ']
            .into_iter()
            .find_map(|separator| {
                window
                    .bytes()
                    .rposition(|byte| byte == separator)
                    .filter(|at| *at >= half)
            })
            .map_or(limit, |at| at + 1);
        let (piece, tail) = rest.split_at(cut);
        pieces.push(piece);
        rest = tail;
    }
    pieces.push(rest);
    pieces
}
