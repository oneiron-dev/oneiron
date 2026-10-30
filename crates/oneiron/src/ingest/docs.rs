//! Export-seam docs normalization. Registry JSON and source bytes remain evidence, not instructions.
use super::{
    IngestError, IngestResult, IngestSource, NormalizedIngestBatch, NormalizedIngestEntity,
    NormalizedIngestRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const DOCS_EXPORT_SOURCE_ID: &str = "docs-export";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsExport {
    pub corpus_id: String,
    /// The PROJECT entity with role corpus that owns derived claims.
    pub project_id: crate::EntityId,
    pub registry: Value,
    pub pages: Vec<DocsPage>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsPage {
    pub page_id: String,
    pub path: String,
    pub text: String,
}
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
pub fn docs_extraction_id(corpus: &str, page: &str, span: &str) -> String {
    let mut h = blake3::Hasher::new();
    for part in ["docs-extraction:v1", corpus, page, span] {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().to_hex().to_string()
}
impl DocsExport {
    pub fn validate(&self) -> IngestResult<()> {
        let invalid = |path: &str| IngestError::InvalidDocumentField {
            source_id: DOCS_EXPORT_SOURCE_ID,
            path: path.to_owned(),
        };
        if self.corpus_id.trim().is_empty() || !self.registry.is_object() {
            return Err(invalid("corpus_id/registry"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for page in &self.pages {
            if page.page_id.trim().is_empty() || page.text.trim().is_empty() {
                return Err(invalid("page_id/text"));
            }
            if !ids.insert(&page.page_id) {
                return Err(IngestError::DuplicateId {
                    source_id: DOCS_EXPORT_SOURCE_ID,
                    kind: "page",
                    id: page.page_id.clone(),
                });
            }
        }
        Ok(())
    }
}
pub struct DocsExportSource;
impl IngestSource for DocsExportSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let document: DocsExport =
            serde_json::from_str(input).map_err(|error| IngestError::InvalidDocument {
                source_id: DOCS_EXPORT_SOURCE_ID,
                message: error.to_string(),
            })?;
        document.validate()?;
        let mut batch = NormalizedIngestBatch {
            source_id: DOCS_EXPORT_SOURCE_ID,
            records: Vec::new(),
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: None,
        };
        for page in document.pages {
            batch.entities.push(NormalizedIngestEntity {
                entity_type: crate::registry::ENTITY_TYPE_ASSET,
                body: page.text.clone(),
                recognizer_locality: None,
            });
            for segment in docs_semantic_segments(&page.text) {
                let id = docs_extraction_id(&document.corpus_id, &page.page_id, &segment.block);
                batch.records.push(NormalizedIngestRecord {
                    source_record_id: id,
                    thread_id: Some(page.page_id.clone()),
                    speaker: None,
                    occurred_at: None,
                    text: segment.text.clone(),
                });
                batch.entities.push(NormalizedIngestEntity {
                    entity_type: crate::registry::ENTITY_TYPE_ASSET_TEXT,
                    body: segment.text,
                    recognizer_locality: None,
                });
            }
        }
        Ok(batch)
    }
}
