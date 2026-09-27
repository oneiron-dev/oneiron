//! Read-only knowledge ladder. Search shows summaries, never expanded source text.
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::gate::RetrievalFilter;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_SUMMARY};
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocsSummaryHit {
    pub reference: String,
    pub entity_type: u8,
    pub rank_score: f32,
    /// Only summary hits contain text. Chunks require an explicit expand call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocsExpansionLevel {
    Summary,
    Span,
    Section,
    FullText,
    RawAsset,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocsExpansion {
    pub level: DocsExpansionLevel,
    pub text: String,
    /// The next rung is offered as a ref, not automatically read.
    pub next_ref: Option<String>,
    /// Only the final rung carries source metadata; full text is never a search hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<serde_json::Value>,
}

fn docs_filter(kinds: impl IntoIterator<Item = u8>) -> RetrievalFilter {
    RetrievalFilter {
        entity_types: Some(kinds.into_iter().collect::<BTreeSet<_>>()),
        ..Default::default()
    }
}

fn invalid_ref() -> Error {
    Error::InvalidConfig("invalid docs expansion reference".into())
}

fn text(value: &serde_json::Value) -> Result<&str> {
    value["text"].as_str().ok_or_else(invalid_ref)
}

impl ScopedRead<'_> {
    /// Fuse lexical and (when supplied by the caller) semantic ranks across
    /// summary and chunk indexes. A conceptual/vector match favors the summary;
    /// an exact text match can put a chunk first. No source body is expanded.
    pub fn search_docs_summaries(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<ScopedReadResult<Vec<DocsSummaryHit>>> {
        self.search_docs_summaries_with_vector(query, None, limit)
    }

    pub fn search_docs_summaries_with_vector(
        &self,
        query: &str,
        vector: Option<&[f32]>,
        limit: usize,
    ) -> Result<ScopedReadResult<Vec<DocsSummaryHit>>> {
        let requested = docs_filter([ENTITY_TYPE_SUMMARY, ENTITY_TYPE_ASSET_TEXT]);
        let mut ranks = BTreeMap::<EntityId, (u8, f32)>::new();
        let mut suppressed = 0usize;
        // The SUMMARY kind is shared with session and DAG producers. Fetch the
        // complete bounded index candidate set so those rows cannot fill the
        // page before document membership is checked below.
        let candidates_limit =
            self.vault()
                .scoped_read_search_candidate_limit(limit, true, vector.is_some())?;
        // Separate kind lanes avoid a dominant index hiding candidates from the
        // other level before fusion. Distinct lexical/vector ranks can accumulate
        // on the *same* entity, unlike two disjoint kind-only lists.
        for kind in [ENTITY_TYPE_SUMMARY, ENTITY_TYPE_ASSET_TEXT] {
            let kind_filter = docs_filter([kind]);
            for semantic in [false, true] {
                let results = if semantic {
                    let Some(vector) = vector else { continue };
                    self.search_vector(vector, candidates_limit, Some(&kind_filter))?
                } else {
                    self.search_text(query, candidates_limit, Some(&kind_filter))?
                };
                suppressed = suppressed.saturating_add(results.receipt.suppressed_count);
                let weight = match (kind, semantic) {
                    (ENTITY_TYPE_SUMMARY, true) => 1.4,
                    (ENTITY_TYPE_SUMMARY, false) => 1.1,
                    _ => 1.0,
                };
                for (rank, row) in results.value.into_iter().enumerate() {
                    ranks.entry(row.id).or_insert((kind, 0.0)).1 +=
                        weight / (60.0 + rank as f32 + 1.0);
                }
            }
        }
        let candidates = ranks
            .iter()
            .map(|(id, (_, score))| crate::ScoredEntity {
                id: *id,
                score: *score,
            })
            .collect();
        let filtered = self.filter_scored_entities_requested(candidates, Some(&requested))?;
        let mut receipt = filtered.receipt;
        receipt.add_suppressed(suppressed);
        let mut rows = filtered.value;
        rows.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| {
                    (ranks[&b.id].0 == ENTITY_TYPE_SUMMARY)
                        .cmp(&(ranks[&a.id].0 == ENTITY_TYPE_SUMMARY))
                })
                .then_with(|| a.id.cmp(&b.id))
        });
        // Both kind bytes are shared with unrelated producers. Read each
        // candidate through the scoped point door before applying the page
        // limit. Only summary text, never chunk text, enters the response.
        let ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
        let bodies = self.get_entities_parts_with_receipt(&ids, Some(&requested))?;
        receipt.restrict_with(&bodies.receipt);
        let mut parts = ids
            .into_iter()
            .zip(bodies.value)
            .filter_map(|(id, part)| part.map(|part| (id, part)))
            .collect::<BTreeMap<_, _>>();
        let mut value = Vec::new();
        for row in rows {
            let kind = ranks[&row.id].0;
            let Some((actual_kind, _, body)) = parts.remove(&row.id) else {
                continue;
            };
            if actual_kind != kind {
                continue;
            }
            let decoded = crate::batch::export::redacted_memory_body(&body);
            let summary = if kind == ENTITY_TYPE_SUMMARY {
                // Session `content` and DAG scope `text` are valid SUMMARY
                // rows, but not derived document units.
                if decoded["derivation"]["derived_kind"] != "summary"
                    || decoded["derivation"]["source"] != "imported"
                    || decoded["derivation"]["source_ref"].as_str().is_none()
                {
                    continue;
                }
                let Some(text) = decoded["text"].as_str() else {
                    continue;
                };
                Some(text.to_owned())
            } else {
                // OCR and other ASSET_TEXT producers have no document
                // asset/section ref. Do not offer a ref the ladder cannot open.
                if decoded["source"] != "imported"
                    || decoded["text"].as_str().is_none()
                    || decoded["asset_ref"]
                        .as_str()
                        .is_none_or(|asset| EntityId::from_hex(asset).is_err())
                    || decoded["section"]
                        .as_str()
                        .is_none_or(|section| section.parse::<usize>().is_err())
                {
                    continue;
                }
                None
            };
            if value.len() == limit {
                break;
            }
            value.push(DocsSummaryHit {
                reference: row.id.to_hex(),
                entity_type: kind,
                rank_score: row.score,
                summary,
            });
        }
        Ok(ScopedReadResult { value, receipt })
    }

    /// The old point hydration door stays available for existing callers.
    /// New agents use `expand_doc_ladder_ref` for the explicit next-rung refs.
    pub fn expand_doc_ref(
        &self,
        reference: &str,
    ) -> Result<ScopedReadResult<Option<serde_json::Value>>> {
        let id = EntityId::from_hex(reference)?;
        let result = self.get_entity_parts_with_receipt(&id, None)?;
        let value = result
            .value
            .map(|(_, _, body)| crate::batch::export::redacted_memory_body(&body));
        Ok(ScopedReadResult {
            receipt: result.receipt,
            value,
        })
    }

    /// An agent chooses each ref. A summary offers a span; the span offers a
    /// section; the section offers full text; full text offers the raw asset.
    /// Every rung uses the scoped point-read door, including synthetic refs.
    pub fn expand_doc_ladder_ref(
        &self,
        reference: &str,
    ) -> Result<ScopedReadResult<Option<DocsExpansion>>> {
        let (id, rung) = if let Some(rest) = reference.strip_prefix("doc-section:") {
            let (id, section) = rest.split_once(':').ok_or_else(invalid_ref)?;
            if section.is_empty() || !section.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_ref());
            }
            (
                EntityId::from_hex(id)?,
                Some((DocsExpansionLevel::Section, section)),
            )
        } else if let Some(rest) = reference.strip_prefix("doc-text:") {
            (
                EntityId::from_hex(rest)?,
                Some((DocsExpansionLevel::FullText, "")),
            )
        } else {
            (EntityId::from_hex(reference)?, None)
        };
        let result = self.get_entity_parts_with_receipt(&id, None)?;
        let Some((kind, _, body)) = result.value else {
            return Ok(ScopedReadResult {
                value: None,
                receipt: result.receipt,
            });
        };
        let data = crate::batch::export::redacted_memory_body(&body);
        let expanded = match (kind, rung) {
            (ENTITY_TYPE_SUMMARY, None) if data["derivation"]["derived_kind"] == "summary" => {
                DocsExpansion {
                    level: DocsExpansionLevel::Summary,
                    text: text(&data)?.to_owned(),
                    next_ref: Some(
                        data["derivation"]["source_ref"]
                            .as_str()
                            .ok_or_else(invalid_ref)?
                            .to_owned(),
                    ),
                    asset: None,
                }
            }
            (ENTITY_TYPE_ASSET_TEXT, None) => {
                let asset = data["asset_ref"].as_str().ok_or_else(invalid_ref)?;
                let section = data["section"].as_str().ok_or_else(invalid_ref)?;
                DocsExpansion {
                    level: DocsExpansionLevel::Span,
                    text: text(&data)?.to_owned(),
                    next_ref: Some(format!("doc-section:{asset}:{section}")),
                    asset: None,
                }
            }
            (ENTITY_TYPE_ASSET, Some((DocsExpansionLevel::Section, section))) => {
                let spans = super::docs_semantic_segments(text(&data)?)
                    .into_iter()
                    .filter(|span| span.section == section)
                    .map(|span| span.text)
                    .collect::<Vec<_>>();
                if spans.is_empty() {
                    return Err(invalid_ref());
                }
                DocsExpansion {
                    level: DocsExpansionLevel::Section,
                    text: spans.join("\n\n"),
                    next_ref: Some(format!("doc-text:{}", id.to_hex())),
                    asset: None,
                }
            }
            (ENTITY_TYPE_ASSET, Some((DocsExpansionLevel::FullText, _))) => DocsExpansion {
                level: DocsExpansionLevel::FullText,
                text: text(&data)?.to_owned(),
                next_ref: Some(id.to_hex()),
                asset: None,
            },
            (ENTITY_TYPE_ASSET, None) => DocsExpansion {
                level: DocsExpansionLevel::RawAsset,
                text: text(&data)?.to_owned(),
                next_ref: None,
                asset: Some(data),
            },
            _ => return Err(invalid_ref()),
        };
        Ok(ScopedReadResult {
            value: Some(expanded),
            receipt: result.receipt,
        })
    }
}
