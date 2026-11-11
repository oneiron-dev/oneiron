//! What an anchored comment reads of a live office body (FIX 2460; decks,
//! FIX 12264): the frontier a version projects, and the anchorable units at
//! a frontier. Entry: `Vault::office_body_units_in_txn`.

use std::collections::BTreeMap;

use super::*;
use oneiron_docedit::live::{LiveDeck, NodeId};
use oneiron_docedit::xlsx_body::XlsxAxisEdit;

/// A kept export's native and creation ids by model node (FIX 12346).
pub(crate) type HeldDeckIds = BTreeMap<u64, (Option<u32>, Option<String>)>;

/// One live body's anchorable units at a frontier.
pub(crate) enum OfficeBodyUnits {
    /// The blocks in order: the body's block id and its text.
    Docx(DocxUnits),
    /// The worksheets in order, by key and name, and the row and column
    /// edits since import, in order, by sheet key.
    Xlsx {
        sheets: Vec<(String, String)>,
        axes: Vec<(String, XlsxAxisEdit)>,
    },
    /// The deck's slides and shapes by node id.
    Pptx(DeckUnits),
}

/// A document's body units and separately scoped story paragraphs, including
/// direct story-table cell paragraphs.
pub(crate) struct DocxUnits {
    pub(crate) blocks: Vec<(String, String)>,
    pub(crate) stories: Vec<DocxStoryUnits>,
}

/// One actual native story, with paragraph ids local to this scope.
pub(crate) struct DocxStoryUnits {
    pub(crate) scope: oneiron_docedit::docx_body::DocxStoryScope,
    pub(crate) paragraphs: Vec<(String, String)>,
}

impl DocxUnits {
    pub(crate) fn story(
        &self,
        scope: &oneiron_docedit::docx_body::DocxStoryScope,
    ) -> Option<&[(String, String)]> {
        let mut matches = self.stories.iter().filter(|story| &story.scope == scope);
        let story = matches.next()?;
        matches
            .next()
            .is_none()
            .then_some(story.paragraphs.as_slice())
    }
}

/// A live deck's slides and shapes at a frontier, each slide followed by
/// its shapes in tree order, and the version the deck is bound to there.
pub(crate) struct DeckUnits {
    /// The landed export the deck is bound to, else the imported version:
    /// the version whose file holds the ids its bindings name.
    pub(crate) bound: u64,
    pub(crate) nodes: Vec<DeckUnit>,
}

/// One slide or shape of a live deck.
pub(crate) struct DeckUnit {
    /// The node's model identity.
    pub(crate) node: u64,
    /// Its slide's model identity; its own for a slide.
    pub(crate) slide: u64,
    /// Its slide's 1-based position in the deck.
    pub(crate) position: u64,
    /// The slide part, native id and creation id it holds in the bound
    /// version; `None` for a node born in the body since.
    pub(crate) binding: Option<(String, Option<u32>, Option<String>)>,
}

impl DeckUnits {
    fn of(deck: &LiveDeck, bound: u64) -> Self {
        let slides = deck
            .nodes
            .get(&NodeId(0))
            .map(|root| root.children.clone())
            .unwrap_or_default();
        let mut nodes = Vec::new();
        for (position, slide) in (1_u64..).zip(slides) {
            for node in std::iter::once(slide).chain(deck.descendants(slide)) {
                let binding = deck
                    .nodes
                    .get(&node)
                    .and_then(|found| found.binding.as_ref())
                    .map(|binding| {
                        (
                            binding.slide_part.clone(),
                            binding.native_id,
                            binding.creation_id.clone(),
                        )
                    });
                nodes.push(DeckUnit {
                    node: node.0,
                    slide: slide.0,
                    position,
                    binding,
                });
            }
        }
        Self { bound, nodes }
    }
}

impl Vault {
    /// Every artifact with a live body.
    pub(crate) fn office_bodies_in_txn(&self, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
        Ok(SOURCES
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(artifact, _)| artifact)
            .collect())
    }

    /// The artifact's newest export: its version and the body frontier it
    /// projects, read where its rebinding left it (`export_frontier`).
    pub(crate) fn office_body_latest_export_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        let mut exports = EXPORTS.iter_rev_from(&self.store, txn, artifact.as_bytes())?;
        Ok(exports
            .next()
            .transpose()?
            .map(|(_, record)| (record.version, export_frontier(record))))
    }

    /// The body frontier whose projection `version` holds: the import's for
    /// the imported version, an export's for the version it landed, read
    /// where its rebinding left it (`export_frontier`). `None` when the
    /// artifact has no live body or the body never held it.
    pub(crate) fn office_body_frontier_of_version_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(source) = SOURCES.get(&self.store, txn, artifact)? else {
            return Ok(None);
        };
        if version == source.source_version {
            return Ok(Some(self.head_in_txn(txn, artifact)?.import_frontier));
        }
        Ok(EXPORTS
            .get(&self.store, txn, &version_key(artifact, version))?
            .map(export_frontier))
    }

    /// The ids a kept deck export held when its Keep did not bind the deck
    /// (FIX 12346). `None` for every other export and for old records.
    pub(crate) fn office_body_held_ids_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        version: u64,
    ) -> Result<Option<HeldDeckIds>> {
        Ok(EXPORTS
            .get(&self.store, txn, &version_key(artifact, version))?
            .and_then(|record| record.held_ids)
            .map(|ids| {
                ids.into_iter()
                    .map(|id| (id.node, (id.native_id, id.creation_id)))
                    .collect()
            }))
    }

    /// The head frontier of the artifact's live body; `None` for no body.
    pub(crate) fn office_body_frontier_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        match SOURCES.get(&self.store, txn, artifact)? {
            Some(_) => Ok(Some(self.head_in_txn(txn, artifact)?.frontier)),
            None => Ok(None),
        }
    }

    /// The units of the artifact's live body at frontier `at`; `None` for no
    /// body.
    pub(crate) fn office_body_units_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        at: &[u8],
    ) -> Result<Option<OfficeBodyUnits>> {
        let Some(source) = SOURCES.get(&self.store, txn, artifact)? else {
            return Ok(None);
        };
        let (_, doc) = self.loro_body(txn, artifact, source.kind, Some(at))?;
        Ok(Some(match source.kind {
            OfficeBodyKind::Docx => {
                let body = docx::read(&doc)?;
                OfficeBodyUnits::Docx(DocxUnits {
                    blocks: body
                        .blocks
                        .into_iter()
                        .map(|block| (block.id, block.text))
                        .collect(),
                    stories: body
                        .stories
                        .into_iter()
                        .map(|story| DocxStoryUnits {
                            scope: story.scope,
                            paragraphs: story
                                .paragraphs
                                .into_iter()
                                .map(|paragraph| (paragraph.id, paragraph.text))
                                .chain(
                                    story
                                        .tables
                                        .into_iter()
                                        .flat_map(|table| table.cells)
                                        .flat_map(|cell| cell.paragraphs)
                                        .map(|paragraph| (paragraph.id, paragraph.text)),
                                )
                                .collect(),
                        })
                        .collect(),
                })
            }
            OfficeBodyKind::Xlsx => {
                let body = xlsx::read(&doc)?;
                OfficeBodyUnits::Xlsx {
                    sheets: body
                        .sheets
                        .into_iter()
                        .map(|sheet| (sheet.key, sheet.name))
                        .collect(),
                    axes: body.axes,
                }
            }
            OfficeBodyKind::Pptx => {
                let (deck, landed) = super::pptx::deck_with_binding(&doc)?;
                OfficeBodyUnits::Pptx(DeckUnits::of(
                    &deck,
                    landed.unwrap_or(source.source_version),
                ))
            }
        }))
    }
}

/// The frontier a comment reads an export's body at: the one its rebinding
/// left when it has one (FIX 12325), else the one it projects. A deck there
/// holds the same slides and shapes, bound to the export: each node's
/// binding names its ids in that version, whichever version the head is
/// bound to now.
fn export_frontier(record: OfficeBodyExportRecord) -> Vec<u8> {
    record.rebind_frontier.unwrap_or(record.frontier)
}
