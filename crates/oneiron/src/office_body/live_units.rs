//! A live body's position when an ask read its artifact, and the units an
//! edit never exported changed since (OF-506, FIX 2115).
//! Entry: `Vault::office_body_pin`.
//!
//! An ask reads the artifact's head version, and a person may go on editing
//! the live body without exporting it, which moves no version. So each ask
//! pins the body's frontier and commit count beside the version it read. A
//! held answer's split and a standing question's arrival read the body at
//! that frontier and at its head, and compare the units the ask read: a
//! paragraph's text, kind and lock; a sheet's cells, its rows and columns;
//! what a slide shows; a folder file whole. An ask made before the body was
//! imported compares against the body as imported.
//!
//! An ask of an artifact that has a live body reads its units there, at the
//! head, with the pin it reads them at (FIX 11981): a sheet's cells, a
//! document's paragraphs, a file's whole text, a deck as it renders.
//!
//! An export version holds the body as it stood at the frontier its record
//! names, so the same units compare up to that frontier in place of the
//! head when a split asks what an export changed (FIX 12017).
//!
//! A workbook's formula cells are read as an export would compute them from
//! the cells of the same read ([`super::live_recalc`], FIX 11982), so a live
//! edit to a formula's inputs changes the formula cell, and an ask reads the
//! value the export of what it read lands (FIX 12052). Each live read
//! recalculates at the read's time in UTC; the export-frontier end of a
//! compare against the newest export recalculates at that export's own
//! recorded clock (FIX 12183).

use super::*;
use crate::edit_roundtrip::{CellRef, CellValue};
use crate::secret_custody::SecretSight;
use oneiron_docedit::live::{DeckNode, LiveDeck, NodeId, NodeKind, TextBody};
use std::collections::BTreeMap;

/// Where one live office body stood: its head's frontier and the commits on
/// it so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LivePin {
    pub frontier: Vec<u8>,
    pub commits: u64,
}

/// How one unit fares between a pinned frontier and the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveChange {
    Changed,
    Gone,
}

/// Each unit's content at a pinned frontier and at the head, by its id.
pub(crate) struct LiveUnits<K: Ord> {
    then: BTreeMap<K, [u8; 32]>,
    now: BTreeMap<K, [u8; 32]>,
}

impl<K: Ord> LiveUnits<K> {
    /// How `unit` fares. A unit the body did not hold at the pin and does not
    /// hold now was not changed by the body's edits.
    pub(crate) fn change(&self, unit: &K) -> Option<LiveChange> {
        match (self.then.get(unit), self.now.get(unit)) {
            (None, None) => None,
            (Some(_), None) => Some(LiveChange::Gone),
            (was, now) if was == now => None,
            _ => Some(LiveChange::Changed),
        }
    }
}

/// A sheet's cells, by `(row, col)`: each one's value and formula, a
/// formula's value as an export would compute it.
type SheetCells = BTreeMap<(u32, u32), (XlsxValue, Option<String>)>;

/// One sheet of a live workbook, by name, at a pinned frontier and at the
/// head; `None` where the body held no sheet of that name.
pub(crate) struct LiveSheet {
    /// The name moved to another sheet, or the sheet's rows or columns moved,
    /// so no address names the cell it named at the pin.
    shifted: bool,
    then: Option<SheetCells>,
    now: Option<SheetCells>,
}

impl LiveSheet {
    /// How the sheet fares as a whole: gone from the head, or every address
    /// in doubt.
    pub(crate) fn whole(&self) -> Option<LiveChange> {
        match (&self.then, &self.now) {
            (None, None) => None,
            (Some(_), None) => Some(LiveChange::Gone),
            (None, Some(_)) => Some(LiveChange::Changed),
            (Some(_), Some(_)) => self.shifted.then_some(LiveChange::Changed),
        }
    }

    /// Whether the cell at `col`, `row` reads otherwise at the head.
    pub(crate) fn differs(&self, col: u32, row: u32) -> bool {
        match (&self.then, &self.now) {
            (Some(then), Some(now)) => {
                self.shifted || then.get(&(row, col)) != now.get(&(row, col))
            }
            (None, None) => false,
            _ => true,
        }
    }
}

impl Vault {
    /// `artifact`'s live body where it stands now; `None` when it has none.
    pub(crate) fn office_body_pin(&self, artifact: &EntityId) -> Result<Option<LivePin>> {
        {
            let txn = self.store.env.read_txn()?;
            if !SOURCES.contains(&self.store, &txn, artifact)? {
                return Ok(None);
            }
        }
        Ok(found(self.typed_body_head(artifact))?.map(|head| LivePin {
            frontier: head.frontier,
            commits: head.commits,
        }))
    }

    /// [`Self::office_body_pin`] read in `txn`, with the time its newest
    /// commit was made, or a merged fork's commits landed if that is later:
    /// an edit's quiet interval runs from it (FIX 11983).
    pub(crate) fn office_body_pin_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<(LivePin, u64)>> {
        let Some(source) = SOURCES.get(&self.store, txn, artifact)? else {
            return Ok(None);
        };
        let Some((head, doc)) = found(typed_body_in_txn(
            &self.store,
            txn,
            artifact,
            source.kind.schema(),
            None,
        ))?
        else {
            return Ok(None);
        };
        let at = doc
            .oplog_frontiers()
            .iter()
            .filter_map(|id| doc.get_change(id))
            .filter_map(|change| u64::try_from(change.timestamp).ok())
            .chain(head.landed_at)
            .max()
            .unwrap_or(0);
        Ok(Some((
            LivePin {
                frontier: head.frontier,
                commits: head.commits,
            },
            at,
        )))
    }

    /// The paragraphs of `artifact`'s live body at `then` and at its head,
    /// each by its text, kind and lock. `None` when the body has not moved
    /// since `then`.
    pub(crate) fn live_paragraphs(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
    ) -> Result<Option<LiveUnits<String>>> {
        self.live_paragraphs_until(artifact, then, None)
    }

    /// [`Self::live_paragraphs`] at the frontier `until` in place of the head
    /// when one is given.
    pub(crate) fn live_paragraphs_until(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
        until: Option<&[u8]>,
    ) -> Result<Option<LiveUnits<String>>> {
        let Some((was, now)) = self.live_span(artifact, OfficeBodyKind::Docx, then, until)? else {
            return Ok(None);
        };
        let blocks = |doc: &LoroDoc| -> Result<BTreeMap<String, [u8; 32]>> {
            Ok(docx::read(doc)?
                .blocks
                .into_iter()
                .map(|block| {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(format!("{:?}|{}|", block.kind, block.locked).as_bytes());
                    hasher.update(block.text.as_bytes());
                    (block.id, *hasher.finalize().as_bytes())
                })
                .collect())
        };
        Ok(Some(LiveUnits {
            then: blocks(&was)?,
            now: blocks(&now)?,
        }))
    }

    /// The sheet named `sheet` of `artifact`'s live workbook at `then` and at
    /// its head. `None` when the body has not moved since `then`.
    pub(crate) fn live_sheet(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
        sheet: &str,
    ) -> Result<Option<LiveSheet>> {
        self.live_sheet_until(artifact, then, sheet, None)
    }

    /// [`Self::live_sheet`] against the export `until` names in place of the
    /// head: its frontier, with its record's version. The pin side
    /// recalculates at the read's time in UTC; the export side at the
    /// export's own recorded clock, or the read's time in UTC when the
    /// record keeps none (FIX 12183).
    pub(crate) fn live_sheet_until(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
        sheet: &str,
        until: Option<(&[u8], u64)>,
    ) -> Result<Option<LiveSheet>> {
        let frontier = until.map(|(frontier, _)| frontier);
        let Some((was, now)) =
            self.live_span(artifact, OfficeBodyKind::Xlsx, then, frontier)?
        else {
            return Ok(None);
        };
        let mut bodies = [xlsx::read(&was)?, xlsx::read(&now)?];
        match until {
            Some((_, version)) => {
                let at = self.now_recorded_at();
                let zone = OfficeRecalcZone::default();
                let (export_at, export_zone) = self
                    .office_body_export(artifact, version)?
                    .and_then(|record| record.recalc_clock())
                    .unwrap_or((at, OfficeRecalcZone::default()));
                self.live_recalc_until(
                    artifact,
                    Some(sheet),
                    &mut bodies,
                    at,
                    &zone,
                    export_at,
                    &export_zone,
                );
            }
            None => self.live_recalc(artifact, Some(sheet), &mut bodies),
        }
        let [was, now] = bodies;
        let named = |body: &XlsxBody| {
            body.sheets
                .iter()
                .find(|entry| entry.name == sheet)
                .map(|entry| {
                    let cells: SheetCells = entry
                        .cells
                        .iter()
                        .filter(|(_, cell)| {
                            cell.value != XlsxValue::Blank || cell.formula.is_some()
                        })
                        .map(|(at, cell)| (*at, (cell.value.clone(), cell.formula.clone())))
                        .collect();
                    (entry.key.clone(), cells)
                })
        };
        let axes = |body: &XlsxBody, key: &str| {
            body.axes
                .iter()
                .filter(|(owner, _)| owner == key)
                .map(|(_, edit)| *edit)
                .collect::<Vec<_>>()
        };
        let (then, now_sheet) = (named(&was), named(&now));
        let shifted = match (&then, &now_sheet) {
            (Some((was_key, _)), Some((now_key, _))) => {
                was_key != now_key || axes(&was, was_key) != axes(&now, now_key)
            }
            _ => false,
        };
        Ok(Some(LiveSheet {
            shifted,
            then: then.map(|(_, cells)| cells),
            now: now_sheet.map(|(_, cells)| cells),
        }))
    }

    /// What each slide of `artifact`'s live deck shows at `then` and at its
    /// head, or at the frontier `until` when one is given, by its slide part
    /// and slide id: the slide's tree, its texts and the parts it renders
    /// through. `None` when the deck has not moved since `then`.
    pub(crate) fn live_slides(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
        until: Option<&[u8]>,
    ) -> Result<Option<LiveUnits<(String, u32)>>> {
        if self
            .live_span(artifact, OfficeBodyKind::Pptx, then, until)?
            .is_none()
        {
            return Ok(None);
        }
        let at = match then {
            Some(pin) => pin.frontier.clone(),
            // No head row reads as unmoved, as `live_span` reads it.
            None => match self.office_body_head(artifact)? {
                Some(head) => head.import_frontier,
                None => return Ok(None),
            },
        };
        Ok(Some(LiveUnits {
            then: deck_slides(&self.read_pptx_body(artifact, Some(at.as_slice()))?.deck)?,
            now: deck_slides(&self.read_pptx_body(artifact, until)?.deck)?,
        }))
    }

    /// Whether `artifact`'s live body, of any kind, reads otherwise at its
    /// head than at `then`.
    pub(crate) fn live_body_changed(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
    ) -> Result<bool> {
        self.live_body_changed_until(artifact, then, None)
    }

    /// [`Self::live_body_changed`] at the frontier `until` in place of the
    /// head when one is given. A deck compares what its slides show, as a
    /// slide answer does: its nodes' bindings to the retained package move
    /// on every export's rebind and change nothing shown (FIX 12050).
    pub(crate) fn live_body_changed_until(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
        until: Option<&[u8]>,
    ) -> Result<bool> {
        let kind = {
            let txn = self.store.env.read_txn()?;
            match SOURCES.get(&self.store, &txn, artifact)? {
                Some(source) => source.kind,
                None => return Ok(false),
            }
        };
        if kind == OfficeBodyKind::Pptx {
            return Ok(self
                .live_slides(artifact, then, until)?
                .is_some_and(|slides| slides.then != slides.now));
        }
        Ok(self
            .live_span(artifact, kind, then, until)?
            .is_some_and(|(was, now)| was.get_deep_value() != now.get_deep_value()))
    }

    /// The cells of the sheet named `sheet` of `artifact`'s live workbook at
    /// its head, a formula's by the value an export would compute, with the
    /// pin they were read at. `None` when it has no live workbook; a sheet
    /// the body does not hold has no cells.
    pub(crate) fn live_head_cells(
        &self,
        artifact: &EntityId,
        sheet: &str,
    ) -> Result<Option<(LivePin, BTreeMap<CellRef, CellValue>)>> {
        let Some((OfficeBodyKind::Xlsx, pin, doc)) = self.live_head(artifact)? else {
            return Ok(None);
        };
        let mut bodies = [xlsx::read(&doc)?];
        self.live_recalc(artifact, Some(sheet), &mut bodies);
        let [body] = bodies;
        let cells: BTreeMap<CellRef, CellValue> = body
            .sheets
            .into_iter()
            .find(|entry| entry.name == sheet)
            .map(|entry| {
                entry
                    .cells
                    .into_iter()
                    .map(|((row, col), cell)| (CellRef { col, row }, cell_value(cell)))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some((pin, cells)))
    }

    /// The paragraphs of `artifact`'s live document at its head, with the pin
    /// they were read at. `None` when it has no live document.
    pub(crate) fn live_head_blocks(
        &self,
        artifact: &EntityId,
    ) -> Result<Option<(LivePin, Vec<BodyBlock>)>> {
        let Some((OfficeBodyKind::Docx, pin, doc)) = self.live_head(artifact)? else {
            return Ok(None);
        };
        Ok(Some((pin, docx::read(&doc)?.blocks)))
    }

    /// `artifact`'s live body at its head read whole, as a folder ask reads
    /// a file's text, with the pin it was read at: a document's paragraphs
    /// and table cells, a workbook's cells by address, a deck's texts in tree
    /// order. A reader `sight` does not let see a lifted secret reads its
    /// handle. `None` when it has no live body.
    pub(crate) fn live_head_text(
        &self,
        artifact: &EntityId,
        sight: SecretSight,
    ) -> Result<Option<(LivePin, String)>> {
        let Some((kind, pin, doc)) = self.live_head(artifact)? else {
            return Ok(None);
        };
        let text = match kind {
            OfficeBodyKind::Docx => docx::read(&doc)?
                .blocks
                .into_iter()
                .flat_map(|block| std::iter::once(block.text).chain(block.cells.into_values()))
                .filter(|text| !text.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n\n"),
            OfficeBodyKind::Xlsx => {
                let mut bodies = [xlsx::read(&doc)?];
                self.live_recalc(artifact, None, &mut bodies);
                let [body] = bodies;
                body.sheets
                    .iter()
                    .flat_map(|sheet| {
                        sheet.cells.values().filter_map(move |cell| {
                            let value = match &cell.value {
                                XlsxValue::Blank => return None,
                                XlsxValue::Number(number) => number.to_string(),
                                XlsxValue::Text(text) | XlsxValue::Error(text) => text.clone(),
                                XlsxValue::Bool(value) => value.to_string(),
                            };
                            Some(format!("{}!{}: {value}", sheet.name, cell.address))
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OfficeBodyKind::Pptx => {
                let deck = self
                    .read_pptx_body(artifact, Some(pin.frontier.as_slice()))?
                    .deck;
                deck.descendants(NodeId(0))
                    .iter()
                    .filter_map(|node| deck.texts.get(node).map(TextBody::plain))
                    .filter(|text| !text.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
        };
        let text = match sight {
            SecretSight::Masked => self
                .typed_body_lifted_keys(artifact)?
                .masked(&text)
                .unwrap_or(text),
            SecretSight::Owner | SecretSight::Granted => text,
        };
        Ok(Some((pin, text)))
    }

    /// `artifact`'s live deck projected at its head as an export would write
    /// it, nothing landed, with the pin read before it: what a re-ask renders
    /// and reads. `None` when it has no live deck, or the deck does not
    /// project, which leaves the ask on the head version as before.
    pub(crate) fn live_head_deck(&self, artifact: &EntityId) -> Result<Option<(LivePin, Vec<u8>)>> {
        {
            let txn = self.store.env.read_txn()?;
            if SOURCES
                .get(&self.store, &txn, artifact)?
                .is_none_or(|source| source.kind != OfficeBodyKind::Pptx)
            {
                return Ok(None);
            }
        }
        let Some(pin) = self.office_body_pin(artifact)? else {
            return Ok(None);
        };
        Ok(self
            .export_pptx_body(artifact)
            .ok()
            .map(|export| (pin, export.outcome.bytes)))
    }

    /// `artifact`'s live body at its head, its kind and its pin, read in one
    /// transaction. `None` when it has none.
    fn live_head(&self, artifact: &EntityId) -> Result<Option<(OfficeBodyKind, LivePin, LoroDoc)>> {
        let txn = self.store.env.read_txn()?;
        let Some(source) = SOURCES.get(&self.store, &txn, artifact)? else {
            return Ok(None);
        };
        let read = found(typed_body_in_txn(
            &self.store,
            &txn,
            artifact,
            source.kind.schema(),
            None,
        ))?;
        Ok(read.map(|(head, doc)| {
            let pin = LivePin {
                frontier: head.frontier,
                commits: head.commits,
            };
            (source.kind, pin, doc)
        }))
    }

    /// `artifact`'s live body of `kind` at `then` and at its head, or at the
    /// frontier `until` when one is given, when it moved between them. `None`
    /// when it has no such body, has not moved, or its history no longer
    /// reads at `then` or `until`, which compares as unmoved, as an unpinned
    /// body did before. With no pin, the body as imported stands for `then`.
    fn live_span(
        &self,
        artifact: &EntityId,
        kind: OfficeBodyKind,
        then: Option<&LivePin>,
        until: Option<&[u8]>,
    ) -> Result<Option<(LoroDoc, LoroDoc)>> {
        let txn = self.store.env.read_txn()?;
        if SOURCES
            .get(&self.store, &txn, artifact)?
            .is_none_or(|source| source.kind != kind)
        {
            return Ok(None);
        }
        let Some((head, now)) = found(typed_body_in_txn(
            &self.store,
            &txn,
            artifact,
            kind.schema(),
            None,
        ))?
        else {
            return Ok(None);
        };
        let end = until.unwrap_or(head.frontier.as_slice());
        let at = match then {
            Some(pin)
                if pin.frontier.as_slice() == end
                    && (until.is_some() || pin.commits == head.commits) =>
            {
                return Ok(None);
            }
            Some(pin) => pin.frontier.clone(),
            None if head.birth.as_slice() == end => return Ok(None),
            None => head.birth.clone(),
        };
        let read = |frontier: &[u8]| {
            typed_body_in_txn(&self.store, &txn, artifact, kind.schema(), Some(frontier))
                .ok()
                .flatten()
                .map(|(_, doc)| doc)
        };
        let now = match until {
            Some(until) => read(until),
            None => Some(now),
        };
        Ok(read(at.as_slice()).zip(now))
    }
}

/// Each slide of `deck` by its slide part and slide id, hashed over the
/// slide's node, every node under it with its text, and the deck's opaque
/// parts (masters, layouts, themes, media), which any slide may render
/// through. A node's binding to the retained package is left out: an
/// export's rebind moves it and changes nothing the slide shows (FIX 12017).
fn deck_slides(deck: &LiveDeck) -> Result<BTreeMap<(String, u32), [u8; 32]>> {
    let mut slides = BTreeMap::new();
    for (id, node) in &deck.nodes {
        let (NodeKind::Slide, Some(binding)) = (node.kind, &node.binding) else {
            continue;
        };
        let Some(sld_id) = binding.native_id else {
            continue;
        };
        let tree: Vec<_> = std::iter::once(*id)
            .chain(deck.descendants(*id))
            .map(|node| {
                let shown = deck.nodes.get(&node).map(|read| DeckNode {
                    binding: None,
                    ..read.clone()
                });
                (node, shown, deck.texts.get(&node))
            })
            .collect();
        let bytes = serde_json::to_vec(&(tree, &deck.opaque_parts))
            .map_err(|_| Error::InvariantViolation("live slide encoding"))?;
        slides.insert(
            (binding.slide_part.clone(), sld_id),
            *blake3::hash(&bytes).as_bytes(),
        );
    }
    Ok(slides)
}

/// A live cell as an ask reads a saved one: a formula by its computed
/// value.
fn cell_value(cell: BodyCell) -> CellValue {
    let value = match cell.value {
        XlsxValue::Blank => CellValue::Blank,
        XlsxValue::Number(number) => CellValue::Number(number),
        XlsxValue::Text(text) => CellValue::Text(text),
        XlsxValue::Bool(value) => CellValue::Bool(value),
        XlsxValue::Error(error) => CellValue::Error(error),
    };
    match cell.formula {
        Some(expr) => CellValue::Formula {
            expr,
            cached: Some(Box::new(value)),
        },
        None => value,
    }
}

/// `read` with a body that is gone, or whose artifact no longer stands, as
/// none.
fn found<T>(read: Result<Option<T>>) -> Result<Option<T>> {
    match read {
        Err(Error::EntityNotFound) => Ok(None),
        other => other,
    }
}
