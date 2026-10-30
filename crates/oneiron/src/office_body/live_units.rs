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

use super::*;
use oneiron_docedit::live::{LiveDeck, NodeKind};
use std::collections::BTreeMap;

/// Where one live office body stood: its head's frontier and the commits on
/// it so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A sheet's cells, by `(row, col)`: each one's value and formula.
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
    /// commit was made: an edit's quiet interval runs from it.
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
        let Some((was, now)) = self.live_span(artifact, OfficeBodyKind::Docx, then)? else {
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
        let Some((was, now)) = self.live_span(artifact, OfficeBodyKind::Xlsx, then)? else {
            return Ok(None);
        };
        let (was, now) = (xlsx::read(&was)?, xlsx::read(&now)?);
        let named = |body: &XlsxBody| {
            body.sheets.iter().find(|found| found.name == sheet).map(|found| {
                let cells: SheetCells = found
                    .cells
                    .iter()
                    .filter(|(_, cell)| cell.value != XlsxValue::Blank || cell.formula.is_some())
                    .map(|(at, cell)| (*at, (cell.value.clone(), cell.formula.clone())))
                    .collect();
                (found.key.clone(), cells)
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
    /// head, by its slide part and slide id: the slide's tree, its texts and
    /// the parts it renders through. `None` when the deck has not moved
    /// since `then`.
    pub(crate) fn live_slides(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
    ) -> Result<Option<LiveUnits<(String, u32)>>> {
        if self.live_span(artifact, OfficeBodyKind::Pptx, then)?.is_none() {
            return Ok(None);
        }
        let at = match then {
            Some(pin) => pin.frontier.clone(),
            None => self
                .office_body_head(artifact)?
                .ok_or(Error::EntityNotFound)?
                .import_frontier,
        };
        Ok(Some(LiveUnits {
            then: deck_slides(&self.read_pptx_body(artifact, Some(&at))?.deck)?,
            now: deck_slides(&self.read_pptx_body(artifact, None)?.deck)?,
        }))
    }

    /// Whether `artifact`'s live body, of any kind, reads otherwise at its
    /// head than at `then`.
    pub(crate) fn live_body_changed(
        &self,
        artifact: &EntityId,
        then: Option<&LivePin>,
    ) -> Result<bool> {
        let kind = {
            let txn = self.store.env.read_txn()?;
            match SOURCES.get(&self.store, &txn, artifact)? {
                Some(source) => source.kind,
                None => return Ok(false),
            }
        };
        Ok(self
            .live_span(artifact, kind, then)?
            .is_some_and(|(was, now)| was.get_deep_value() != now.get_deep_value()))
    }

    /// `artifact`'s live body of `kind` at `then` and at its head, when it
    /// moved since. `None` when it has no such body, has not moved, or its
    /// history no longer reads at `then`, which compares as unmoved, as an
    /// unpinned body did before. With no pin, the body as imported stands
    /// for `then`.
    fn live_span(
        &self,
        artifact: &EntityId,
        kind: OfficeBodyKind,
        then: Option<&LivePin>,
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
        let at = match then {
            Some(pin) if pin.frontier == head.frontier && pin.commits == head.commits => {
                return Ok(None);
            }
            Some(pin) => pin.frontier.clone(),
            None if head.frontier == head.birth => return Ok(None),
            None => head.birth,
        };
        let was = typed_body_in_txn(&self.store, &txn, artifact, kind.schema(), Some(&at))
            .ok()
            .flatten();
        Ok(was.map(|(_, was)| (was, now)))
    }
}

/// Each slide of `deck` by its slide part and slide id, hashed over the
/// slide's node, every node under it with its text, and the deck's opaque
/// parts (masters, layouts, themes, media), which any slide may render
/// through.
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
            .map(|node| (node, deck.nodes.get(&node), deck.texts.get(&node)))
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

/// `read` with a body that is gone, or whose artifact no longer stands, as
/// none.
fn found<T>(read: Result<Option<T>>) -> Result<Option<T>> {
    match read {
        Err(Error::EntityNotFound) => Ok(None),
        other => other,
    }
}
