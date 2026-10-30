//! The batch door's file mark (owner ruling C2) for a carrier's stored text
//! no door rewrites (OF-067, Engine ruling G2 = b): a code file at a tested
//! frontier, a typed body's text, an entity document's text. The text, its
//! operations and its hashes stay as they are. Each key the door's file rules
//! place goes to its own custody record (a value custody already holds keeps
//! its record), and each key's span is recorded under the text's hash, as a
//! file's is (`secret_custody::masked_files`).
//!
//! A reader other than the owner reads the text with each span as its handle
//! (`[secret sc12]`, owner ruling G04 = A); a granted agent reads a value
//! through its handle's reveal. An edit of that copy that carries a handle
//! back writes the value it stands for again, and one that deletes the
//! handle removes the secret.

use std::ops::Range;
use std::sync::Arc;

use heed::{RoTxn, RwTxn};

use super::super::shapes::HANDLE_OPEN;
use super::super::write_payload_hit;
use super::{Masker, put_file_marks_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::secret_custody::{CustodyWrite, KnownValues, masked_file_in_txn};
use crate::side_table::SideTableDecl;
use crate::store::Store;

/// Domain of the id a lifted carrier row's custody records name as where
/// their keys were found.
const CARRIER_ORIGIN: &[u8] = b"oneiron:secret-lift:carrier:v1";

/// What [`mark_carrier_text_in_txn`] found in a carrier's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierText {
    /// No hit the write door finds.
    Clean,
    /// Its keys were marked before.
    Marked,
    /// Its keys are marked now: the first key's reason.
    Minted(&'static str),
    /// A hit no span places: the door's reason. Nothing is minted.
    Unplaceable(&'static str),
}

/// Marks the keys in `text`, a carrier's stored text, in the caller's
/// transaction: each key the write door's file rules place goes to custody
/// (`origin` and `place` name where it was found), and their spans are
/// recorded under the text's hash. The copy with each key overwritten is read
/// again first; a hit it still holds mints nothing.
pub(crate) fn mark_carrier_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    origin: EntityId,
    place: &str,
    text: &[u8],
) -> Result<CarrierText> {
    let store = &vault.store;
    let hash = *blake3::hash(text).as_bytes();
    if masked_file_in_txn(store, txn, &hash)?.is_some() {
        return Ok(CarrierText::Marked);
    }
    let Some(hit) = write_payload_hit(text) else {
        return Ok(CarrierText::Clean);
    };
    let mut plan = Masker {
        mints: true,
        known: KnownValues::load_in_writer(store, txn)?.map(Arc::new),
        at: Some((origin, place.to_owned())),
        ..Masker::default()
    };
    let Some(copy) = plan.mark_file(origin, text)? else {
        return Ok(CarrierText::Unplaceable(hit));
    };
    if let Some(left) = write_payload_hit(&copy) {
        return Ok(CarrierText::Unplaceable(left));
    }
    let reason = plan
        .files
        .first()
        .and_then(|file| file.keys.first())
        .map_or(hit, |key| key.reason);
    let files = std::mem::take(&mut plan.files);
    let at = crate::ports::recorded_at_in_txn(store, txn)?;
    let minted = plan.mint(&CustodyWrite::of(vault), txn, at)?;
    put_file_marks_in_txn(store, txn, files, &minted, at)?;
    Ok(CarrierText::Minted(reason))
}

/// Whether [`mark_carrier_text_in_txn`] places each key in `text`, a
/// carrier's stored text with a hit no mark covers, by the door's file
/// rules: judged in a reader, so nothing is minted and nothing is marked
/// (FIX 8996). A key only custody's known values place reads as unplaced
/// here.
pub(crate) fn carrier_text_placeable(text: &[u8]) -> Result<bool> {
    let origin = EntityId::derive(CARRIER_ORIGIN, &[b"placeable".as_slice()])?;
    let mut plan = Masker {
        mints: true,
        at: Some((origin, "carrier".to_owned())),
        ..Masker::default()
    };
    Ok(plan
        .mark_file(origin, text)?
        .is_some_and(|copy| write_payload_hit(&copy).is_none()))
}

/// What a reader other than the owner reads in place of a string that
/// still holds a hit the write door finds once each lifted key reads as its
/// handle: the door's placeholder, which holds no value (FIX 8996).
const UNPLACED: &str = "[secret redacted]";

/// Each string in `value` the write door still finds a hit in, read whole
/// as [`UNPLACED`]: a key no mark places, masked for a reader other than
/// the owner (FIX 8996). `true` when one changed.
pub(crate) fn mask_unplaced_json(value: &mut serde_json::Value) -> bool {
    each_string(value, &|text| {
        write_payload_hit(text.as_bytes()).map(|_| UNPLACED.to_owned())
    })
}

impl CarrierText {
    /// The two outcomes of one row's texts as one: a hit left unplaced
    /// first, then a key marked now, then one marked before.
    const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unplaceable(reason), _) | (_, Self::Unplaceable(reason)) => {
                Self::Unplaceable(reason)
            }
            (Self::Minted(reason), _) | (_, Self::Minted(reason)) => Self::Minted(reason),
            (Self::Marked, _) | (_, Self::Marked) => Self::Marked,
            (Self::Clean, Self::Clean) => Self::Clean,
        }
    }
}

/// The write door's first hit in one of `texts`, a carrier row's stored
/// texts, that no mark covers yet.
pub(crate) fn carrier_texts_hit_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    texts: &[String],
) -> Result<Option<&'static str>> {
    for text in texts {
        let Some(hit) = write_payload_hit(text.as_bytes()) else {
            continue;
        };
        if masked_file_in_txn(store, txn, blake3::hash(text.as_bytes()).as_bytes())?.is_none() {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

/// [`mark_carrier_text_in_txn`] over each of `texts`, the stored texts of
/// `table`'s row `key`, as one outcome. Each key's custody record names the
/// row as where it was found.
pub(crate) fn mark_carrier_texts_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    table: &SideTableDecl,
    key: &[u8],
    texts: &[String],
) -> Result<CarrierText> {
    let origin = EntityId::derive(CARRIER_ORIGIN, &[table.name.as_bytes(), key])?;
    let place = format!("carrier:{}", table.name);
    let mut outcome = CarrierText::Clean;
    for text in texts {
        outcome = outcome.and(mark_carrier_text_in_txn(
            vault,
            txn,
            origin,
            &place,
            text.as_bytes(),
        )?);
    }
    Ok(outcome)
}

/// The keys a carrier's lifted texts hold: each value, and the handle that
/// stands for it (`[secret sc12]`), longest value first.
#[derive(Debug, Default)]
pub(crate) struct LiftedKeys(Vec<(String, String)>);

impl LiftedKeys {
    /// The keys the marks of `texts` name, each text a carrier's stored text.
    pub(crate) fn of_in_txn(
        store: &Store,
        txn: &RoTxn<'_>,
        texts: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self> {
        let mut keys = Vec::new();
        for text in texts {
            let text = text.as_ref();
            let hash = blake3::hash(text.as_bytes());
            let Some(file) = masked_file_in_txn(store, txn, hash.as_bytes())? else {
                continue;
            };
            for key in &file.keys {
                let value = usize::try_from(key.start)
                    .ok()
                    .zip(usize::try_from(key.end).ok())
                    .and_then(|(start, end)| text.get(start..end))
                    .ok_or(Error::CorruptedIndex("a lifted text's key span"))?;
                if value.is_empty() || keys.iter().any(|(held, _)| held == value) {
                    continue;
                }
                let handle = store
                    .port_short_id_reference(txn, &key.custody)?
                    .map(|(short_id, _)| short_id)
                    .ok_or(Error::InvariantViolation(
                        "a lifted text's custody record has no handle",
                    ))?;
                keys.push((value.to_owned(), format!("{HANDLE_OPEN}{handle}]")));
            }
        }
        keys.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
        Ok(Self(keys))
    }

    /// The keys the marks of the strings in `value` name: a record body
    /// whose text field holds a lifted text.
    pub(crate) fn of_json_in_txn(
        store: &Store,
        txn: &RoTxn<'_>,
        value: &serde_json::Value,
    ) -> Result<Self> {
        let mut texts = Vec::new();
        strings_of(value, &mut texts);
        Self::of_in_txn(store, txn, texts)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `text` names any handle, so a writer's text may need
    /// [`Self::resolved`].
    pub(crate) fn names_a_handle(text: &str) -> bool {
        text.contains(HANDLE_OPEN)
    }

    /// `text` as a reader other than the owner reads it: each value as its
    /// handle. `None` when it holds none.
    pub(crate) fn masked(&self, text: &str) -> Option<String> {
        swapped(text, self.0.iter().map(|(value, tag)| (value, tag)))
    }

    /// `text`, a writer's new text for the carrier, with each handle back as
    /// the value it stands for: an edit that kept a handle writes the value
    /// again, one that deleted it removed the secret. A handle of any other
    /// record stays as written. `None` when it carries none.
    pub(crate) fn resolved(&self, text: &str) -> Option<String> {
        if !text.contains(HANDLE_OPEN) {
            return None;
        }
        swapped(text, self.0.iter().map(|(value, tag)| (tag, value)))
    }

    /// Each string in `value` masked as [`Self::masked`] masks it; `true`
    /// when one changed.
    pub(crate) fn mask_json(&self, value: &mut serde_json::Value) -> bool {
        each_string(value, &|text| self.masked(text))
    }

    /// Each string in `value` resolved as [`Self::resolved`] resolves it;
    /// `true` when one changed.
    pub(crate) fn resolve_json(&self, value: &mut serde_json::Value) -> bool {
        each_string(value, &|text| self.resolved(text))
    }

    /// `text` as [`Self::masked`] reads it, with where each run of it came
    /// from (FIX 2936): the same values in the same order, each replaced
    /// where [`str::replace`] replaces it, a handle over a handle standing
    /// for both stretches. A pure reading: nothing is scanned or minted.
    pub(crate) fn masked_text(&self, text: &str) -> MaskedText {
        let mut runs = vec![Run {
            text: text.to_owned(),
            source: 0..text.chars().count(),
            handle: false,
        }];
        for (value, handle) in self.0.iter().filter(|(value, _)| !value.is_empty()) {
            let current: String = runs.iter().map(|run| run.text.as_str()).collect();
            // Right to left, so each earlier match keeps its position.
            for at in char_matches(&current, value).into_iter().rev() {
                split_run(&mut runs, at.start);
                split_run(&mut runs, at.end);
                let covered = covering(&runs, &at);
                let stretch = &runs[covered.clone()];
                let start = stretch.iter().map(|run| run.source.start).min();
                let end = stretch.iter().map(|run| run.source.end).max();
                let run = Run {
                    text: handle.clone(),
                    source: start.unwrap_or_default()..end.unwrap_or_default(),
                    handle: true,
                };
                runs.splice(covered, [run]);
            }
        }
        MaskedText(runs)
    }
}

/// A text as [`LiftedKeys::masked`] reads it, run by run: each run is a
/// stretch of the stored text read as it is, or a handle that stands for
/// the stretch it replaced. Positions are Unicode scalar counts.
#[derive(Debug)]
pub(crate) struct MaskedText(Vec<Run>);

#[derive(Debug)]
struct Run {
    /// What the reader reads.
    text: String,
    /// The stretch of the stored text it reads or stands for.
    source: Range<usize>,
    /// Whether `text` stands for `source` rather than reading it as it is.
    handle: bool,
}

/// A selection of a masked text that splits no handle (C-ANCHOR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaskedSelection {
    /// The selection in the text the reader reads.
    pub(crate) shown: Range<usize>,
    /// The stretch of the stored text it stands for.
    pub(crate) stored: Range<usize>,
}

impl MaskedText {
    /// The text the reader reads: [`LiftedKeys::masked`]'s reading.
    pub(crate) fn text(&self) -> String {
        self.0.iter().map(|run| run.text.as_str()).collect()
    }

    /// The selection `start..end` of the text the reader reads, widened so
    /// it splits no handle: an end inside a handle moves out to that
    /// handle's edge, and an empty selection inside one takes the whole
    /// handle (C-ANCHOR). `None` for a selection past the text's end or one
    /// that ends before it starts.
    pub(crate) fn selection(&self, start: usize, end: usize) -> Option<MaskedSelection> {
        let mut shown = start..end;
        let (mut from, mut to) = (None, None);
        let mut at = 0;
        for run in &self.0 {
            let next = at + run.text.chars().count();
            if from.is_none() && start < next {
                if run.handle {
                    shown.start = at;
                    from = Some(run.source.start);
                } else {
                    from = Some(run.source.start + (start - at));
                }
            }
            if at < end && end <= next {
                if run.handle {
                    shown.end = next;
                    to = Some(run.source.end);
                } else {
                    to = Some(run.source.start + (end - at));
                }
            }
            at = next;
        }
        if start > end || end > at {
            return None;
        }
        // A selection at the text's end, or an empty one at its start.
        let from = from.unwrap_or_else(|| self.0.last().map_or(0, |run| run.source.end));
        let to = to.unwrap_or_default().max(from);
        Some(MaskedSelection {
            shown,
            stored: from..to,
        })
    }
}

/// Where [`str::replace`] replaces `value` in `text`, in characters.
fn char_matches(text: &str, value: &str) -> Vec<Range<usize>> {
    let len = value.chars().count();
    let (mut found, mut chars, mut last) = (Vec::new(), 0, 0);
    for (at, _) in text.match_indices(value) {
        chars += text[last..at].chars().count();
        found.push(chars..chars + len);
        chars += len;
        last = at + value.len();
    }
    found
}

/// Splits the run `at` falls inside, so that a run starts at `at`. A
/// handle's two parts both stand for its whole stretch.
fn split_run(runs: &mut Vec<Run>, at: usize) {
    let mut start = 0;
    for index in 0..runs.len() {
        let len = runs[index].text.chars().count();
        if start < at && at < start + len {
            let run = &mut runs[index];
            let cut = run
                .text
                .char_indices()
                .nth(at - start)
                .map_or(run.text.len(), |(byte, _)| byte);
            let mut tail = Run {
                text: run.text.split_off(cut),
                source: run.source.clone(),
                handle: run.handle,
            };
            if !run.handle {
                run.source.end = run.source.start + (at - start);
                tail.source.start = run.source.end;
            }
            runs.insert(index + 1, tail);
            return;
        }
        start += len;
    }
}

/// The runs that make up `at`, whose edges fall on run edges.
fn covering(runs: &[Run], at: &Range<usize>) -> Range<usize> {
    let (mut start, mut first) = (0, 0);
    for (index, run) in runs.iter().enumerate() {
        if start == at.start {
            first = index;
        }
        start += run.text.chars().count();
        if start >= at.end {
            return first..index + 1;
        }
    }
    first..runs.len()
}

fn strings_of<'v>(value: &'v serde_json::Value, texts: &mut Vec<&'v str>) {
    match value {
        serde_json::Value::String(text) => texts.push(text),
        serde_json::Value::Array(items) => {
            for item in items {
                strings_of(item, texts);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                strings_of(item, texts);
            }
        }
        _ => {}
    }
}

/// Each string in `value` replaced by what `swap` makes of it; `true` when
/// one changed.
fn each_string(value: &mut serde_json::Value, swap: &dyn Fn(&str) -> Option<String>) -> bool {
    match value {
        serde_json::Value::String(text) => swap(text).is_some_and(|swapped| {
            *text = swapped;
            true
        }),
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| each_string(item, swap) | changed),
        serde_json::Value::Object(fields) => fields
            .values_mut()
            .fold(false, |changed, item| each_string(item, swap) | changed),
        _ => false,
    }
}

/// `text` with each `from` replaced by its `to`, in order; `None` when none
/// was there.
fn swapped<'a>(
    text: &str,
    pairs: impl Iterator<Item = (&'a String, &'a String)>,
) -> Option<String> {
    let mut out = None::<String>;
    for (from, to) in pairs {
        let current = out.as_deref().unwrap_or(text);
        if current.contains(from.as_str()) {
            out = Some(current.replace(from.as_str(), to));
        }
    }
    out
}
