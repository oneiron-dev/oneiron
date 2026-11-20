//! A live held row read against a raw offer once custody knows a value (FIX
//! RECEIPT-RECORDS-CALL-HELD-INPUT; blind review round 2 of #9503): the row
//! is a template. Each handle it holds that names a record custody knows is
//! a slot, and every other byte of the row compares as written. A slot meets
//! the same handle offered again, or one value its record holds, at any
//! generation the record's history keeps and in any spelling the known-value
//! matcher reads, of a length that lets the row's text after the slot match
//! as written. So text the row holds as written never reads as a handle,
//! whatever custody took since (a rotation into it included), and a handle
//! takes no more of the offer than its record's value. Neither side is
//! masked again, and nothing is minted.

use std::collections::{BTreeSet, HashSet};
use std::ops::Range;
use std::sync::Arc;

use rmpv::Value;

use super::Masker;
use super::side_row::origin;
use super::text::handle_slots;
use super::wipe::PlanTree;
use crate::error::Result;
use crate::store::known_value_index::KnownValues;

/// The most whole-value reads one compare makes. Past it the two do not
/// meet: a row built to make the search long fails closed, as any refused
/// resume does (the step fails; no write runs twice). One constant, so a
/// ruling changes one line.
const MAX_SLOT_READS: usize = 4096;

/// How a compare pairs the entries of two maps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapOrder {
    /// In the order each is written: a MessagePack row and its offer.
    Written,
    /// In any order: a JSON input, whose object keys a receipt reads in any
    /// order.
    Any,
}

/// Whether `held`, a live row the side-row wall stored, is what admitting
/// `offered` stored, read with the values custody holds now, through
/// `known`, as the module docs say: each handle the row holds that names a
/// record custody knows meets the same handle offered again or one value of
/// that record, and nothing else; every other byte meets only itself. A part
/// the wall placed whole as one handle (a credential member that is no
/// text, or an array read as a recovery phrase) is read in the offer as the
/// wall reads it, for the values of the records that part names alone.
/// `false` when no handle the row holds names a record custody knows: the
/// two then meet only as written.
///
/// # Errors
///
/// A value the wall's reading cannot read.
pub(crate) fn held_row_meets(
    held: &Value,
    offered: &Value,
    known: &Arc<KnownValues>,
    maps: MapOrder,
) -> Result<bool> {
    if held == offered {
        return Ok(true);
    }
    let mut records = BTreeSet::new();
    named_records(held, &mut records);
    records.retain(|handle| known.holds_handle(handle));
    if records.is_empty() {
        return Ok(false);
    }
    HeldTemplate {
        known,
        records,
        maps,
        reads: MAX_SLOT_READS,
    }
    .meets(held, offered, None)
}

/// One compare of a held row with an offer.
struct HeldTemplate<'k> {
    known: &'k Arc<KnownValues>,
    /// Each record the row's handles name that custody knows, by its bare
    /// handle.
    records: BTreeSet<String>,
    maps: MapOrder,
    /// The whole-value reads left ([`MAX_SLOT_READS`]).
    reads: usize,
}

impl HeldTemplate<'_> {
    /// `held` against `offered`; `key` is the offered map key `offered` is
    /// the member of.
    fn meets(&mut self, held: &Value, offered: &Value, key: Option<&Value>) -> Result<bool> {
        if held == offered {
            return Ok(true);
        }
        match (held, offered) {
            (Value::String(held), Value::String(offered)) => {
                return Ok(match (held.as_str(), offered.as_str()) {
                    (Some(held), Some(offered)) => self.text_meets(held, offered),
                    _ => false,
                });
            }
            (Value::Binary(held), Value::Binary(offered)) => {
                return Ok(
                    match (std::str::from_utf8(held), std::str::from_utf8(offered)) {
                        (Ok(held), Ok(offered)) => self.text_meets(held, offered),
                        _ => false,
                    },
                );
            }
            (Value::Array(held), Value::Array(offered)) if held.len() == offered.len() => {
                for (held, offered) in held.iter().zip(offered) {
                    if !self.meets(held, offered, None)? {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
            (Value::Map(held), Value::Map(offered)) if held.len() == offered.len() => {
                return self.map_meets(held, offered);
            }
            _ => {}
        }
        self.placed_whole(held, offered, key)
    }

    /// Two maps of one length: each held entry meets one offered entry, key
    /// and member, in the order [`MapOrder`] says.
    fn map_meets(&mut self, held: &[(Value, Value)], offered: &[(Value, Value)]) -> Result<bool> {
        if self.maps == MapOrder::Written {
            for ((held_key, held_member), (key, member)) in held.iter().zip(offered) {
                if !self.meets(held_key, key, None)?
                    || !self.meets(held_member, member, Some(key))?
                {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        let mut taken = vec![false; offered.len()];
        for (held_key, held_member) in held {
            // The entry under the same key as written is read first.
            let mut order: Vec<usize> = (0..offered.len()).filter(|at| !taken[*at]).collect();
            order.sort_by_key(|at| offered[*at].0 != *held_key);
            let mut met = false;
            for at in order {
                let (key, member) = &offered[at];
                if self.meets(held_key, key, None)? && self.meets(held_member, member, Some(key))? {
                    taken[at] = true;
                    met = true;
                    break;
                }
            }
            if !met {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `held`, a text, against `offered`: the row's text between its slots
    /// as written, each slot the same handle as written or one value its
    /// record holds.
    fn text_meets(&mut self, held: &str, offered: &str) -> bool {
        let Some(template) = Template::of(held, &self.records) else {
            return held == offered;
        };
        let offered = offered.as_bytes();
        let reach = self.known.reach().max(1);
        // Each place a piece of the row's text may start at, tried once: a
        // second visit follows a first that failed.
        let mut tried: HashSet<(usize, usize)> = HashSet::new();
        let mut places: Vec<(usize, usize)> = vec![(0, 0)];
        while let Some((piece, at)) = places.pop() {
            let written = template.pieces[piece];
            if !offered[at..].starts_with(written) {
                continue;
            }
            let from = at + written.len();
            let Some(&(as_written, handle)) = template.slots.get(piece) else {
                if from == offered.len() {
                    return true;
                }
                continue;
            };
            if !tried.insert((piece, from)) {
                continue;
            }
            let next = template.pieces[piece + 1];
            let ends: Vec<usize> = if piece + 1 == template.slots.len() {
                offered
                    .len()
                    .checked_sub(next.len())
                    .filter(|end| *end > from && end - from <= reach && offered[*end..] == *next)
                    .into_iter()
                    .collect()
            } else {
                (from + 1..=offered.len().min(from.saturating_add(reach)))
                    .filter(|end| offered[*end..].starts_with(next))
                    .collect()
            };
            for end in ends {
                if self.reads == 0 {
                    return false;
                }
                self.reads -= 1;
                if self.known.is_whole_held_by(&offered[from..end], handle) {
                    places.push((piece + 1, end));
                }
            }
            // The same handle offered again is read first.
            if offered[from..].starts_with(as_written) {
                places.push((piece + 1, from + as_written.len()));
            }
        }
        false
    }

    /// `held`, a part the wall placed whole as one handle or that holds a
    /// run of items it placed so (a recovery phrase over an array's items),
    /// against `offered`, a part of another shape: `offered` read as the
    /// wall reads it, under its map key `key` when it is a member, for the
    /// values of the records `held` names alone, no shape sought and
    /// nothing minted, meets `held` as written. The copy is wiped when it
    /// drops (FIX 1101).
    fn placed_whole(&self, held: &Value, offered: &Value, key: Option<&Value>) -> Result<bool> {
        let mut records = BTreeSet::new();
        named_records(held, &mut records);
        records.retain(|handle| self.records.contains(handle));
        if records.is_empty() {
            return Ok(false);
        }
        let mut reading = Masker {
            mints: true,
            known_only: true,
            records: Some(records),
            at: Some((origin("replay", &[])?, "replay".to_owned())),
            known: Some(Arc::clone(self.known)),
            ..Masker::default()
        };
        Ok(match key {
            Some(key) => {
                let mut part = PlanTree(Value::Map(vec![(key.clone(), offered.clone())]));
                reading.mask_value(&mut part.0)?;
                matches!(&part.0, Value::Map(fields) if fields.len() == 1 && fields[0].1 == *held)
            }
            None => {
                let mut part = PlanTree(offered.clone());
                reading.mask_value(&mut part.0)?;
                part.0 == *held
            }
        })
    }
}

/// A held text as a template: the text written before each slot and after
/// the last, and each slot.
struct Template<'h> {
    /// One more than the slots.
    pieces: Vec<&'h [u8]>,
    /// Each slot: its handle as written, and its record's bare handle.
    slots: Vec<(&'h [u8], &'h str)>,
}

impl<'h> Template<'h> {
    /// `held` with a slot at each handle that names one of `records`, or
    /// `None` when it holds none.
    fn of(held: &'h str, records: &BTreeSet<String>) -> Option<Self> {
        let named: Vec<(Range<usize>, &str)> = handle_slots(held)
            .into_iter()
            .filter(|(_, handle)| records.contains(*handle))
            .collect();
        if named.is_empty() {
            return None;
        }
        let bytes = held.as_bytes();
        let mut pieces = Vec::with_capacity(named.len() + 1);
        let mut slots = Vec::with_capacity(named.len());
        let mut from = 0;
        for (span, handle) in named {
            pieces.push(&bytes[from..span.start]);
            slots.push((&bytes[span.clone()], handle));
            from = span.end;
        }
        pieces.push(&bytes[from..]);
        Some(Self { pieces, slots })
    }
}

/// Each record a handle in `value` names, by its bare handle, into
/// `records`: in each text, map key and member included.
pub(super) fn named_records(value: &Value, records: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if let Some(text) = text.as_str() {
                records.extend(
                    handle_slots(text)
                        .into_iter()
                        .map(|(_, handle)| handle.to_owned()),
                );
            }
        }
        Value::Binary(bytes) => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                records.extend(
                    handle_slots(text)
                        .into_iter()
                        .map(|(_, handle)| handle.to_owned()),
                );
            }
        }
        Value::Array(items) => {
            for item in items {
                named_records(item, records);
            }
        }
        Value::Map(fields) => {
            for (key, member) in fields {
                named_records(key, records);
                named_records(member, records);
            }
        }
        _ => {}
    }
}
