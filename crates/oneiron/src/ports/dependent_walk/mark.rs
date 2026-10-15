//! A walk row and the marks it holds: what each mark of a source covers,
//! and the worlds a row is withdrawn for.

use super::{DependentWalkDoor, ROW, RowKey};
use crate::error::{Error, Result};
use crate::settings::CarriedWorlds;
use crate::side_table::{CodecError, RawValue};

/// What one mark of a source covers: the dependency rows `(after, end]` it
/// held when it was marked, in key order. A row written later is a newer
/// version's (a deleted source takes none), and the mark leaves it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mark {
    /// Which mark of the source this is: a row settled at it or a later one
    /// is passed by.
    pub(super) generation: u64,
    /// The last row walked; `None` before the first batch.
    pub(super) after: Option<RowKey>,
    /// The last row the source held at the mark.
    pub(super) end: RowKey,
    /// Where the source's words sat, read at the mark while its row, stamp
    /// and edges still stood: later batches cannot read them again.
    pub(super) worlds: CarriedWorlds,
}

impl Mark {
    pub(super) fn covers(&self, row: &RowKey) -> bool {
        self.after.is_none_or(|after| *row > after) && *row <= self.end
    }

    pub(super) fn covers_none(&self) -> bool {
        self.after.is_some_and(|after| after >= self.end)
    }

    /// Whether this mark withdraws every row `other` withdraws, for at least
    /// its worlds: it is as late, and covers as much.
    fn answers_for(&self, other: &Self) -> bool {
        self.generation >= other.generation
            && self.after <= other.after
            && self.end >= other.end
            && other.worlds.worlds.is_subset(&self.worlds.worlds)
            && (self.worlds.unknown || !other.worlds.unknown)
    }

    fn encode_into(&self, raw: &mut Vec<u8>) -> Result<()> {
        raw.extend_from_slice(&self.generation.to_be_bytes());
        raw.extend_from_slice(&self.end);
        raw.push(u8::from(self.after.is_some()));
        raw.extend_from_slice(&self.after.unwrap_or([0; ROW]));
        let worlds = self.worlds.encode();
        let len = u32::try_from(worlds.len()).map_err(|_| corrupt_walk())?;
        raw.extend_from_slice(&len.to_be_bytes());
        raw.extend_from_slice(&worlds);
        Ok(())
    }

    fn decode_from(raw: &mut &[u8]) -> Result<Self> {
        let generation = u64::from_be_bytes(take(raw, 8)?.try_into().map_err(|_| corrupt_walk())?);
        let end: RowKey = take(raw, ROW)?.try_into().map_err(|_| corrupt_walk())?;
        let flag = take(raw, 1)?[0];
        let after: RowKey = take(raw, ROW)?.try_into().map_err(|_| corrupt_walk())?;
        let after = match flag {
            0 => None,
            1 => Some(after),
            _ => return Err(corrupt_walk()),
        };
        let len = u32::from_be_bytes(take(raw, 4)?.try_into().map_err(|_| corrupt_walk())?);
        let worlds = take(raw, usize::try_from(len).map_err(|_| corrupt_walk())?)?;
        Ok(Self {
            generation,
            after,
            end,
            worlds: CarriedWorlds::decode(worlds)?,
        })
    }
}

/// What is left of one source's walk: its latest mark, whose cursor the
/// batches advance, and the earlier marks it had not finished when that one
/// came. Each earlier one still withdraws the rows it covered ahead of the
/// cursor, for its own worlds; the latest mark's range holds them all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WalkRow {
    pub(super) door: DependentWalkDoor,
    /// Dependents withdrawn so far.
    pub(super) walked: u64,
    pub(super) mark: Mark,
    pub(super) earlier: Vec<Mark>,
}

impl WalkRow {
    /// The worlds the walk withdraws `row` for, given the mark it was
    /// settled at; `None` where every mark that covers it passes it by.
    pub(super) fn worlds_for(&self, row: &RowKey, settled: Option<u64>) -> Option<CarriedWorlds> {
        if !self.mark.covers(row) {
            return None;
        }
        let mut worlds: Option<CarriedWorlds> = None;
        for mark in std::iter::once(&self.mark).chain(&self.earlier) {
            if mark.covers(row) && settled.is_none_or(|at| at < mark.generation) {
                worlds
                    .get_or_insert_with(CarriedWorlds::default)
                    .absorb(&mark.worlds);
            }
        }
        worlds
    }
}

/// Earlier marks one walk keeps apart. Past it the two oldest merge into one
/// that withdraws the rows of both for the worlds of both, settled rows as
/// the newer one passes them: a narrowing, never a widening, and only for a
/// source whose worlds changed this often within one walk.
const EARLIER_MARKS: usize = 16;

/// The earlier marks a walk keeps beside `latest`, newest first: none that a
/// later mark answers for, and at most [`EARLIER_MARKS`].
pub(super) fn keep_apart(mut earlier: Vec<Mark>, latest: &Mark) -> Vec<Mark> {
    earlier.sort_by(|a, b| b.generation.cmp(&a.generation));
    let mut kept: Vec<Mark> = Vec::with_capacity(earlier.len());
    for mark in earlier {
        if !std::iter::once(latest)
            .chain(&kept)
            .any(|later| later.answers_for(&mark))
        {
            kept.push(mark);
        }
    }
    while kept.len() > EARLIER_MARKS
        && let Some(oldest) = kept.pop()
        && let Some(older) = kept.last_mut()
    {
        older.after = older.after.min(oldest.after);
        older.end = older.end.max(oldest.end);
        older.worlds.absorb(&oldest.worlds);
    }
    kept
}

fn corrupt_walk() -> Error {
    Error::CorruptedIndex("dependent walk")
}

/// The next `n` bytes of `raw`, which moves past them.
fn take<'a>(raw: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let (head, rest) = raw.split_at_checked(n).ok_or_else(corrupt_walk)?;
    *raw = rest;
    Ok(head)
}

impl RawValue for WalkRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = vec![self.door.tag()];
        raw.extend_from_slice(&self.walked.to_be_bytes());
        let earlier = u32::try_from(self.earlier.len()).map_err(|_| corrupt_walk())?;
        raw.extend_from_slice(&earlier.to_be_bytes());
        for mark in std::iter::once(&self.mark).chain(&self.earlier) {
            mark.encode_into(&mut raw)?;
        }
        Ok(raw)
    }

    fn from_raw(mut raw: &[u8]) -> std::result::Result<Self, CodecError> {
        let raw = &mut raw;
        let door = DependentWalkDoor::from_tag(take(raw, 1)?[0]).ok_or_else(corrupt_walk)?;
        let walked = u64::from_be_bytes(take(raw, 8)?.try_into().map_err(|_| corrupt_walk())?);
        let earlier = u32::from_be_bytes(take(raw, 4)?.try_into().map_err(|_| corrupt_walk())?);
        let mark = Mark::decode_from(raw)?;
        let earlier = (0..earlier)
            .map(|_| Mark::decode_from(raw))
            .collect::<Result<Vec<_>>>()?;
        if !raw.is_empty() {
            return Err(corrupt_walk().into());
        }
        Ok(Self {
            door,
            walked,
            mark,
            earlier,
        })
    }
}
