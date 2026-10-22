//! A window carrier's own spelling (KS7-3b): what KS7-5 keeps of a split
//! window under the image's outer seal. It holds the vendored skeleton in
//! the vendor's own encoding, each row's locator, family and slice, and
//! each value's copies and fields: locators, ordinals and field names,
//! never a value or an actor. A carrier has one spelling; any other refuses.

use loro::IdSpan;
use loro::checkpoint::Skeleton;
use serde::{Deserialize, Serialize};

use super::{AtomRef, LoroCarrier, LoroRow, LoroSlice, LoroSlot, SlotCopy, SyncCarrier};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{RowDb, RowLocator, bad_part};

/// The spelling's version.
const FRAME: u8 = 1;

#[derive(Serialize, Deserialize)]
struct Frame {
    frame: u8,
    window: String,
    skeleton: Vec<u8>,
    rows: Vec<FrameRow>,
    slots: Vec<FrameSlot>,
}

#[derive(Serialize, Deserialize)]
struct FrameLocator {
    db: u8,
    key: Vec<u8>,
    path: String,
}

#[derive(Serialize, Deserialize)]
struct FrameRow {
    at: FrameLocator,
    carrier: u8,
    /// `None` for a snapshot; an update's spans as (peer, start, end).
    spans: Option<Vec<(u64, i32, i32)>>,
}

#[derive(Serialize, Deserialize)]
struct FrameSlot {
    copies: Vec<(FrameLocator, u32)>,
    holes: Vec<String>,
}

const DBS: [RowDb; 6] = [
    RowDb::Entities,
    RowDb::EdgesOut,
    RowDb::EdgesIn,
    RowDb::VaultMeta,
    RowDb::SyncState,
    RowDb::SyncQueue,
];

const CARRIERS: [SyncCarrier; 6] = [
    SyncCarrier::WindowSnapshot,
    SyncCarrier::WindowUpdate,
    SyncCarrier::ResidenceItem,
    SyncCarrier::PendingEdit,
    SyncCarrier::PendingNoteOperation,
    SyncCarrier::SyncQueue,
];

/// `value`'s place in `all`, as its tag.
fn tag<T: PartialEq>(all: &[T], value: &T) -> Result<u8> {
    let place = all.iter().position(|known| known == value);
    place
        .and_then(|place| u8::try_from(place).ok())
        .ok_or_else(bad_part)
}

/// The value tagged `tag` in `all`.
fn tagged<T: Copy>(all: &[T], tag: u8) -> Result<T> {
    all.get(usize::from(tag)).copied().ok_or_else(bad_part)
}

fn write_locator(at: &RowLocator) -> Result<FrameLocator> {
    Ok(FrameLocator {
        db: tag(&DBS, &at.db)?,
        key: at.key.clone(),
        path: at.path.clone(),
    })
}

fn read_locator(at: FrameLocator) -> Result<RowLocator> {
    Ok(RowLocator {
        db: tagged(&DBS, at.db)?,
        key: at.key,
        path: at.path,
    })
}

impl LoroCarrier {
    /// This carrier's one spelling.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let spans = match &row.slice {
                LoroSlice::Snapshot => None,
                LoroSlice::Updates(spans) => Some(
                    spans
                        .iter()
                        .map(|span| (span.peer, span.counter.start, span.counter.end))
                        .collect(),
                ),
            };
            rows.push(FrameRow {
                at: write_locator(&row.at)?,
                carrier: tag(&CARRIERS, &row.carrier)?,
                spans,
            });
        }
        let mut slots = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let mut copies = Vec::with_capacity(slot.copies.len());
            for copy in &slot.copies {
                copies.push((write_locator(&copy.at)?, copy.atom.0));
            }
            slots.push(FrameSlot {
                copies,
                holes: slot.holes.clone(),
            });
        }
        let frame = Frame {
            frame: FRAME,
            window: self.window.clone(),
            skeleton: self.skeleton.to_bytes().map_err(|_| bad_part())?,
            rows,
            slots,
        };
        rmp_serde::to_vec_named(&frame).map_err(|_| bad_part())
    }

    /// The carrier `bytes` spells.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let frame: Frame = rmp_serde::from_slice(bytes).map_err(|_| bad_part())?;
        if frame.frame != FRAME {
            return Err(bad_part());
        }
        let mut rows = Vec::with_capacity(frame.rows.len());
        for row in frame.rows {
            let slice = match row.spans {
                None => LoroSlice::Snapshot,
                Some(spans) => LoroSlice::Updates(
                    spans
                        .into_iter()
                        .map(|(peer, start, end)| IdSpan::new(peer, start, end))
                        .collect(),
                ),
            };
            rows.push(LoroRow {
                at: read_locator(row.at)?,
                carrier: tagged(&CARRIERS, row.carrier)?,
                slice,
            });
        }
        let mut slots = Vec::with_capacity(frame.slots.len());
        for slot in frame.slots {
            let mut copies = Vec::with_capacity(slot.copies.len());
            for (at, atom) in slot.copies {
                copies.push(SlotCopy {
                    at: read_locator(at)?,
                    atom: AtomRef(atom),
                });
            }
            slots.push(LoroSlot {
                copies,
                holes: slot.holes,
            });
        }
        let carrier = Self {
            window: frame.window,
            skeleton: Skeleton::from_bytes(&frame.skeleton).map_err(|_| bad_part())?,
            rows,
            slots,
        };
        if carrier.to_bytes()? != bytes {
            return Err(bad_part());
        }
        Ok(carrier)
    }
}
