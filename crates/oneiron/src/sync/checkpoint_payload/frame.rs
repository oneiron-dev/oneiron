//! A window carrier's own spelling (KS7-3b): what KS7-5 keeps of a split
//! window under the image's outer seal. It holds the vendored skeleton in
//! the vendor's own encoding, each row's locator, family and slice, and
//! each value's copies and fields: locators, ordinals, each copy's home and
//! the owners it holds only while they do (FIX 10283), and field names,
//! never a value or an actor. A carrier has one spelling; any other refuses.

use loro::IdSpan;
use loro::checkpoint::Skeleton;
use serde::{Deserialize, Serialize};

use super::{AtomHome, AtomRef, LoroCarrier, LoroRow, LoroSlice, LoroSlot, SlotCopy, SyncCarrier};
use crate::error::Result;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{OtherClient, OwnerRef, RowDb, RowLocator, bad_part};

/// The spelling's version: 2 binds each copy to its home (FIX 10283).
const FRAME: u8 = 2;

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
struct FrameOwner {
    subtype: u8,
    owner: [u8; 32],
}

/// A copy's home: 0 an owner's compartment, 1 the image's seal (structure),
/// 2 another custody client's, by its tag.
#[derive(Serialize, Deserialize)]
struct FrameHome {
    kind: u8,
    owner: Option<FrameOwner>,
    client: Option<u8>,
}

#[derive(Serialize, Deserialize)]
struct FrameCopy {
    at: FrameLocator,
    atom: u32,
    home: FrameHome,
    dependencies: Vec<FrameOwner>,
}

#[derive(Serialize, Deserialize)]
struct FrameSlot {
    copies: Vec<FrameCopy>,
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

const CLIENTS: [OtherClient; 4] = [
    OtherClient::Body,
    OtherClient::Response,
    OtherClient::WorldPad,
    OtherClient::Credential,
];

fn write_owner(owner: &OwnerRef) -> FrameOwner {
    FrameOwner {
        subtype: owner.subtype.tag(),
        owner: owner.owner32,
    }
}

fn read_owner(owner: FrameOwner) -> Result<OwnerRef> {
    Ok(OwnerRef {
        subtype: Subtype::from_tag(owner.subtype).ok_or_else(bad_part)?,
        owner32: owner.owner,
    })
}

fn write_home(home: &AtomHome) -> Result<FrameHome> {
    Ok(match home {
        AtomHome::Owner(owner) => FrameHome {
            kind: 0,
            owner: Some(write_owner(owner)),
            client: None,
        },
        AtomHome::Structure => FrameHome {
            kind: 1,
            owner: None,
            client: None,
        },
        AtomHome::Client(client) => FrameHome {
            kind: 2,
            owner: None,
            client: Some(tag(&CLIENTS, client)?),
        },
    })
}

fn read_home(home: FrameHome) -> Result<AtomHome> {
    match (home.kind, home.owner, home.client) {
        (0, Some(owner), None) => Ok(AtomHome::Owner(read_owner(owner)?)),
        (1, None, None) => Ok(AtomHome::Structure),
        (2, None, Some(client)) => Ok(AtomHome::Client(tagged(&CLIENTS, client)?)),
        _ => Err(bad_part()),
    }
}

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
                copies.push(FrameCopy {
                    at: write_locator(&copy.at)?,
                    atom: copy.atom.0,
                    home: write_home(&copy.home)?,
                    dependencies: copy.dependencies.iter().map(write_owner).collect(),
                });
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
            for copy in slot.copies {
                copies.push(SlotCopy {
                    at: read_locator(copy.at)?,
                    atom: AtomRef(copy.atom),
                    home: read_home(copy.home)?,
                    dependencies: copy
                        .dependencies
                        .into_iter()
                        .map(read_owner)
                        .collect::<Result<_>>()?,
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
