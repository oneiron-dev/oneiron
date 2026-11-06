//! The native recording-clock row program and its caller-owned projection.

use std::borrow::Cow;
use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use super::{CLOCK_FLOOR, Error, ID_FLOOR, Result, StoreClock};
use crate::store::ManifestDbs;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum FloorKey {
    Id,
    Clock,
}

impl FloorKey {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Id => ID_FLOOR,
            Self::Clock => CLOCK_FLOOR,
        }
    }
}

trait RecordingRows {
    fn floor(&self, key: FloorKey) -> Result<Option<Cow<'_, [u8]>>>;
    fn put_floor(&mut self, key: FloorKey, value: Vec<u8>) -> Result<()>;
    fn clock(&self) -> &StoreClock;
}

pub(super) fn decode_clock_floor(bytes: Option<&[u8]>) -> Result<(u64, u64)> {
    let Some(bytes) = bytes else {
        return Ok((0, 0));
    };
    let half = |at: usize| -> Result<u64> {
        bytes
            .get(at..at + 8)
            .and_then(|part| part.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(Error::CorruptedIndex("recorded clock floor"))
    };
    match bytes.len() {
        8 => Ok((half(0)?, 0)),
        16 => Ok((half(0)?, half(8)?)),
        _ => Err(Error::CorruptedIndex("recorded clock floor")),
    }
}

pub(super) fn encode_clock_floor(floor: u64, lease: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&floor.to_be_bytes());
    bytes[8..].copy_from_slice(&lease.to_be_bytes());
    bytes
}

fn persist_id_floor(rows: &mut impl RecordingRows) -> Result<()> {
    let id_floor = match rows.floor(FloorKey::Id)? {
        Some(bytes) => u128::from_be_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("id source floor"))?,
        ),
        None => 0,
    };
    let observed_id_floor = rows.clock().observe_id_floor(id_floor)?;
    if observed_id_floor != id_floor {
        rows.put_floor(FloorKey::Id, observed_id_floor.to_be_bytes().to_vec())?;
    }
    Ok(())
}

fn observe_clock_floor(rows: &mut impl RecordingRows) -> Result<u64> {
    let (persisted, lease) = {
        let bytes = rows.floor(FloorKey::Clock)?;
        decode_clock_floor(bytes.as_deref())?
    };
    let now = rows.clock().observe_leased_floor(persisted, lease)?;
    if now != persisted {
        rows.put_floor(FloorKey::Clock, encode_clock_floor(now, lease).to_vec())?;
    }
    Ok(now)
}

struct WriterRows<'store, 'write, 'env, D> {
    store: &'store D,
    txn: &'write mut RwTxn<'env>,
}

impl<D: ManifestDbs> RecordingRows for WriterRows<'_, '_, '_, D> {
    fn floor(&self, key: FloorKey) -> Result<Option<Cow<'_, [u8]>>> {
        self.store.vault_meta().get(self.txn, key.bytes())
    }

    fn put_floor(&mut self, key: FloorKey, value: Vec<u8>) -> Result<()> {
        self.store.vault_meta().put(self.txn, key.bytes(), &value)
    }

    fn clock(&self) -> &StoreClock {
        self.store.clock()
    }
}

pub(super) fn persist_id_floor_in_txn(store: &impl ManifestDbs, txn: &mut RwTxn<'_>) -> Result<()> {
    persist_id_floor(&mut WriterRows { store, txn })
}

pub(super) fn observe_clock_floor_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
) -> Result<u64> {
    observe_clock_floor(&mut WriterRows { store, txn })
}

/// Projects only recording-clock row writes over the caller's snapshot and
/// earlier writes in this projection. The REAL store clock is observed: this
/// can advance its process-local clock and id-source state. It is not an
/// isolated clock, a read-only preview or authority to perform an effect.
///
/// The store and reader lifetimes are separate so plans can outlive the
/// snapshot borrow without outliving the store that made the observations.
pub(crate) struct RecordingClockProjection<'store, 'read, 'env, D> {
    store: &'store D,
    txn: &'read RoTxn<'env>,
    floors: HashMap<FloorKey, Vec<u8>>,
    operations: Vec<(FloorKey, Vec<u8>)>,
}

impl<'store, 'read, 'env, D: ManifestDbs> RecordingClockProjection<'store, 'read, 'env, D> {
    pub(crate) fn new(store: &'store D, txn: &'read RoTxn<'env>) -> Self {
        Self {
            store,
            txn,
            floors: HashMap::new(),
            operations: Vec::new(),
        }
    }

    /// Preserve the native id-floor step before the recording-floor step.
    pub(crate) fn recorded_at(&mut self) -> Result<u64> {
        self.persist_id_floor()?;
        self.observe_clock_floor()
    }

    pub(crate) fn persist_id_floor(&mut self) -> Result<()> {
        persist_id_floor(self)
    }

    pub(crate) fn observe_clock_floor(&mut self) -> Result<u64> {
        observe_clock_floor(self)
    }

    /// Take this interval's selected writes, retaining the read-through floors
    /// for the next native interval. Also available after a preparation error:
    /// the caller owns the original error and the selected partial prefix.
    pub(crate) fn take_plan(&mut self) -> PreparedRecordingClock<'store, D> {
        PreparedRecordingClock {
            store: self.store,
            operations: std::mem::take(&mut self.operations),
        }
    }
}

impl<D: ManifestDbs> RecordingRows for RecordingClockProjection<'_, '_, '_, D> {
    fn floor(&self, key: FloorKey) -> Result<Option<Cow<'_, [u8]>>> {
        match self.floors.get(&key) {
            Some(bytes) => Ok(Some(Cow::Borrowed(bytes))),
            None => self.store.vault_meta().get(self.txn, key.bytes()),
        }
    }

    fn put_floor(&mut self, key: FloorKey, value: Vec<u8>) -> Result<()> {
        self.floors.insert(key, value.clone());
        self.operations.push((key, value));
        Ok(())
    }

    fn clock(&self) -> &StoreClock {
        self.store.clock()
    }
}

/// Selected row writes, not a clock lease or a reusable permission. They keep
/// their native interval boundaries and their original store, without keeping
/// the snapshot borrow alive. No clock is sampled again while consuming them.
pub(crate) struct PreparedRecordingClock<'store, D> {
    store: &'store D,
    operations: Vec<(FloorKey, Vec<u8>)>,
}

impl<D: ManifestDbs> PreparedRecordingClock<'_, D> {
    /// Consume at this interval's original position in the SAME writer. Only
    /// represented clock-floor writes may have intervened since preparation;
    /// other native effects belong at their own positions between intervals.
    pub(crate) fn apply_in_txn(self, txn: &mut RwTxn<'_>) -> Result<()> {
        for (key, value) in self.operations {
            self.store.vault_meta().put(txn, key.bytes(), &value)?;
        }
        Ok(())
    }
}
