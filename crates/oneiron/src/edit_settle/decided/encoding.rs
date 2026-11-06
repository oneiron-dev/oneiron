//! Named CONTENT encoding without an unadmitted growing output buffer.

use std::io::{self, Cursor, Write};
use std::time::Instant;

use oneiron_docedit::resource::{ResourceRefusal, Resources, wide};

use super::{DECIDED, DecidedSheetAnswers};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SideTableRowProblem};
use crate::office_body::{document_resources_until, machine_memory_refused};
use crate::side_table::StagedRow;

pub(super) struct EncodedAnswers {
    // Drop the owned buffer before the fallback allocated lease it uses.
    staged: StagedRow,
    _resources: Resources,
    deadline: Instant,
}

impl EncodedAnswers {
    pub(super) fn new(
        key: &(EntityId, [u8; 32]),
        row: &DecidedSheetAnswers,
        deadline: Instant,
    ) -> Result<Self> {
        let encoded = encode_buffer(row, deadline)?;
        Ok(Self {
            staged: DECIDED.stage_encoded(key, encoded.bytes),
            _resources: encoded.resources,
            deadline,
        })
    }

    pub(super) fn put(&self, store: &crate::store::Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        check_deadline(self.deadline)?;
        self.staged.put(store, txn)
    }
}

// Fields drop in order: the buffer before the fallback allocated lease.
struct EncodedBuffer {
    bytes: Vec<u8>,
    resources: Resources,
}

pub(crate) struct ExpectedAnswers {
    encoded: EncodedBuffer,
    deadline: Instant,
}

impl ExpectedAnswers {
    pub(super) fn new(row: &DecidedSheetAnswers, deadline: Instant) -> Result<Self> {
        Ok(Self {
            encoded: encode_buffer(row, deadline)?,
            deadline,
        })
    }

    pub(super) fn decode(&self) -> Result<DecidedSheetAnswers> {
        check_deadline(self.deadline)?;
        DECIDED.decode_value(&self.encoded.bytes)
    }
}

fn encode_buffer(row: &DecidedSheetAnswers, deadline: Instant) -> Result<EncodedBuffer> {
    let mut count = EncodedLength::default();
    encode(row, &mut count, deadline)?;
    check_deadline(deadline)?;
    let resources = document_resources_until(Some(deadline));
    let mut hold = resources
        .reserve(wide(count.0))
        .map_err(machine_memory_refused)?;
    check_deadline(deadline)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count.0)
        .map_err(|error| Error::Io(io::Error::new(io::ErrorKind::OutOfMemory, error)))?;
    hold.take(wide(bytes.capacity().saturating_sub(count.0)))
        .map_err(machine_memory_refused)?;
    bytes.resize(count.0, 0);
    // The live reading now carries the allocation. Without one the port
    // keeps the allocated lease until this operation's Resources drops.
    drop(hold);
    let written = {
        let mut target = Cursor::new(bytes.as_mut_slice());
        encode(row, &mut target, deadline)?;
        target.position()
    };
    if written != wide(count.0) {
        return Err(unencodable());
    }
    Ok(EncodedBuffer { bytes, resources })
}

fn encode(row: &DecidedSheetAnswers, target: &mut impl Write, deadline: Instant) -> Result<()> {
    let mut writer = DeadlineWriter {
        target,
        deadline,
        timed_out: false,
    };
    let encoded = rmp_serde::encode::write_named(&mut writer, row);
    if writer.timed_out {
        return Err(machine_memory_refused(ResourceRefusal::Deadline));
    }
    encoded.map_err(|_| unencodable())
}

fn unencodable() -> Error {
    DECIDED.decl().row_error(SideTableRowProblem::Unencodable)
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(machine_memory_refused(ResourceRefusal::Deadline));
    }
    Ok(())
}

#[derive(Default)]
struct EncodedLength(usize);

impl Write for EncodedLength {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("encoded answer length overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct DeadlineWriter<'a, W> {
    target: &'a mut W,
    deadline: Instant,
    timed_out: bool,
}

impl<W: Write> DeadlineWriter<'_, W> {
    fn checkpoint(&mut self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            self.timed_out = true;
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(())
    }
}

impl<W: Write> Write for DeadlineWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.checkpoint()?;
        self.target.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.checkpoint()?;
        self.target.flush()
    }
}
