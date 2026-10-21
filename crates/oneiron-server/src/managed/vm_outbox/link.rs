//! One carrier connection, read and written through its own buffers: its
//! frames, one line each, and a transfer's data chunks.

use super::local::Staged;
use oneiron_vault_contract::vm_outbox::{
    MAX_VM_OUTBOX_LINE, VM_OUTBOX_CHUNK_BYTES, VmOutboxFrame, decode_vm_outbox_frame,
    encode_vm_outbox_frame, vm_outbox_chunk_header, vm_outbox_chunk_len,
};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

/// One connection, read and written through its own buffers.
pub(super) struct Link<S: Read + Write> {
    reader: BufReader<S>,
    writer: BufWriter<S>,
}

impl<S: Read + Write> Link<S> {
    /// The connection whose two handles are `reader` and `writer`.
    pub(super) fn new(reader: S, writer: S) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        }
    }

    pub(super) fn send(&mut self, frame: &VmOutboxFrame) -> anyhow::Result<()> {
        self.writer
            .write_all(encode_vm_outbox_frame(frame)?.as_bytes())?;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> anyhow::Result<()> {
        Ok(self.writer.flush()?)
    }

    /// The next frame, or `None` once the other end closed the connection.
    pub(super) fn read(&mut self) -> anyhow::Result<Option<VmOutboxFrame>> {
        let mut line = Vec::new();
        let bound = MAX_VM_OUTBOX_LINE as u64;
        if (&mut self.reader)
            .take(bound)
            .read_until(b'\n', &mut line)?
            == 0
        {
            return Ok(None);
        }
        anyhow::ensure!(
            line.last() == Some(&b'\n'),
            "an outbox frame ran past its line bound or the connection"
        );
        Ok(Some(decode_vm_outbox_frame(std::str::from_utf8(&line)?)?))
    }

    /// `length` bytes of `file`, from its start, in data chunks.
    pub(super) fn send_data(&mut self, mut file: &File, length: u64) -> anyhow::Result<()> {
        let mut buffer = vec![0u8; VM_OUTBOX_CHUNK_BYTES];
        let mut left = length;
        while left > 0 {
            let want = usize::try_from(left).map_or(buffer.len(), |left| left.min(buffer.len()));
            let read = file.read(&mut buffer[..want])?;
            anyhow::ensure!(read > 0, "a member shrank while it was sent");
            let header = vm_outbox_chunk_header(read)
                .ok_or_else(|| anyhow::anyhow!("a data chunk outside its bounds"))?;
            self.writer.write_all(&header)?;
            self.writer.write_all(&buffer[..read])?;
            left -= read as u64;
        }
        Ok(())
    }

    /// Reads a transfer's `length` bytes of data chunks, written into
    /// `staged` when there is one. A write that fails stops the writing, not
    /// the reading, and is returned.
    pub(super) fn read_data(
        &mut self,
        length: u64,
        mut staged: Option<&mut Staged>,
    ) -> anyhow::Result<Option<std::io::Error>> {
        let mut buffer = vec![0u8; VM_OUTBOX_CHUNK_BYTES];
        let mut left = length;
        let mut failed = None;
        while left > 0 {
            let mut header = [0u8; 4];
            self.reader.read_exact(&mut header)?;
            let len = vm_outbox_chunk_len(header)
                .filter(|len| *len as u64 <= left)
                .ok_or_else(|| anyhow::anyhow!("a data chunk outside its transfer"))?;
            self.reader.read_exact(&mut buffer[..len])?;
            if failed.is_none()
                && let Some(staged) = staged.as_deref_mut()
                && let Err(error) = staged.write(&buffer[..len])
            {
                failed = Some(error);
            }
            left -= len as u64;
        }
        Ok(failed)
    }
}
