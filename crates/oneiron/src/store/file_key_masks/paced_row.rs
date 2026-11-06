use std::io::{Cursor, Read};

use heed::RoTxn;

use super::{MASKED_FILE, MaskedFile};
use crate::batch::secret_scan::container::{ContainerReader, ReadProgress, withheld};
use crate::error::{Error, Result, SideTableRowProblem};
use crate::side_table::SideTableDbs;

pub(crate) fn masked_file_in_txn_with_reader(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    hash: &[u8; 32],
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<Option<MaskedFile>> {
    let Some(bytes) = MASKED_FILE.get_borrowed(store, txn, hash)? else {
        return Ok(None);
    };
    let mut input = MaskedRowReader {
        cursor: Cursor::new(bytes.as_ref()),
        reader,
        scan_bytes: scan_bytes.max(1),
        stopped: None,
    };
    let decoded = rmp_serde::decode::from_read(&mut input);
    if let Some(error) = input.stopped.take() {
        return Err(error);
    }
    let value = decoded.map_err(|_| {
        MASKED_FILE
            .decl()
            .row_error(SideTableRowProblem::Undecodable)
    })?;
    if input.cursor.position() != bytes.len() as u64 {
        return Err(MASKED_FILE
            .decl()
            .row_error(SideTableRowProblem::TrailingBytes));
    }
    Ok(Some(value))
}

struct MaskedRowReader<'bytes, 'reader> {
    cursor: Cursor<&'bytes [u8]>,
    reader: &'reader ContainerReader,
    scan_bytes: usize,
    stopped: Option<Error>,
}

impl Read for MaskedRowReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Err(stop) = self.reader.pacing.checkpoint(ReadProgress::Member) {
            self.stopped = Some(withheld(stop));
            return Err(std::io::ErrorKind::Other.into());
        }
        let len = buffer.len().min(self.scan_bytes);
        self.cursor.read(&mut buffer[..len])
    }
}
