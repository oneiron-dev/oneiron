//! A result body read as it streams (FIX 3677 step 7, FIX 5392): what the
//! whole read checks, read a frame at a time, so a reader that copies a body
//! on never holds it whole. The row's inline bytes are read in place, a
//! file through the body file reader; both are checked against the body's
//! length and BLAKE3 once read to their end.

use std::io::{Read, Write};

use super::*;
use crate::result_body::ResultBodyPin;

impl Vault {
    /// [`Self::code_run_result_body_in_txn`] as it streams: the body of
    /// `output` under `rtxn`, from its row in place or from its file, which
    /// [`CodeRunResultBodyReader::copy_checked`] checks against the body's
    /// length and digest once it reads to the end. `None` when no row holds
    /// it. The body's digest is pinned while the reader lives; a reader of a
    /// whole set pins every body before `rtxn` opened, and this pin adds to
    /// that one, never stands for it.
    pub(crate) fn code_run_result_body_reader_in_txn<'t>(
        &self,
        rtxn: &'t heed::RoTxn<'_>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<CodeRunResultBodyReader<'t>>> {
        let Some(row) = RAW_OUTPUTS.get_borrowed(&self.store, rtxn, &output.handle)? else {
            return Ok(None);
        };
        let pin = self.pin_result_body(output.raw_blake3);
        let source = if code_run_row_inline(&row) {
            if u64::try_from(row.len() - 1).ok() != Some(output.raw_len) {
                return Err(drifted());
            }
            Source::Inline(row)
        } else {
            let StoredBody::File { len, .. } = RAW_OUTPUTS.decode_value(&row)? else {
                return Err(Error::CorruptedIndex("code-run raw output row"));
            };
            if len != output.raw_len {
                return Err(drifted());
            }
            let key = body_key_row_in_txn(&self.store, rtxn, &output.raw_blake3)?;
            Source::File(open_body_file(
                output,
                key.as_ref(),
                vec![self.store.body_dir()?],
            )?)
        };
        Ok(Some(CodeRunResultBodyReader {
            source,
            len: output.raw_len,
            digest: output.raw_blake3,
            _pin: pin,
        }))
    }
}

/// One result body as it streams ([`Vault::code_run_result_body_reader_in_txn`]):
/// read once, through [`Self::copy_checked`].
pub(crate) struct CodeRunResultBodyReader<'t> {
    source: Source<'t>,
    len: u64,
    digest: [u8; 32],
    _pin: ResultBodyPin,
}

/// Where a streamed body's bytes are: its row, lent by the read
/// transaction (its tag first), or its file.
enum Source<'t> {
    Inline(std::borrow::Cow<'t, [u8]>),
    File(BodyFile),
}

impl CodeRunResultBodyReader<'_> {
    /// Copies the body into `out` a frame at a time, its BLAKE3 and length
    /// read as it passes, and checks both at its end: a body that runs past
    /// its length, ends short of it or hashes to other bytes is drifted, as
    /// the whole read finds it. What reached `out` before that is the
    /// caller's to drop.
    ///
    /// # Errors
    ///
    /// A drifted body ([`body_drifted`]), the body file reader's errors and
    /// `out`'s.
    pub(crate) fn copy_checked(self, out: &mut impl Write) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        let mut read = 0_u64;
        match self.source {
            Source::Inline(row) => {
                let body = row.get(1..).unwrap_or_default();
                hasher.update(body);
                read = body.len() as u64;
                out.write_all(body)?;
            }
            Source::File(mut file) => {
                // A buffer a frame long, not a bound on the body (Rule 5).
                let mut frame = vec![0; crate::store::LINE_INDEX_BLOCK_BYTES as usize];
                loop {
                    let got = match file.read(&mut frame) {
                        Ok(0) => break,
                        Ok(got) => got,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(read_error(error)),
                    };
                    read = read.saturating_add(got as u64);
                    if read > self.len {
                        return Err(drifted());
                    }
                    hasher.update(&frame[..got]);
                    out.write_all(&frame[..got])?;
                }
            }
        }
        if read != self.len || *hasher.finalize().as_bytes() != self.digest {
            return Err(drifted());
        }
        Ok(())
    }
}

/// The error a body file read failed with: the store's own, as a range
/// read returns it, when the reader carried one.
fn read_error(error: std::io::Error) -> Error {
    if !error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
        return error.into();
    }
    match error.into_inner().map(|inner| inner.downcast::<Error>()) {
        Some(Ok(inner)) => *inner,
        _ => Error::InvariantViolation("a body file read lost its error"),
    }
}
