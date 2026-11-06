//! One result body of a run, read a piece at a time through the run's
//! storage, and the live cutoff a scoped child's reads of it stop at (FIX
//! 8233).
//!
//! A read made for a scoped child holds its runner's [`ScopedCallControl`].
//! Each piece read checks it first, and the facets check it at their long
//! loop points through [`ResultBody::live_cutoff`]. Once it is reached, the
//! read stops there with [`live_cutoff_error`], and the read's caller answers
//! `reader_task_settled` in place of all the cut read left. The check latches
//! the control, so the child's runner ends its entry at its cutoff. A read
//! for any other reader holds no control and reads no clock.

use std::time::Instant;

use super::{READ_PIECE_BYTES, ResultBody, ResultRead};
use crate::code_run::{
    CodeRunOutputKind, CodeRunRawOutput, ExecutorStorage, READER_TASK_SETTLED, ScopedCallControl,
};
use crate::{Error, Result};

/// The live cutoff one result read stops at (FIX 8233): the control of the
/// scoped child it is made for, or none for any other reader.
#[derive(Clone, Copy, Default)]
pub(crate) struct LiveCutoff<'c>(Option<&'c ScopedCallControl>);

impl LiveCutoff<'_> {
    /// `Ok` while the child's live cutoff is not reached; once it is,
    /// [`live_cutoff_error`]. A reached cutoff latches its control. With no
    /// control it reads no clock.
    pub(crate) fn check(self) -> Result<()> {
        match self.0 {
            Some(control) if control.expired(Instant::now()) => Err(live_cutoff_error()),
            _ => Ok(()),
        }
    }
}

/// The error a read stops with at its live cutoff (FIX 8233): a refusal
/// that names `reader_task_settled`. The read's caller answers that refusal
/// in its place. It is never a parse, taint or index error.
fn live_cutoff_error() -> Error {
    Error::Refused(READER_TASK_SETTLED.to_owned())
}

/// One result body of a run, read by range through the run's storage.
pub(crate) struct RunBody<'s, 'a> {
    storage: &'s ExecutorStorage<'a>,
    output: &'s CodeRunRawOutput,
    base: u64,
    len: u64,
    live_cutoff: LiveCutoff<'s>,
}

impl<'s, 'a> RunBody<'s, 'a> {
    /// The body `read` reads in `storage`: the window its range names, or the
    /// whole body, stopped at its live cutoff when it has one (FIX 8233).
    pub(super) fn of(read: &'s ResultRead, storage: &'s ExecutorStorage<'a>) -> Self {
        let (base, end) = read.range.unwrap_or((0, read.output.raw_len));
        Self {
            storage,
            output: &read.output,
            base,
            len: end - base,
            live_cutoff: LiveCutoff(read.live_cutoff.as_ref()),
        }
    }
}

impl ResultBody for RunBody<'_, '_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.output.kind
    }

    /// Each piece is read only while the live cutoff is not reached (FIX
    /// 8233).
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = usize::try_from(self.len.saturating_sub(offset).min(len as u64))
            .map_err(|_| Error::ArithmeticOverflow("code-run result read"))?;
        let mut bytes = Vec::with_capacity(take);
        while bytes.len() < take {
            self.live_cutoff.check()?;
            let at = self.base + offset + bytes.len() as u64;
            let piece = self
                .storage
                .read_code_run_raw_output_range(
                    self.output,
                    at,
                    (take - bytes.len()).min(READ_PIECE_BYTES),
                )?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
            if piece.is_empty() {
                break;
            }
            bytes.extend_from_slice(&piece);
        }
        Ok(bytes)
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        self.storage.code_run_line_index(self.output).ok().flatten()
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn note_search_credit(&self, offset: u64, line: u64, credit: u64) {
        self.storage
            .note_search_credit(self.output, self.base, self.len, offset, line, credit);
    }

    fn valid_search_credit(&self, offset: u64, line: u64, credit: u64) -> bool {
        self.storage
            .valid_search_credit(self.output, self.base, self.len, offset, line, credit)
    }

    fn live_cutoff(&self) -> LiveCutoff<'_> {
        self.live_cutoff
    }
}
