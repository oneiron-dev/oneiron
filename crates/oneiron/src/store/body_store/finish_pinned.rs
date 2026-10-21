//! A body finished under its reader's pin (FIX 5399b). A swept sink's tail
//! is written through once, so the digest the sink holds after it is the
//! one its finish names the body by, and the pin on that digest is taken
//! before a spilled body's file is published under it. A collector that
//! finds the pin leaves the file be until the writer that names it is done.

use super::{BodyFacts, BodySink, SunkBody};
use crate::Result;

impl BodySink {
    /// Writes the sweep's tail through, once: the digest the sink holds
    /// after it is the final one. A sink that sweeps nothing, or whose tail
    /// is through already, writes nothing.
    ///
    /// # Errors
    ///
    /// Custody errors reading the sweep's values; filesystem errors.
    pub(crate) fn finalize_sweep(&mut self) -> Result<()> {
        if let Some(sweep) = self.sweep.take() {
            self.write_through(&sweep.tail()?)?;
        }
        Ok(())
    }

    /// [`Self::finish`], with `pin` taken on the body's final digest, its
    /// sweep's tail written through once, before a spilled body is published
    /// under it: the body's facts, where it went, and the pin, for the
    /// caller to hold until the row naming the body commits or is dropped.
    ///
    /// # Errors
    ///
    /// As [`Self::finish`].
    pub(crate) fn finish_pinned<P>(
        mut self,
        preview_chars: usize,
        pin: impl FnOnce([u8; 32]) -> P,
    ) -> Result<(BodyFacts, SunkBody, P)> {
        self.finalize_sweep()?;
        let pin = pin(self.digest()?);
        let (facts, sunk) = self.finish(preview_chars)?;
        Ok((facts, sunk, pin))
    }
}
