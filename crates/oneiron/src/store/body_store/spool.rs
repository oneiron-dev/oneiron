//! A body sink that spools its body raw for admission (FIX 5718 part 3,
//! Engine ruling 3): it measures and scans the body as it streams, as any
//! sink does, but sweeps nothing and publishes nothing. Past its inline
//! bound a vault directory's spool spills into a temp file that takes no
//! instance and is never published (sealed under a key held in memory on a
//! sealed vault); an off-record or shadow arm directory's spills as its own
//! sinks do. [`BodySink::into_spool`] hands the bytes to the side-row wall's
//! spool adapter (`batch::secret_scan::admit_spool_in_txn`), which admits
//! them in the writer that publishes the admitted body through a sink of
//! its own.

use super::{BodyDir, BodySink};
use crate::batch::secret_scan::{BodySpool, SPOOL_HEAD_BYTES};
use crate::store::BodySpill;
use crate::{Error, Result};

impl BodySink {
    /// A sink whose body is spooled raw for admission into `dir`, kept in
    /// memory up to `inline_limit`: see the module notes.
    pub(crate) fn spooling(dir: BodyDir, inline_limit: u64) -> Self {
        Self::new(dir, inline_limit, None)
    }

    /// The spill this sink's body goes to past its inline bound: an
    /// instance minted before its writer opened, for a sink that publishes
    /// into a vault directory; a temp that is never published, for a spool
    /// in one; an off-record or shadow arm directory's own.
    pub(super) fn open_spill(&self) -> Result<BodySpill> {
        match &self.mint {
            Some(mint) => BodySpill::create(&self.dir, Some(mint.mint()?)),
            None if !self.dir.session => BodySpill::ephemeral(&self.dir),
            None => BodySpill::create(&self.dir, None),
        }
    }

    /// The body this spool took, as it streamed, for admission: what its
    /// scan measured, its head, and its bytes, a spilled one in its temp
    /// file, which goes when the spool is dropped.
    ///
    /// # Errors
    ///
    /// A swept sink, which is no spool; filesystem and sealing errors.
    pub(crate) fn into_spool(mut self) -> Result<BodySpool> {
        if self.sweep.is_some() {
            return Err(Error::InvariantViolation(
                "a swept body sink is no admission spool",
            ));
        }
        let meter = self
            .meter
            .take()
            .ok_or(Error::InvariantViolation("result body sink finished twice"))?;
        let head = meter.head[..meter.head.len().min(SPOOL_HEAD_BYTES)].to_vec();
        let facts = meter.finish(0);
        let Some(spill) = self.spill.take() else {
            let bytes = std::mem::take(&mut self.inline);
            return Ok(BodySpool::held(facts, head, bytes));
        };
        let temp = spill.temp().to_owned();
        let held = spill
            .finish(&facts.digest, facts.len)
            .and_then(|spilled| spilled.reader())
            .and_then(|file| {
                let dir = BodyDir {
                    dir: self.dir.dir.try_clone()?,
                    sealed: self.dir.sealed.clone(),
                    session: self.dir.session,
                };
                Ok((file, dir))
            });
        match held {
            Ok((file, dir)) => Ok(BodySpool::spilled(facts, head, file, dir, temp)),
            Err(error) => {
                self.dir.discard(&temp);
                Err(error)
            }
        }
    }
}
