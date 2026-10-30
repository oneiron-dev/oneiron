//! The capture budget and its measured overrun: what one capture or
//! encoding copied, and the bytes it only measured past the budget.
//! `super` owns the snapshot, row readers and deletion-first marking.

use crate::error::{ArtifactError, Result};

/// The bytes a capture measured past its budget (Rule 5, FIX 6540):
/// `required` is the total `held` the measurement reached, not
/// bytes-over-limit, and `limit` is the budget it passed. No copy refuses
/// on it; its caller reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBudgetOverrun {
    pub required: usize,
    pub limit: usize,
}

/// The bytes one capture or encoding has copied, refused with
/// [`ArtifactError::OverlayLimit`] before a copy would pass `limit`.
#[derive(Debug)]
pub(in crate::recovery) struct ByteBudget {
    held: usize,
    pub(super) limit: usize,
    /// Of `held`, the bytes only measured ([`Self::measure`]), which no
    /// refusal answers for.
    measured: usize,
}

impl ByteBudget {
    pub(in crate::recovery) const fn new(limit: usize) -> Self {
        Self {
            held: 0,
            limit,
            measured: 0,
        }
    }

    /// Admits `bytes` more, before they are copied. Bytes only measured
    /// never move the point where this refuses.
    pub(in crate::recovery) fn take(&mut self, bytes: usize) -> Result<()> {
        let held = self.held.saturating_add(bytes);
        let counted = held.saturating_sub(self.measured);
        if counted > self.limit {
            return Err(ArtifactError::OverlayLimit {
                required: counted,
                limit: self.limit,
            }
            .into());
        }
        self.held = held;
        #[cfg(test)]
        held_bytes::note(counted);
        Ok(())
    }

    /// Counts `bytes` no copy refuses on (Rule 5, FIX 6540): the measure
    /// stays honest and the copy goes on. While the measure is past the
    /// limit, the overrun is returned, typed, for its caller to report.
    pub(in crate::recovery) fn measure(
        &mut self,
        bytes: usize,
    ) -> Option<RecoveryBudgetOverrun> {
        self.held = self.held.saturating_add(bytes);
        self.measured = self.measured.saturating_add(bytes);
        if self.held <= self.limit {
            return None;
        }
        Some(RecoveryBudgetOverrun {
            required: self.held,
            limit: self.limit,
        })
    }
}

/// Test hook: the most bytes any one capture or encoding held.
#[cfg(test)]
pub(in crate::recovery) mod held_bytes {
    use std::cell::Cell;

    thread_local!(static PEAK: Cell<usize> = const { Cell::new(0) });

    pub(super) fn note(held: usize) {
        PEAK.with(|peak| peak.set(peak.get().max(held)));
    }

    /// The peak since the last call; the next count starts from zero.
    #[cfg(feature = "sync")]
    pub(in crate::recovery) fn take_peak() -> usize {
        PEAK.with(|peak| peak.replace(0))
    }
}
