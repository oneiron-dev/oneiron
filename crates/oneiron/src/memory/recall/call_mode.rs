//! Call mode (retrieval hub #call-mode): recall for live calls. It is light
//! effort under a hard deadline: at the deadline it returns the best results
//! ready, marked partial, and it never holds the turn past it. Deep recall and
//! Dreamer-chat keep the slower, deadline-free mode.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::Effort;
use crate::memory::MemoryResult;

pub use crate::request_limits::DEFAULT_CALL_MODE_DEADLINE;

/// Light recall's default deadline when the caller sets none (FIX 11572).
pub(super) const LIGHT_RECALL_DEFAULT_DEADLINE_MS: u64 = 5_000;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::recall::call_mode::RecallEffort;

/// What a recall request's dial and raw deadline resolve to: the level it
/// runs at, and the hard deadline it answers by, if it has one. Omitted, the
/// dial is medium; call mode without its own `deadline_ms` takes
/// `call_mode_deadline`, the vault's setting; light without its own
/// `deadline_ms` takes [`LIGHT_RECALL_DEFAULT_DEADLINE_MS`].
pub fn resolve_recall_dial(
    effort: Option<RecallEffort>,
    deadline_ms: Option<u64>,
    call_mode_deadline: Duration,
) -> MemoryResult<(Effort, Option<Duration>)> {
    crate::memory::caps::check_deadline_ms(deadline_ms)?;
    let effort = effort.unwrap_or(RecallEffort::Medium);
    let deadline = deadline_ms
        .map(Duration::from_millis)
        .or((effort == RecallEffort::Call).then_some(call_mode_deadline))
        .or((effort == RecallEffort::Light)
            .then_some(Duration::from_millis(LIGHT_RECALL_DEFAULT_DEADLINE_MS)));
    Ok((effort.level(), deadline))
}

impl crate::Vault {
    /// How long a call-mode recall without its own `deadline_ms` may take:
    /// this vault's [`crate::VaultConfig::call_mode_deadline`].
    #[must_use]
    pub fn call_mode_deadline(&self) -> Duration {
        self.config.call_mode_deadline
    }
}

impl crate::memory::Memory<'_> {
    /// The call-mode deadline of the vault this facade reads.
    #[must_use]
    pub fn call_mode_deadline(&self) -> Duration {
        self.vault.call_mode_deadline()
    }

    /// The pack a recall with `scope` answers with when its door stops
    /// waiting before retrieval ran: no items, marked partial, under the
    /// receipt the recall reads with. Its worlds are the recall's own,
    /// pinned in the door's `pin` (FIX 6693); the credential is read now.
    pub(crate) fn recall_cut_pack(
        &self,
        scope: &super::RecallScope,
        pin: &super::selection::RecallPin,
    ) -> MemoryResult<super::MemoryPack> {
        let worlds = self.recall_door_worlds(scope, pin)?;
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Surfaceable)?;
        let lane = match worlds {
            Some(worlds) => lane.within_worlds(worlds),
            None => lane,
        };
        let receipt = lane.read_receipt(None, 0)?;
        Ok(super::cut_pack(self.vault, &receipt))
    }
}
