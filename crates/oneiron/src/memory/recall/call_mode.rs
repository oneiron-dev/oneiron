//! Call mode (retrieval hub #call-mode): recall for live calls. It is light
//! effort under a hard deadline: at the deadline it returns the best results
//! ready, marked partial, and it never holds the turn past it. Deep recall and
//! Dreamer-chat keep the slower, deadline-free mode.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::Effort;
use crate::memory::MemoryResult;

/// Call mode's deadline unless a vault sets its own. ARCH-0042
/// #call-mode-budget holds call-mode recall at p95 ≤ 100 ms server-side at
/// 10k records (≤ 150 ms at 100k), a starting bar the perf pass drives
/// lower. It is the default of [`crate::VaultConfig::call_mode_deadline`],
/// and a request's own `deadline_ms` overrides that.
pub const DEFAULT_CALL_MODE_DEADLINE: Duration = Duration::from_millis(100);

/// Where a recall request sets the one effort dial: one of the five effort
/// levels, or `call`, the call mode for live calls. Call mode is a position
/// on the dial, not a sixth level: it runs [`Effort::Light`] under a hard
/// deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecallEffort {
    Light,
    Medium,
    High,
    Xhigh,
    Max,
    /// Light effort under a hard deadline: the request's `deadline_ms`, or
    /// else the vault's call-mode deadline.
    Call,
}

impl RecallEffort {
    /// The effort level the request runs at.
    #[must_use]
    pub const fn level(self) -> Effort {
        match self {
            Self::Light | Self::Call => Effort::Light,
            Self::Medium => Effort::Medium,
            Self::High => Effort::High,
            Self::Xhigh => Effort::Xhigh,
            Self::Max => Effort::Max,
        }
    }
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "call" => Some(Self::Call),
            level => Effort::parse(level).map(Self::from),
        }
    }
}

impl From<Effort> for RecallEffort {
    fn from(effort: Effort) -> Self {
        match effort {
            Effort::Light => Self::Light,
            Effort::Medium => Self::Medium,
            Effort::High => Self::High,
            Effort::Xhigh => Self::Xhigh,
            Effort::Max => Self::Max,
        }
    }
}

/// What a recall request's dial and raw deadline resolve to: the level it
/// runs at, and the hard deadline it answers by, if it has one. Omitted, the
/// dial is medium; call mode without its own `deadline_ms` takes
/// `call_mode_deadline`, the vault's setting.
pub fn resolve_recall_dial(
    effort: Option<RecallEffort>,
    deadline_ms: Option<u64>,
    call_mode_deadline: Duration,
) -> MemoryResult<(Effort, Option<Duration>)> {
    crate::memory::caps::check_deadline_ms(deadline_ms)?;
    let effort = effort.unwrap_or(RecallEffort::Medium);
    let deadline = deadline_ms
        .map(Duration::from_millis)
        .or((effort == RecallEffort::Call).then_some(call_mode_deadline));
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
    /// receipt the recall reads with.
    pub(crate) fn recall_cut_pack(
        &self,
        scope: &super::RecallScope,
    ) -> MemoryResult<super::MemoryPack> {
        let worlds = self.recall_worlds(scope)?;
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Surfaceable)?;
        let lane = match worlds {
            Some(worlds) => lane.within_worlds(worlds),
            None => lane,
        };
        let receipt = lane.read_receipt(None, 0)?;
        Ok(super::cut_pack(&receipt))
    }
}
