//! Which embeds wait for the GPU pods' hours (NIGHT-BACKFILL-HOLD = C, 15 Nov
//! 20:48; CROSS-ARCH-0024 #my-network 07: "Embeddings can run on the GPU box
//! at night"). The host reads its pods' hours; the reconciler holds the
//! queued jobs the owner's wait (`embed.pod_hours_wait`, in `setting_keys.rs`)
//! names while every pod is outside them.
use serde::{Deserialize, Serialize};

use super::EMBED_PRIORITY_BACKFILL;
use crate::setting::SettingValue;

/// The owner's "Wait for the night box": which queued embeds wait while
/// every GPU pod is outside its hours, instead of going to the endpoint.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PodHoursWait {
    /// Backfill only (imports, re-embeds after a model swap, rebuilds).
    /// Fresh writes by the owner or an agent embed at once.
    #[default]
    BackfillOnly,
    /// Every queued embed waits for the pods' hours.
    Everything,
    /// None waits: outside the hours every batch goes to the endpoint.
    Nothing,
}

impl SettingValue for PodHoursWait {}

impl PodHoursWait {
    /// Whether a job queued at `priority` waits while every pod is outside
    /// its hours.
    #[must_use]
    pub fn holds(self, priority: u8) -> bool {
        match self {
            Self::BackfillOnly => priority >= EMBED_PRIORITY_BACKFILL,
            Self::Everything => true,
            Self::Nothing => false,
        }
    }

    /// The key's tighter direction: whether `self` holds at least every embed
    /// `other` holds. Holding more keeps more batches off the endpoint, so a
    /// holder's row stays inside the owner's by waiting more, never less.
    pub(super) fn holds_at_least_as_much(&self, other: &Self) -> bool {
        self.held_kinds() >= other.held_kinds()
    }

    /// How many kinds of queued embed wait: none, backfill, or every kind.
    const fn held_kinds(self) -> u8 {
        match self {
            Self::Nothing => 0,
            Self::BackfillOnly => 1,
            Self::Everything => 2,
        }
    }
}

/// A host's GPU pods' daily hours, read once per reconciler pass: the pool
/// an endpoint embedder's document batches route through (ARCH-0019 §5, the
/// batch lane).
pub trait PodHoursClock: Send + Sync {
    /// Whether every pod keeps hours and each is outside them now, so no pod
    /// takes a new batch at this hour. A pod that keeps no hours takes
    /// batches at any hour, so a pool with one never is.
    fn outside_pod_hours(&self) -> bool;
}
