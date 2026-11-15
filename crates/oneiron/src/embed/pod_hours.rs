//! Which embeds wait for the GPU pods' hours (NIGHT-BACKFILL-HOLD = C, 15 Nov
//! 20:48; CROSS-ARCH-0024 #my-network 07: "Embeddings can run on the GPU box
//! at night"). The host reads its pods' hours; the reconciler holds the
//! queued jobs the wait names while every pod is outside them.
use super::EMBED_PRIORITY_BACKFILL;

/// The owner's "Wait for the night box": which queued embeds wait while
/// every GPU pod is outside its hours, instead of going to the endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
