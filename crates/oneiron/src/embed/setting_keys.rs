//! The embedding queue's Setting key: the owner's "Wait for the night box"
//! (NIGHT-BACKFILL-HOLD = C, Engine 15 Nov 20:48). It sits at the vault, the
//! owner sets it through `vault.settings.set`, and the reconciler reads it in
//! each pass's writer while every GPU pod is outside its hours.

use super::gpu_pod_hours::PodHoursWait;
use crate::setting::Kind;

/// The default: only backfill waits; fresh writes embed at once.
fn backfill_only() -> PodHoursWait {
    PodHoursWait::BackfillOnly
}

/// The strict side, what an unreadable row reads as: every embed waits for
/// the pods' hours, so none goes to the endpoint outside them.
fn everything() -> PodHoursWait {
    PodHoursWait::Everything
}

crate::setting::setting_keys! {
    /// Wait for the night box: which queued embeds wait for the GPU pods' hours while every pod
    /// is outside them, instead of going to the endpoint. `backfill_only` (imports, re-embeds
    /// after a model swap, rebuilds; fresh writes embed at once), `everything`, or `nothing`.
    pub(crate) POD_HOURS_WAIT: PodHoursWait = "embed.pod_hours_wait" {
        kind: Kind::new(backfill_only)
            .strictest(everything)
            .tighter(PodHoursWait::holds_at_least_as_much),
    };
}
