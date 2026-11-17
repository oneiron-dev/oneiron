//! The embedding owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file. The owner sets them through `vault.settings.set`.
//! - The space move's undo window.
//! - "Wait for the night box" (NIGHT-BACKFILL-HOLD = C, Engine 15 Nov 20:48): it sits at the
//!   vault, and the reconciler reads it in each pass's writer while every GPU pod is outside its
//!   hours.

use serde::{Deserialize, Serialize};

use super::gpu_pod_hours::PodHoursWait;
use super::space_move::SPACE_MOVE_UNDO_WINDOW_SECS;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// The longest undo window a value may name: ten years, in seconds.
pub(crate) const SPACE_MOVE_UNDO_WINDOW_CEILING_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Seconds a swapped-in space move stays undoable: 0 to [`SPACE_MOVE_UNDO_WINDOW_CEILING_SECS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct SpaceMoveUndoWindowSecs(pub(crate) u64);

impl SettingValue for SpaceMoveUndoWindowSecs {
    fn check(self) -> Result<Self> {
        if self.0 > SPACE_MOVE_UNDO_WINDOW_CEILING_SECS {
            return Err(Error::InvalidConfig(
                "a space move's undo window is at most ten years".into(),
            ));
        }
        Ok(self)
    }
}

/// Thirty days: the window before the owner moves it, and what an unreadable row reads as, so a
/// damaged row never retires an old space sooner than today.
fn thirty_days() -> SpaceMoveUndoWindowSecs {
    SpaceMoveUndoWindowSecs(SPACE_MOVE_UNDO_WINDOW_SECS)
}

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
    /// How long a swapped-in embedding space move can be undone, in seconds; thirty days by
    /// default. When the window passes, the old space retires and the move can no longer be
    /// undone. A raise keeps the old space, its rows and its declaration, for longer, and is the
    /// looser value; a lower value retires it sooner. Only the owner sets it.
    pub(crate) SPACE_MOVE_UNDO_WINDOW: SpaceMoveUndoWindowSecs = "embed.space_move.undo_window_secs" {
        kind: Kind::new(thirty_days)
            .strictest(thirty_days)
            .lower(),
    };

    /// Wait for the night box: which queued embeds wait for the GPU pods' hours while every pod
    /// is outside them, instead of going to the endpoint. `backfill_only` (imports, re-embeds
    /// after a model swap, rebuilds; fresh writes embed at once), `everything`, or `nothing`.
    pub(crate) POD_HOURS_WAIT: PodHoursWait = "embed.pod_hours_wait" {
        kind: Kind::new(backfill_only)
            .strictest(everything)
            .tighter(PodHoursWait::holds_at_least_as_much),
    };
}
