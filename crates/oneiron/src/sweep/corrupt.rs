//! The full-carrier pass a corrupt CLAIM's erase asks of the sweep (FIX 7800,
//! ARCH-0038).
//!
//! A hard erase that took the audited corrupt-CLAIM exception read neither
//! the CLAIM's world nor its subject, so its due job asks for every carrier:
//! each persisted window and document, as a due obligation's pass already
//! compacts them, and the queued sends of every window, one with no persisted
//! state left among them, through the queue scrub and full-resync repair a due
//! withdrawn generation uses. Delete-bearing sends stay. No second compactor:
//! the pass is the existing one, its holds, race guards and strict cut kept.
//!
//! Such a pass, and a due withdrawn generation's, also drops each queued send
//! that names no window (FIX 9389): no window's scrub reaches one while no
//! window is labelled, so the pass reports no completion while one is left.

#[cfg(feature = "sync")]
use super::run::WindowSweepState;
#[cfg(feature = "sync")]
use crate::Vault;
use crate::deletion::HardEraseSweepJob;
#[cfg(feature = "sync")]
use crate::error::Result;

/// Whether a due job carries a capture failure, so this pass takes every
/// carrier.
pub(super) fn full_carrier_pass(due: &[(Vec<u8>, HardEraseSweepJob)]) -> bool {
    due.iter()
        .any(|(_, job)| !job.scope.capture_failures.is_empty())
}

/// Drops the queued sends that name no window when this pass drops sends,
/// then reads whether any are left: a pass that left one reports no
/// completion, and one that could not drop them reports its failure, by the
/// pinned precedence. Delete-bearing sends stay and count for nothing.
#[cfg(feature = "sync")]
pub(super) fn settle_unlabelled_sends(
    vault: &Vault,
    scrub_sends: bool,
    state: &mut WindowSweepState,
) -> Result<()> {
    if !scrub_sends {
        return Ok(());
    }
    let dropped = vault.with_write_txn_grouped(|wtxn| {
        crate::sync::queue::scrub_unlabelled_updates_in_txn(vault, wtxn)
    });
    match dropped {
        Ok(0) => {}
        Ok(dropped) => tracing::warn!(
            dropped,
            "sweep: queued sends that name no window dropped — no window is left to re-send them"
        ),
        Err(err) => {
            if !matches!(state, WindowSweepState::Failed(_)) {
                *state = WindowSweepState::Failed(format!("{:?}", err.kind()));
            }
            return Ok(());
        }
    }
    let left = {
        let rtxn = vault.store.env.read_txn()?;
        crate::sync::queue::unlabelled_update_count_in_txn(vault, &rtxn)?
    };
    if left > 0 && matches!(state, WindowSweepState::AllCompacted) {
        tracing::warn!(
            left,
            "sweep: queued sends that name no window remain — deferred"
        );
        *state = WindowSweepState::Deferred;
    }
    Ok(())
}
