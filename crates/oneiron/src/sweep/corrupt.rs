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

use crate::deletion::HardEraseSweepJob;

/// Whether a due job carries a capture failure, so this pass takes every
/// carrier.
pub(super) fn full_carrier_pass(due: &[(Vec<u8>, HardEraseSweepJob)]) -> bool {
    due.iter()
        .any(|(_, job)| !job.scope.capture_failures.is_empty())
}
