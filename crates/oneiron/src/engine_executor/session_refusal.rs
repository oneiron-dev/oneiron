//! An off-record session's refusal of one act a run took in it (FIX
//! OFF-RECORD-RUN-POLICY-REFUSAL-500).

use crate::{Error, ErrorKind};

/// Whether `error` is an off-record session's refusal of one act a run took
/// in it: a durable write in a talk-only session, a caller no longer in the
/// session's room, a write route the room's mode flip closed, or an overlay
/// with no room left for the write. Entering the run again meets the same
/// refusal, so the step that met it ends on it, whatever its guest then did
/// (the guest's throw carries none of its words), and the run's door answers
/// it as the caller's refusal, never as a failure of the run.
#[must_use]
pub fn is_session_act_refusal(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::OffRecordTalkOnly
            | ErrorKind::OffRecordNotInRoom
            | ErrorKind::OffRecordOverlayLeaseClosed
            | ErrorKind::OffRecordOverlayFull
    )
}
