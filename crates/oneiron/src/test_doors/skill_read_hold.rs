//! Door for `tests/primitive_a_skill_reader.rs` (#6976 review round 2): holds
//! a skill read by a caller other than the owner at the point where its own
//! read has admitted the skill's row, so the test can commit an owner write
//! in that gap and show which state the served view comes from.

use std::cell::RefCell;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

/// How long a held read waits for the test to resume it.
const RESUME_WAIT: Duration = Duration::from_secs(60);

thread_local! {
    static HOLD: RefCell<Option<(SyncSender<()>, Receiver<()>)>> = const { RefCell::new(None) };
}

/// Holds this thread's next skill read at the point its read admits a row:
/// the read sends on `admitted`, then waits on `resume` (at most a minute).
pub fn hold_next_read(admitted: SyncSender<()>, resume: Receiver<()>) {
    HOLD.with(|hold| *hold.borrow_mut() = Some((admitted, resume)));
}

/// The hold point; a no-op unless [`hold_next_read`] armed this thread.
pub(crate) fn at_row_admitted() {
    if let Some((admitted, resume)) = HOLD.with(|hold| hold.borrow_mut().take()) {
        let _ = admitted.send(());
        let _ = resume.recv_timeout(RESUME_WAIT);
    }
}
