//! Door for `tests/calendar_meeting_follow_up.rs` (CAL-08 PR-E1): the check
//! the connector executor asks before every attempt of a meeting follow-up's
//! send, on one scheduled send TASK.

use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Whether the connector send TASK `task_ref` still holds the approval of
/// the meeting follow-up draft that scheduled it.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no send TASK stands under `task_ref`, and
/// every store error.
pub fn scheduled_send_authorised(vault: &Vault, task_ref: &EntityId) -> Result<bool> {
    let task = vault
        .connector_send_task(task_ref)?
        .ok_or(Error::EntityNotFound)?;
    crate::calendar::follow_up::scheduled_meeting_follow_up_authorised(vault, &task)
}
