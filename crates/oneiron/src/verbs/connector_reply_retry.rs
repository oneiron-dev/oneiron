//! FIX 2405: the owner's retry of one Failed connector reply job (Ambiguous,
//! owner-act Fault) as its queued successor now. The Failed predecessor row
//! and its kept result stay as history; the successor replays the logical
//! send through the queue's own path, as a fresh wake would.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::connector_reply_retry::{
    ConnectorReplyRetryRequest, ConnectorReplyRetryView,
};

/// `vault.connectors.replies.retry_failed` as `owner`: the owner's proof is
/// revalidated in the successor writer. The native retry queues the successor;
/// the Failed predecessor and its kept result stay as history.
///
/// # Errors
/// The owner check's refusal, a malformed attempt ref, no failed connector
/// reply job under it, a successor the guards refuse (already superseded or
/// its dedupe key held), or a vault write failure.
pub fn retry_failed_connector_reply_as(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorReplyRetryRequest,
) -> MemoryResult<ConnectorReplyRetryView> {
    let predecessor = attempt_id(&input.attempt_ref)?;
    let now = vault.now_recorded_at();
    let successor = vault.retry_failed_connector_reply_job_as(owner, predecessor, now)?;
    Ok(ConnectorReplyRetryView {
        predecessor_ref: crate::entity_id::bytes_to_hex_lower(predecessor.as_bytes()),
        successor_ref: crate::entity_id::bytes_to_hex_lower(successor.as_bytes()),
    })
}

/// The attempt id `attempt_ref` names: thirty-two hex digits, as
/// `task_verb::run_control` names a branch.
fn attempt_id(attempt_ref: &str) -> MemoryResult<AttemptId> {
    let invalid = || {
        MemoryError::bad_request_with(
            "attempt_ref must be a 32-hex attempt id",
            &["Name the Failed reply job as vault.runs.branches.get names a branch."],
        )
    };
    if attempt_ref.len() != 32 || !attempt_ref.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut bytes = [0_u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&attempt_ref[at * 2..at * 2 + 2], 16).map_err(|_| invalid())?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| invalid())
}
