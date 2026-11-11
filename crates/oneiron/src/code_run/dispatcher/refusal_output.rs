//! Released reason bodies captured from the actual accepted refusal call.

use super::HostSelfDispatcher;
use crate::Vault;
use crate::claim::ScopedReadActorKey;
use crate::task_verb::ConsultPayloadRef;

impl HostSelfDispatcher<'_> {
    pub(super) fn capture_task_refusal_output(
        &self,
        vault: &Vault,
        reader: Option<ScopedReadActorKey>,
        reason: ConsultPayloadRef,
    ) {
        let Some(reader) = reader else {
            return;
        };
        match crate::task_verb::run_rows::task_refusal::released_reason_body(vault, reader, reason)
        {
            Ok(bytes) => *self.task_refusal_output.borrow_mut() = bytes,
            Err(error) => {
                tracing::warn!(error = %error, "accepted task refusal reason is unavailable");
            }
        }
    }

    pub(crate) fn take_task_refusal_output(&self) -> Option<Vec<u8>> {
        self.task_refusal_output.borrow_mut().take()
    }
}
