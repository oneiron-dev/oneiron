//! The hook pause a parked call names when the run makes it again (FIX
//! 5526): the ask an earlier try of the same call parked on, read from the
//! run's own history (its wait's id), never from the guest. The handle names
//! the pause only, beside the invocation the call takes again: the call keeps
//! its run's caller and authority, and a named pause that is gone refuses
//! rather than running as a new call.

use crate::code_run::payload::self_call_request_value;
use crate::code_run::types::SelfCall;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{entry, parked_call};

impl HostSelfDispatcher<'_> {
    /// The ask handle of the hook pause `call` resumes: the one an earlier
    /// try of the same call in this durable run parked on. `None` for a call
    /// nothing parked, and outside a durable run.
    pub(in crate::code_run::dispatcher) fn parked_ask(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<Option<EntityId>> {
        if site.is_none() || self.parked_hooks.borrow().is_empty() {
            return Ok(None);
        }
        let key = parked_call(call.effect(), self_call_request_value(call)?);
        Ok(self
            .parked_hooks
            .borrow()
            .iter()
            .find(|(held, ..)| *held == key)
            .and_then(|(_, _, ask)| *ask))
    }
}

/// The ask a recorded outcome parked a call on: its wait's id. Read only for
/// a wait that names a verb hook's invocation.
pub(super) fn ask_of(outcome: &rmpv::Value) -> Option<EntityId> {
    let rmpv::Value::Binary(bytes) = entry(outcome, "wait_id")? else {
        return None;
    };
    EntityId::from_bytes(<[u8; 16]>::try_from(bytes.as_slice()).ok()?).ok()
}
