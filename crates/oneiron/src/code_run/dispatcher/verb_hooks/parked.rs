//! The hook pause a parked call names when the run makes it again (FIX
//! 5526): the ask an earlier try of the same call parked on, read from the
//! run's own history (its wait's id), never from the guest. The handle names
//! the pause only, beside the invocation the call takes again: the call keeps
//! its run's caller and authority, and a named pause that is gone refuses
//! rather than running as a new call.
//!
//! An erase can take the words of the row that parked a call (FIX 6534).
//! The note keeps that row, so the same call made again still meets it: by
//! the identity the row keeps, under the row's own host stamps. That call
//! answers that its reply was erased. It never asks again, never resumes
//! the old ask and never runs its effect.

use crate::code_run::RESPONSE_ERASED;
use crate::code_run::payload::self_call_request_value;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::types::{SelfCall, SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::runtime_hooks::InvocationId;

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{bridge_stamped, entry, parked_call, parked_invocation};

/// A call a verb hook's ask parked, as the run's history shows it (FIX
/// 5526): the row that parked it, the invocation its ask waits under and
/// the ask's handle. The row keeps the call's effect, its host stamps and
/// its request, live or erased (FIX 6534).
pub(crate) struct ParkedHook {
    row: CodeRunBridgeCall,
    invocation: InvocationId,
    ask: Option<EntityId>,
}

/// A call offered against the parked ones: the call the run makes now, or
/// a later row of its history.
#[derive(Clone, Copy)]
pub(super) enum ParkedOffer<'a> {
    Call(&'a SelfCall),
    Row(&'a CodeRunBridgeCall),
}

impl HostSelfDispatcher<'_> {
    /// The ask handle of the hook pause `call` resumes: the one an earlier
    /// try of the same call in this durable run parked on. `None` for a call
    /// nothing parked, and outside a durable run.
    pub(in crate::code_run::dispatcher) fn parked_ask(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<Option<EntityId>> {
        Ok(self.parked_hook(call, site, |parked| parked.ask)?.flatten())
    }

    /// The answer to `call` when a hook's ask parked an earlier try of it on
    /// a row an erase took the words of (FIX 6534): its reply was erased.
    /// The call asks no hook again, resumes no ask and runs no effect.
    /// `None` for every other call.
    pub(super) fn parked_erased_answer(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<Option<SelfDispatchOutcome>> {
        if self.parked_hook(call, site, |parked| parked.row.request_erased())? != Some(true) {
            return Ok(None);
        }
        Ok(Some(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: RESPONSE_ERASED.to_owned(),
            code: None,
            disk_floor: None,
        })))
    }

    /// What `read` takes from the note of the parked call `call` makes
    /// again: the first note it meets. `None` for a call nothing parked,
    /// and outside a durable run.
    pub(super) fn parked_hook<T>(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read: impl FnOnce(&ParkedHook) -> T,
    ) -> Result<Option<T>> {
        if site.is_none() {
            return Ok(None);
        }
        for parked in &*self.parked_hooks.borrow() {
            if parked.meets(ParkedOffer::Call(call))? {
                return Ok(Some(read(parked)));
            }
        }
        Ok(None)
    }
}

impl ParkedHook {
    /// The note `row` makes when it parked its call on a hook's ask. `None`
    /// for a row that parked nothing.
    pub(super) fn of(row: &CodeRunBridgeCall) -> Option<Self> {
        Some(Self {
            invocation: parked_invocation(&row.outcome)?,
            ask: ask_of(&row.outcome),
            row: row.clone(),
        })
    }

    /// The invocation the parked call's ask waits under.
    pub(super) fn invocation(&self) -> InvocationId {
        self.invocation
    }

    /// Whether `offered` is the call this note parked. Two live requests
    /// compare whole, less the bridge's own stamps. When an erase took
    /// the words of one side only (FIX 6534), that side's row meets the
    /// other's request as made under the row's own seq and start clock, by
    /// the identity the row keeps. Two erased requests compare their erased
    /// forms. A call of another effect is another call.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, or one that does not encode.
    pub(super) fn meets(&self, offered: ParkedOffer<'_>) -> Result<bool> {
        let row = &self.row;
        if row.effect != offered.effect() {
            return Ok(false);
        }
        match (row.request_erased(), offered) {
            (true, ParkedOffer::Call(call)) => {
                let restamped = call.clone().with_bridge_stamp(row.seq, row.started_at_ms);
                row.request_identity_is(&self_call_request_value(&restamped)?)
            }
            (true, ParkedOffer::Row(later)) if !later.request_erased() => {
                row.request_identity_is(&stamped_as(&later.request, row))
            }
            (false, ParkedOffer::Row(later)) if later.request_erased() => {
                later.request_identity_is(&stamped_as(&row.request, later))
            }
            _ => Ok(parked_call(row.effect, row.request.clone())
                == parked_call(offered.effect(), offered.request()?)),
        }
    }
}

impl ParkedOffer<'_> {
    fn effect(self) -> SelfEffect {
        match self {
            Self::Call(call) => call.effect(),
            Self::Row(row) => row.effect,
        }
    }

    /// The offered request as made at its own place in the run.
    fn request(self) -> Result<rmpv::Value> {
        match self {
            Self::Call(call) => self_call_request_value(call),
            Self::Row(row) => Ok(row.request.clone()),
        }
    }
}

/// `request`, a live request of a call of `row`'s effect, as made under
/// `row`'s host stamps: a speech bubble's or a blocked report's order and
/// time take the values [`SelfCall::with_bridge_stamp`] gives at `row`'s
/// seq and start clock. Every other request is unchanged.
fn stamped_as(request: &rmpv::Value, row: &CodeRunBridgeCall) -> rmpv::Value {
    let mut request = request.clone();
    if bridge_stamped(row.effect)
        && let rmpv::Value::Map(entries) = &mut request
    {
        let order = u32::try_from(row.seq).unwrap_or(u32::MAX);
        for (key, value) in entries {
            match key.as_str() {
                Some("order") => *value = rmpv::Value::from(order),
                Some("occurred_at") => *value = rmpv::Value::from(row.started_at_ms / 1000),
                _ => {}
            }
        }
    }
    request
}

/// The ask a recorded outcome parked a call on: its wait's id. Read only for
/// a wait that names a verb hook's invocation.
pub(super) fn ask_of(outcome: &rmpv::Value) -> Option<EntityId> {
    let rmpv::Value::Binary(bytes) = entry(outcome, "wait_id")? else {
        return None;
    };
    EntityId::from_bytes(<[u8; 16]>::try_from(bytes.as_slice()).ok()?).ok()
}
