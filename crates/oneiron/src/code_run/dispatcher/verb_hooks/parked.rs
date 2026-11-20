//! The hook pause a parked call names when the run makes it again (FIX
//! 5526): the ask an earlier try of the same call parked on, read from the
//! run's own history (its wait's id), never from the guest. The handle names
//! the pause only, beside the invocation the call takes again: the call keeps
//! its run's caller and authority, and a named pause that is gone refuses
//! rather than running as a new call.
//!
//! The row holds the call's request as the side-row wall stored it: each
//! value base custody holds as its handle, where the call made again holds
//! the value. Such a call resumes its ask when the two meet as the replay
//! cursor reads them, and the ask saved the call's own args, the request as
//! the guest made it before the wall took any value (FIX
//! PARKED-HOOK-LIVE-EXACT-COMPARE). A handle names a custody record at every
//! generation it keeps, so the saved args alone tell the value the owner was
//! asked about from one the record took since.
//!
//! An erase can take the words of the row that parked a call (FIX 6534).
//! The note keeps that row, so the same call made again still meets it: by
//! the identity the row keeps, under the row's own host stamps. That call
//! answers that its reply was erased. It never asks again, never resumes
//! the old ask and never runs its effect.

use crate::code_run::payload::self_call_request_value;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfCall, SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::code_run::{CompareKnown, RESPONSE_ERASED};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::{VerbCall, VerbHookStorage};

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{
    bridge_stamped, entry, hook_args, hook_class, hook_domain, parked_call, parked_invocation,
};

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
    /// again: the first note whose ask it resumes
    /// ([`ParkedHook::resumed_by`]). `None` for a call nothing parked, and
    /// outside a durable run.
    pub(super) fn parked_hook<T>(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read: impl FnOnce(&ParkedHook) -> T,
    ) -> Result<Option<T>> {
        if site.is_none() {
            return Ok(None);
        }
        let base_known = || self.base_known_values();
        let known = CompareKnown::new(Some(&base_known));
        for parked in &*self.parked_hooks.borrow() {
            if parked.resumed_by(call, &known, || self.parked_ask_args(parked, call))? {
                return Ok(Some(read(parked)));
            }
        }
        Ok(None)
    }

    /// The args the ask `parked` waits on saved for its call, read as the
    /// hook boundary reads them, under `call`'s verb and this run's actor and
    /// class. `None` in a room's run, whose saved calls sit in the session's
    /// keep: there a call meets its note only as written.
    fn parked_ask_args(
        &self,
        parked: &ParkedHook,
        call: &SelfCall,
    ) -> Result<Option<serde_json::Value>> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(None);
        };
        let saved = VerbCall {
            verb: call.effect().as_str().to_owned(),
            invocation: parked.invocation,
            actor: self.actor.entity_ref(),
            class: hook_class(self.actor.actor_class()),
            scope: None,
            board_epoch: None,
            turn: None,
            domain: hook_domain(call),
            reader: None,
        };
        vault.verb_hook_saved_args(VerbHookStorage::Canonical, &saved)
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
    /// the identity the row keeps, each value base custody holds read through
    /// `known` as the stand-in there (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS).
    /// Two erased requests compare their erased forms. A call of another
    /// effect is another call.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, one that does not encode,
    /// or the read of base custody's values.
    pub(super) fn meets(&self, offered: ParkedOffer<'_>, known: &CompareKnown<'_>) -> Result<bool> {
        let row = &self.row;
        if row.effect != offered.effect() {
            return Ok(false);
        }
        match (row.request_erased(), offered) {
            (true, ParkedOffer::Call(call)) => {
                let restamped = call.clone().with_bridge_stamp(row.seq, row.started_at_ms);
                row.request_identity_is(&self_call_request_value(&restamped)?, known)
            }
            (true, ParkedOffer::Row(later)) if !later.request_erased() => {
                row.request_identity_is(&stamped_as(&later.request, row), known)
            }
            (false, ParkedOffer::Row(later)) if later.request_erased() => {
                later.request_identity_is(&stamped_as(&row.request, later), known)
            }
            _ => Ok(parked_call(row.effect, row.request.clone())
                == parked_call(offered.effect(), offered.request()?)),
        }
    }

    /// Whether `call`, made again, resumes this note's ask: it meets the
    /// note ([`Self::meets`]), or its live row once each value base custody
    /// holds, read through `known`, meets the handle the side-row wall
    /// placed for it there, as the replay cursor reads a row (FIX
    /// PARKED-HOOK-LIVE-EXACT-COMPARE), and the ask saved `call`'s own args,
    /// which `saved` reads. A handle meets every generation its record keeps,
    /// so only the saved args tell the value the owner was asked about from
    /// one the record took since (blind review round 1 of #9676). An ask
    /// that saved no args, or other ones, is not this call's.
    ///
    /// # Errors
    ///
    /// Those of [`Self::meets`], the call's args, or `saved`'s read.
    pub(super) fn resumed_by(
        &self,
        call: &SelfCall,
        known: &CompareKnown<'_>,
        saved: impl FnOnce() -> Result<Option<serde_json::Value>>,
    ) -> Result<bool> {
        if self.meets(ParkedOffer::Call(call), known)? {
            return Ok(true);
        }
        let row = &self.row;
        if row.effect != call.effect() || row.request_erased() {
            return Ok(false);
        }
        let (_, held) = parked_call(row.effect, row.request.clone());
        let (_, again) = parked_call(call.effect(), self_call_request_value(call)?);
        if !known.admits(&held, &again)? {
            return Ok(false);
        }
        let args = hook_args(call)?;
        Ok(saved()?.is_some_and(|saved| saved == args))
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
