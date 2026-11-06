//! A bridge request's identity apart from its words (FIX 6534).
//!
//! An erase of a run's replies takes the words its bridge requests copied
//! from them too: a request the run built from an earlier reply holds that
//! reply's words, and a hook's rewrite of it is one more copy. The erased
//! form of a request keeps its identity alone: the BLAKE3 digest of its
//! canonical MessagePack, read in the form the side-row wall compares a
//! held row and a raw offer in, so a masked row and the call it was
//! admitted from have one identity. A program resume page lists the same
//! digest. The guest's original request and a hook's rewrite each keep
//! their own.
//!
//! The erased form is a typed map no live request spells: `{state: erased,
//! cause: response_erased, identity: <32 bytes>}`. A spawn whose ask is a
//! typed marker, an erased target's or a barrier's, keeps that marker as
//! its `ask`, and its identity leaves the ask out, as its match does. An
//! erased request meets a call by its identity alone: a hit answers with
//! the call's own recorded outcome, and every other call drifts. It is
//! never a wildcard and never a spawn's miss, so no fresh effect runs in
//! its place. A live request keeps its full value and its `admitted_from`
//! matching.

use rmpv::Value;

use super::super::spawn_replay::{
    ReplayRequestMatch, ask_of, is_barrier_ask, is_erased_ask, without_ask,
};
use super::super::support::{invalid_code_run_replay, request_map};
use super::super::types::SelfEffect;
use super::CodeRunBridgeCall;
use crate::Result;
use crate::batch::secret_scan::admission_form;
use crate::code_run::RESPONSE_ERASED;

/// The domain of a bridge request's identity digest.
const REQUEST_IDENTITY_DOMAIN: &[u8] = b"oneiron:code-run:bridge-request-identity:v1";

/// The keys of an erased request, in order. `ask` is a spawn's alone.
const ERASED_REQUEST_KEYS: [&str; 4] = ["state", "cause", "identity", "ask"];

/// The `state` an erased request names.
const ERASED_STATE: &str = "erased";

/// One erased request as a row stores it: the identity it keeps, and the
/// typed ask of a spawn whose ask was one.
#[derive(Debug, Clone, Copy)]
pub(in crate::code_run) struct ErasedRequest<'a> {
    identity: [u8; 32],
    ask: Option<&'a Value>,
}

impl<'a> ErasedRequest<'a> {
    /// `request` read as an erased request, in its one spelling. `None` for
    /// any other value, every live request among them.
    pub(in crate::code_run) fn of(request: &'a Value) -> Option<Self> {
        let Value::Map(fields) = request else {
            return None;
        };
        let (state, cause, identity, ask) = match fields.as_slice() {
            [state, cause, identity] => (state, cause, identity, None),
            [state, cause, identity, ask] => (state, cause, identity, Some(ask)),
            _ => return None,
        };
        if keyed(state, ERASED_REQUEST_KEYS[0])?.as_str() != Some(ERASED_STATE)
            || keyed(cause, ERASED_REQUEST_KEYS[1])?.as_str() != Some(RESPONSE_ERASED)
        {
            return None;
        }
        let Value::Binary(identity) = keyed(identity, ERASED_REQUEST_KEYS[2])? else {
            return None;
        };
        let ask = match ask {
            None => None,
            Some(entry) => Some(keyed(entry, ERASED_REQUEST_KEYS[3]).filter(|ask| typed(ask))?),
        };
        Some(Self {
            identity: <[u8; 32]>::try_from(identity.as_slice()).ok()?,
            ask,
        })
    }

    /// How this erased request meets `offered`, the request its call makes
    /// now under the row's own bridge stamp: a hit only when `offered` has
    /// the identity it keeps, and drift for every other request, never a
    /// spawn's miss. A spawn whose ask was a typed marker meets an offer
    /// that asks something and has its identity in every other field, as
    /// its live row's match did.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, or one that does not encode.
    pub(in crate::code_run) fn meets(&self, offered: &Value) -> Result<ReplayRequestMatch> {
        let identity = match (self.ask, offered) {
            (None, _) => canonical_digest(offered)?,
            (Some(_), Value::Map(fields)) if ask_of(fields).is_some_and(Value::is_str) => {
                canonical_digest(&without_ask(fields))?
            }
            (Some(_), _) => return Ok(ReplayRequestMatch::Drift),
        };
        Ok(if identity == self.identity {
            ReplayRequestMatch::Hit
        } else {
            ReplayRequestMatch::Drift
        })
    }
}

/// Whether `request` holds the erased form (FIX 6534).
pub(in crate::code_run) fn is_erased_request(request: &Value) -> bool {
    ErasedRequest::of(request).is_some()
}

impl CodeRunBridgeCall {
    /// Whether an erase took this call's request words (FIX 6534): its
    /// request holds the erased form.
    #[must_use]
    pub(crate) fn request_erased(&self) -> bool {
        is_erased_request(&self.request)
    }

    /// The request this call dispatched: a hook's rewrite where one rewrote
    /// it, else the guest's own. `None` once an erase took its words (FIX
    /// 6534): no reader takes the erased form for a live call.
    #[must_use]
    pub(crate) fn dispatched_request(&self) -> Option<&Value> {
        let dispatched = self.rewritten_request.as_ref().unwrap_or(&self.request);
        (!is_erased_request(dispatched)).then_some(dispatched)
    }

    /// The text-free identity of the guest's original request (FIX 6534):
    /// the one its erased form keeps, or the one its live request has.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, or one that does not encode.
    pub(crate) fn request_identity(&self) -> Result<[u8; 32]> {
        match ErasedRequest::of(&self.request) {
            Some(erased) => Ok(erased.identity),
            None => live_identity(self.effect, &self.request),
        }
    }

    /// Whether this call dispatched `offered`, a kept or an erased row read
    /// one way (FIX 6534): the very value while its words are kept, and its
    /// identity once an erase took them.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, or one that does not encode.
    pub(crate) fn dispatched_request_is(&self, offered: &Value) -> Result<bool> {
        let dispatched = self.rewritten_request.as_ref().unwrap_or(&self.request);
        match ErasedRequest::of(dispatched) {
            Some(erased) => Ok(erased.meets(offered)?.is_hit()),
            None => Ok(dispatched == offered),
        }
    }

    /// Erases this call's request words (FIX 6534): the guest's original
    /// request and a hook's rewrite each take their erased form, with the
    /// identity each had. Every other field stays as it is: its seq,
    /// effect, outcome, times, action digest, targets and hook view, and so
    /// its receipts and the effect it stands for. `true` when the call
    /// changed; one already erased is left as it is.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, or one that does not encode.
    pub(crate) fn erase_request(&mut self) -> Result<bool> {
        if self.request_erased() {
            return Ok(false);
        }
        let rewritten = self
            .rewritten_request
            .as_ref()
            .map(|rewritten| erased_value(self.effect, rewritten))
            .transpose()?;
        self.request = erased_value(self.effect, &self.request)?;
        self.rewritten_request = rewritten;
        Ok(true)
    }
}

/// The value of `entry` when its key is `name`.
fn keyed<'a>(entry: &'a (Value, Value), name: &str) -> Option<&'a Value> {
    (entry.0.as_str() == Some(name)).then_some(&entry.1)
}

/// Whether `ask` is a typed marker a spawn's ask holds: an erased target's
/// or a barrier's.
fn typed(ask: &Value) -> bool {
    is_erased_ask(ask) || is_barrier_ask(ask)
}

/// The typed marker the ask of `request`, a spawn's, holds, when it holds
/// one.
fn typed_ask(effect: SelfEffect, request: &Value) -> Option<&Value> {
    let Value::Map(fields) = request else {
        return None;
    };
    ask_of(fields).filter(|ask| effect == SelfEffect::AgentsSpawn && typed(ask))
}

/// The identity of the live `request` a call of `effect` made: over the
/// whole request, or, for a spawn whose ask is a typed marker, over every
/// field but its ask.
fn live_identity(effect: SelfEffect, request: &Value) -> Result<[u8; 32]> {
    match (typed_ask(effect, request), request) {
        (Some(_), Value::Map(fields)) => canonical_digest(&without_ask(fields)),
        _ => canonical_digest(request),
    }
}

/// The erased form of the live `request` a call of `effect` made: its
/// identity, and a spawn's typed ask beside it.
fn erased_value(effect: SelfEffect, request: &Value) -> Result<Value> {
    let mut fields = vec![
        (ERASED_REQUEST_KEYS[0], Value::from(ERASED_STATE)),
        (ERASED_REQUEST_KEYS[1], Value::from(RESPONSE_ERASED)),
        (
            ERASED_REQUEST_KEYS[2],
            Value::Binary(live_identity(effect, request)?.to_vec()),
        ),
    ];
    fields.extend(typed_ask(effect, request).map(|ask| (ERASED_REQUEST_KEYS[3], ask.clone())));
    Ok(request_map(fields))
}

/// The BLAKE3 digest of `request`'s canonical MessagePack, read in its
/// admission form: each secret the side-row wall places, and each handle
/// it placed, as one stand-in.
fn canonical_digest(request: &Value) -> Result<[u8; 32]> {
    let admitted = admission_form(request)?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &admitted)
        .map_err(|_| invalid_code_run_replay("a bridge request does not encode"))?;
    Ok(*blake3::Hasher::new()
        .update(REQUEST_IDENTITY_DOMAIN)
        .update(&bytes)
        .finalize()
        .as_bytes())
}
