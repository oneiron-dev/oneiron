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
//! its `ask`, and its identity leaves the ask out, as its match does. A
//! verb call keeps its catalog verb's name as its `verb`, a text-free call
//! fact a write's count and receipt read. An erased request meets a call
//! by its identity alone: a hit answers with the call's own recorded
//! outcome, and every other call drifts. It is never a wildcard and never
//! a spawn's miss, so no fresh effect runs in its place. A live request
//! keeps its full value and its `admitted_from_known` matching.
//!
//! An erase in a writer that reads custody keeps one more fact (FIX
//! ERASED-IDENTITY-ONE-STAND-IN, Engine ANSWER 19 Nov 02:54 = B): the custody
//! records the request names, by their handles, and its custody identity,
//! the digest of the request read for those records' values alone, each as
//! its record's handle ([`custody_record_form`]). Such a row meets a call
//! only when the call, read the same way, digests the same: its values name
//! the same records. While custody no longer knows one of those records, or
//! no custody read is in reach, the row reads by its stand-in identity, as a
//! row erased before does. No value is kept, and no fingerprint of one: the
//! digest holds handles and the shape rules' stand-in where values stood.
//! Both identities and the records sit in the one `identity` member, so the
//! erased form names no word a fenced put's wall did not already read there
//! (blind review round 1 of #9528): each record is a bare handle, which the
//! wall reads as the handle of a record custody knows and leaves as it is.
//!
//! Such an erase reads its stand-in identity with custody too (FIX
//! FENCE-ERASE-STAND-IN-DIGESTS-RAW-VALUE): each value base custody holds
//! reads as the stand-in, as the handle the wall places for it does. A put
//! fence erases a record before the wall reads it, so its request may hold
//! a passphrase custody holds as written; its stand-in identity is still
//! the one a scrub of the stored row keeps, and no digest of the value as
//! written is kept, which a guess could be tested against.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use rmpv::Value;

use super::super::spawn_replay::{
    CompareKnown, ReplayRequestMatch, ask_of, is_barrier_ask, is_erased_ask, without_ask,
};
use super::super::support::{invalid_code_run_replay, request_map};
use super::super::types::SelfEffect;
use super::CodeRunBridgeCall;
use crate::Result;
use crate::batch::secret_scan::{
    MapOrder, admission_form, custody_record_form, custody_records_named, held_row_meets,
};
use crate::code_run::RESPONSE_ERASED;
use crate::store::known_value_index::KnownValues;
use crate::task_verb::sdk::AgentVerb;

/// The domain of a bridge request's identity digest.
const REQUEST_IDENTITY_DOMAIN: &[u8] = b"oneiron:code-run:bridge-request-identity:v1";

/// The domain of an erased request's custody identity digest.
const CUSTODY_IDENTITY_DOMAIN: &[u8] = b"oneiron:code-run:bridge-request-custody-identity:v1";

/// The keys of an erased request, in order. `ask` is a spawn's alone and
/// `verb` a verb call's.
const ERASED_REQUEST_KEYS: [&str; 5] = ["state", "cause", "identity", "ask", VERB_KEY];

/// The `state` an erased request names.
const ERASED_STATE: &str = "erased";

/// The request key of a verb call's verb, and of its JSON input.
const VERB_KEY: &str = "verb";
const INPUT_KEY: &str = "input";

/// One erased request as a row stores it: the identity it keeps, the typed
/// ask of a spawn whose ask was one, a verb call's catalog verb, and the
/// custody identity an erase that read custody kept beside its identity.
#[derive(Debug, Clone, Copy)]
pub(in crate::code_run) struct ErasedRequest<'a> {
    identity: [u8; 32],
    ask: Option<&'a Value>,
    verb: Option<&'a str>,
    custody: Option<CustodyIdentity<'a>>,
}

/// The custody records an erased request named, by their bare handles in
/// ascending order, and the digest of the request read for their values
/// (FIX ERASED-IDENTITY-ONE-STAND-IN).
#[derive(Debug, Clone, Copy)]
struct CustodyIdentity<'a> {
    identity: [u8; 32],
    records: &'a [Value],
}

impl<'a> ErasedRequest<'a> {
    /// `request` read as an erased request, in its one spelling. `None` for
    /// any other value, every live request among them.
    pub(in crate::code_run) fn of(request: &'a Value) -> Option<Self> {
        let Value::Map(fields) = request else {
            return None;
        };
        let (state, cause, identity, kept) = match fields.as_slice() {
            [state, cause, identity] => (state, cause, identity, None),
            [state, cause, identity, kept] => (state, cause, identity, Some(kept)),
            _ => return None,
        };
        if keyed(state, ERASED_REQUEST_KEYS[0])?.as_str() != Some(ERASED_STATE)
            || keyed(cause, ERASED_REQUEST_KEYS[1])?.as_str() != Some(RESPONSE_ERASED)
        {
            return None;
        }
        let (identity, custody) = match keyed(identity, ERASED_REQUEST_KEYS[2])? {
            Value::Binary(identity) => (identity, None),
            Value::Array(parts) => match parts.as_slice() {
                [Value::Binary(identity), custody, records @ ..] => {
                    (identity, Some(CustodyIdentity::of(custody, records)?))
                }
                _ => return None,
            },
            _ => return None,
        };
        let (ask, verb) = match kept.map(|entry| {
            (
                keyed(entry, ERASED_REQUEST_KEYS[3]),
                keyed(entry, ERASED_REQUEST_KEYS[4]),
            )
        }) {
            None => (None, None),
            Some((Some(ask), _)) if typed(ask) => (Some(ask), None),
            Some((_, Some(verb))) => (None, Some(catalog_verb_of(verb)?)),
            Some(_) => return None,
        };
        Some(Self {
            identity: <[u8; 32]>::try_from(identity.as_slice()).ok()?,
            ask,
            verb,
            custody,
        })
    }

    /// How this erased request meets `offered`, the request its call makes
    /// now under the row's own bridge stamp: a hit only when `offered` has
    /// the identity it keeps, and drift for every other request, never a
    /// spawn's miss. A spawn whose ask was a typed marker meets an offer
    /// that asks something and has its identity in every other field, as
    /// its live row's match did.
    ///
    /// A row whose erase kept a custody identity meets `offered` by it
    /// alone while base custody, read through `known`, knows every record
    /// it names (FIX ERASED-IDENTITY-ONE-STAND-IN): `offered` read for those
    /// records' values, each as its record's handle, digests the same, read
    /// with all their values or with those at most each shorter length they
    /// hold (blind review round 2 of #9528: a record rotated to a longer
    /// value since the erase still reads as the erase read it). So a
    /// value another record holds, or a key of the same shape no named
    /// record holds, is another call; a value held as written beside the
    /// handle of another, which custody knew by the erase, meets (FIX-LIST
    /// [REPLAY-COMPARE-MIXED-ERA]); and a value custody took after the erase
    /// changes nothing.
    ///
    /// Any other erased row reads by its stand-in identity. The side-row
    /// wall admitted the row in a scope that decides with custody (FIX
    /// REPLAY-COMPARE-KNOWN-MATCHER), so `offered` meets that identity in
    /// either form. Its admission form first, as the identity of a row
    /// erased with no custody read in reach while it held a value as
    /// written (a row stored before that value entered custody) was taken;
    /// then, once that misses, with each value base custody holds now as
    /// the stand-in too, as the identity of a row erased while it held that
    /// value's handle, or by an erase that read custody, was taken (FIX
    /// FENCE-ERASE-STAND-IN-DIGESTS-RAW-VALUE).
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, one that does not encode,
    /// or the read of base custody's values.
    pub(in crate::code_run) fn meets_known(
        &self,
        offered: &Value,
        known: &CompareKnown<'_>,
    ) -> Result<ReplayRequestMatch> {
        let identity_meets = |request: &Value| -> Result<bool> {
            if let Some(custody) = self.custody
                && let Some((custody_known, records)) = custody.known_records(known)?
            {
                return custody.meets(request, &custody_known, &records);
            }
            if canonical_digest(request, None)? == self.identity {
                return Ok(true);
            }
            Ok(match known.get()? {
                Some(known) => canonical_digest(request, Some(known))? == self.identity,
                None => false,
            })
        };
        let hit = match (self.ask, offered) {
            (None, _) => identity_meets(offered)?,
            (Some(_), Value::Map(fields)) if ask_of(fields).is_some_and(Value::is_str) => {
                identity_meets(&without_ask(fields))?
            }
            (Some(_), _) => return Ok(ReplayRequestMatch::Drift),
        };
        Ok(if hit {
            ReplayRequestMatch::Hit
        } else {
            ReplayRequestMatch::Drift
        })
    }
}

impl<'a> CustodyIdentity<'a> {
    /// `identity` and `records`, the parts of an erased request's identity
    /// past its stand-in identity, read as a custody identity, in its one
    /// spelling: its digest, then at least one record, each a text, in
    /// ascending order.
    fn of(identity: &'a Value, records: &'a [Value]) -> Option<Self> {
        let Value::Binary(identity) = identity else {
            return None;
        };
        let names = records
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<&str>>>()?;
        if names.is_empty() || !names.windows(2).all(|pair| pair[0] < pair[1]) {
            return None;
        }
        Some(Self {
            identity: <[u8; 32]>::try_from(identity.as_slice()).ok()?,
            records,
        })
    }

    /// Whether `request`, read for the values of `records` through
    /// `custody_known`, digests as this identity: read with every value
    /// those records hold, then, past a miss, with only those at most each
    /// shorter length they hold, longest first. A record that took a longer
    /// value since the erase, one spanning the erased value and the words
    /// beside it, so reads the request as the erase read it. Each read
    /// takes only those records' values as their handles, so a value
    /// another record holds meets no read.
    fn meets(
        &self,
        request: &Value,
        custody_known: &Arc<KnownValues>,
        records: &BTreeSet<String>,
    ) -> Result<bool> {
        if custody_digest(request, custody_known, records, None)? == self.identity {
            return Ok(true);
        }
        let lengths = custody_known.held_lengths(|handle| records.contains(handle));
        for longest in lengths.into_iter().rev().skip(1) {
            if custody_digest(request, custody_known, records, Some(longest))? == self.identity {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The values base custody holds, read through `known`, and the records
    /// this identity names, while custody knows each of them; `None` once
    /// it knows one no more (its holder's erase dropped its entries), or
    /// when no custody read is in reach.
    fn known_records(
        &self,
        known: &CompareKnown<'_>,
    ) -> Result<Option<(Arc<KnownValues>, BTreeSet<String>)>> {
        let Some(custody_known) = known.get()? else {
            return Ok(None);
        };
        let records: BTreeSet<String> = self
            .records
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        Ok(records
            .iter()
            .all(|handle| custody_known.holds_handle(handle))
            .then_some((custody_known, records)))
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

    /// The catalog verb a verb call named, a text-free call fact (FIX 6534):
    /// read off its live request beside its input, or kept beside its
    /// erased form's identity. `None` for another effect.
    #[must_use]
    pub(crate) fn recorded_verb(&self) -> Option<&str> {
        if self.effect != SelfEffect::AgentVerb {
            return None;
        }
        if let Some(erased) = ErasedRequest::of(&self.request) {
            return erased.verb;
        }
        let Value::Map(fields) = &self.request else {
            return None;
        };
        let field = |name: &str| fields.iter().find_map(|entry| keyed(entry, name)?.as_str());
        field(INPUT_KEY).and(field(VERB_KEY))
    }

    /// Whether the guest's request this call recorded is `offered` by its
    /// identity alone (FIX 6534): how a row an erase took the words of
    /// meets the call made again, and a live row by the identity it has.
    ///
    /// As `admitted_from_known` does, a live row that is not `offered` as
    /// written is read, once base custody knows a value, through `known`,
    /// as a template ([`held_row_meets`], FIX
    /// REPLAY-COMPARE-KNOWN-OTHER-CALLERS, FIX
    /// RECEIPT-RECORDS-CALL-HELD-INPUT): each handle the row holds that
    /// names a record custody knows meets the same handle or one value of
    /// that record, and every other byte meets only itself, so a value
    /// another record holds, shaped or not, stays another request, and text
    /// the row holds as written never reads as a handle. A custody that
    /// knows no value holds no record a handle names, so the two meet only
    /// as written: never by a digest that reads two shaped tokens, or two
    /// keys the row kept as written with the switch off, as one stand-in.
    /// An erased row meets `offered` as [`ErasedRequest::meets_known`]
    /// reads it: by its custody identity where its erase kept one.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, one that does not encode,
    /// or the read of base custody's values.
    pub(crate) fn request_identity_is(
        &self,
        offered: &Value,
        known: &CompareKnown<'_>,
    ) -> Result<bool> {
        if let Some(erased) = ErasedRequest::of(&self.request) {
            return Ok(erased.meets_known(offered, known)?.is_hit());
        }
        let (held, again) = (
            identity_part(self.effect, &self.request),
            identity_part(self.effect, offered),
        );
        if held == again {
            return Ok(true);
        }
        match known.get()? {
            Some(known) => held_row_meets(&held, &again, &known, MapOrder::Written),
            None => Ok(false),
        }
    }

    /// Whether this call dispatched `offered`, a kept or an erased row read
    /// one way (FIX 6534): the very value while its words are kept, and its
    /// identity once an erase took them, read with each value base custody
    /// holds, through `known`, as [`ErasedRequest::meets_known`] reads it
    /// (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS).
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, one that does not encode,
    /// or the read of base custody's values.
    pub(crate) fn dispatched_request_is(
        &self,
        offered: &Value,
        known: &CompareKnown<'_>,
    ) -> Result<bool> {
        let dispatched = self.rewritten_request.as_ref().unwrap_or(&self.request);
        match ErasedRequest::of(dispatched) {
            Some(erased) => Ok(erased.meets_known(offered, known)?.is_hit()),
            None => Ok(dispatched == offered),
        }
    }

    /// Erases this call's request words (FIX 6534): the guest's original
    /// request and a hook's rewrite each take their erased form, with the
    /// identity each had, and, read with the values base custody holds
    /// through `custody`, the custody identity of each that names a record
    /// custody knows (FIX ERASED-IDENTITY-ONE-STAND-IN). Every other field
    /// stays as it is: its seq, effect, outcome, times, action digest,
    /// targets and hook view, and so its receipts and the effect it stands
    /// for. `true` when the call changed; one already erased is left as it
    /// is.
    ///
    /// # Errors
    ///
    /// A request the side-row wall cannot read, one that does not encode,
    /// or the read of base custody's values.
    pub(crate) fn erase_request(&mut self, custody: &CompareKnown<'_>) -> Result<bool> {
        if self.request_erased() {
            return Ok(false);
        }
        let rewritten = self
            .rewritten_request
            .as_ref()
            .map(|rewritten| erased_value(self.effect, rewritten, custody))
            .transpose()?;
        self.request = erased_value(self.effect, &self.request, custody)?;
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

/// The catalog name of the verb `value` spells, when it spells one.
fn catalog_verb_of(value: &Value) -> Option<&'static str> {
    AgentVerb::from_name(value.as_str()?).map(AgentVerb::as_str)
}

/// The catalog verb the live `request` of a verb call names beside its
/// input, when it names one: the text-free call fact its erased form keeps.
fn catalog_verb(effect: SelfEffect, request: &Value) -> Option<&'static str> {
    let Value::Map(fields) = request else {
        return None;
    };
    let field = |name: &str| fields.iter().find_map(|entry| keyed(entry, name));
    if effect != SelfEffect::AgentVerb || !field(INPUT_KEY).is_some_and(Value::is_str) {
        return None;
    }
    catalog_verb_of(field(VERB_KEY)?)
}

/// The typed marker the ask of `request`, a spawn's, holds, when it holds
/// one.
fn typed_ask(effect: SelfEffect, request: &Value) -> Option<&Value> {
    let Value::Map(fields) = request else {
        return None;
    };
    ask_of(fields).filter(|ask| effect == SelfEffect::AgentsSpawn && typed(ask))
}

/// The identity of the live `request` a call of `effect` made: over its
/// [`identity_part`].
fn live_identity(effect: SelfEffect, request: &Value) -> Result<[u8; 32]> {
    canonical_digest(&identity_part(effect, request), None)
}

/// What the identity of the live `request` a call of `effect` made reads:
/// the whole request, or, for a spawn whose ask is a typed marker, every
/// field but its ask.
fn identity_part(effect: SelfEffect, request: &Value) -> Cow<'_, Value> {
    match (typed_ask(effect, request), request) {
        (Some(_), Value::Map(fields)) => Cow::Owned(without_ask(fields)),
        _ => Cow::Borrowed(request),
    }
}

/// The erased form of the live `request` a call of `effect` made: its
/// identity, and a spawn's typed ask or a verb call's catalog verb beside
/// it. The identity is the stand-in identity alone, or, when the request
/// names a record base custody knows, read through `custody`, the stand-in
/// identity, the custody identity and the records, in one array.
fn erased_value(effect: SelfEffect, request: &Value, custody: &CompareKnown<'_>) -> Result<Value> {
    let stand_in = Value::Binary(stand_in_identity(effect, request, custody)?.to_vec());
    let identity = match custody_identity(effect, request, custody)? {
        Some(parts) => Value::Array(std::iter::once(stand_in).chain(parts).collect()),
        None => stand_in,
    };
    let mut fields = vec![
        (ERASED_REQUEST_KEYS[0], Value::from(ERASED_STATE)),
        (ERASED_REQUEST_KEYS[1], Value::from(RESPONSE_ERASED)),
        (ERASED_REQUEST_KEYS[2], identity),
    ];
    fields.extend(typed_ask(effect, request).map(|ask| (ERASED_REQUEST_KEYS[3], ask.clone())));
    fields.extend(
        catalog_verb(effect, request).map(|verb| (ERASED_REQUEST_KEYS[4], Value::from(verb))),
    );
    Ok(request_map(fields))
}

/// The stand-in identity the erased form of the live `request` a call of
/// `effect` made keeps: the digest of its [`identity_part`] in its admission
/// form, read, when a custody read is in reach through `custody`, with each
/// value base custody holds as the stand-in too (FIX
/// FENCE-ERASE-STAND-IN-DIGESTS-RAW-VALUE). A put fence erases a request
/// before the side-row wall reads it, so a value custody holds that no
/// shape rule reads (a passphrase) is still written there: read with
/// custody it digests as the handle the wall would place, as a scrub of the
/// stored row digests it, and never as written. With no custody read in
/// reach, its [`live_identity`].
fn stand_in_identity(
    effect: SelfEffect,
    request: &Value,
    custody: &CompareKnown<'_>,
) -> Result<[u8; 32]> {
    canonical_digest(&identity_part(effect, request), custody.get()?)
}

/// The custody identity the erased form of the live `request` a call of
/// `effect` made keeps (FIX ERASED-IDENTITY-ONE-STAND-IN): the digest of its
/// [`identity_part`] read for the values of the records that part names
/// once read with the values base custody holds, through `custody`, then
/// those records, by their bare handles. `None` with no custody read in
/// reach, or when it names no record custody knows.
fn custody_identity(
    effect: SelfEffect,
    request: &Value,
    custody: &CompareKnown<'_>,
) -> Result<Option<Vec<Value>>> {
    let Some(known) = custody.get()? else {
        return Ok(None);
    };
    let part = identity_part(effect, request);
    let records = custody_records_named(&part, &known)?;
    if records.is_empty() {
        return Ok(None);
    }
    let identity = custody_digest(&part, &known, &records, None)?;
    Ok(Some(
        std::iter::once(Value::Binary(identity.to_vec()))
            .chain(records.into_iter().map(Value::from))
            .collect(),
    ))
}

/// The BLAKE3 digest of `request`'s canonical MessagePack, read in its
/// admission form: each secret the side-row wall places, and each handle
/// it placed, as one stand-in; with `known`, each value it holds too.
fn canonical_digest(request: &Value, known: Option<Arc<KnownValues>>) -> Result<[u8; 32]> {
    digest(REQUEST_IDENTITY_DOMAIN, &admission_form(request, known)?)
}

/// The BLAKE3 digest of `request`'s canonical MessagePack, read for the
/// values of `records` alone, through `known`, each as its record's handle
/// ([`custody_record_form`]), only those at most `longest` bytes long when
/// given: a custody identity.
fn custody_digest(
    request: &Value,
    known: &Arc<KnownValues>,
    records: &BTreeSet<String>,
    longest: Option<usize>,
) -> Result<[u8; 32]> {
    digest(
        CUSTODY_IDENTITY_DOMAIN,
        &custody_record_form(request, known, records, longest)?,
    )
}

/// The BLAKE3 digest of `value`'s MessagePack under `domain`.
fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid_code_run_replay("a bridge request does not encode"))?;
    Ok(*blake3::Hasher::new()
        .update(domain)
        .update(&bytes)
        .finalize()
        .as_bytes())
}
