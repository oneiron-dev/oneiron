//! Protocol 1.1 asks, the engine side: who answers, and what the receipt
//! records.
//!
//! An organ asks inside a call. The host answers only when the install
//! grant names the verb, the caller supplied a handler for it, and, for a
//! fetch, the first hop is on the allowlist. Otherwise it refuses, and the
//! organ goes on or fails as it chooses. No count or size refuses an ask
//! (Rule 5): the grant's counts and answer bytes, the ask's value, and what
//! its receipt line carries are `[limits]` rows, which ask whether
//! everything is okay, and the call's booking grows to hold every answer
//! (FIX 5284). Handlers run on the caller's own thread, inside the call's
//! deadline; while one runs, that thread may not call an organ.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron_organ_protocol::{
    ASK_NET_FETCH, Ask, AskAnswer, AskCode, AskData, AskOutcome, AskRefusal, ByteBuf, FetchAnswer,
    Hash32, Payload, SharedRegion,
};

use crate::budget::{CallRoom, Stop};
use crate::error::HostError;
use crate::fetch;
use crate::handlers::{Answered, AskHandlers, AskRequest, HandlerScope};
use crate::receipt::{AskReceipt, SignedReceipt, Unanswered, digest};
use crate::spec::OrganSpec;

/// What the host does with one ask.
pub(crate) enum AskStep {
    /// Send this answer, with the region its bytes ride in, if any.
    Answer(AskAnswer, Option<SharedRegion>),
    /// Stop the call with this error: a revocation came while it waited
    /// for room.
    End(HostError),
}

/// What one call's asks need of the host beside its spec and handlers.
pub(crate) struct AskContext<'a> {
    pub(crate) vault: &'a Vault,
    pub(crate) room: &'a CallRoom,
    /// Whether the call's grant is revoked: the one thing that ends a wait
    /// for room.
    pub(crate) revoked: &'a dyn Fn() -> bool,
}

/// One call's asks: its counts, the room its answers hold, and its receipt
/// lines.
pub(crate) struct CallAsks<'a> {
    spec: &'a OrganSpec,
    handlers: &'a AskHandlers<'a>,
    context: AskContext<'a>,
    call_verb: &'a str,
    grant: &'a str,
    deadline: Instant,
    inline_max: usize,
    asked: u32,
    per_verb: HashMap<String, u32>,
    /// Answer bytes lent so far, values and data.
    lent: u64,
    /// What the last ask's answer lent, given back if it is not sent.
    lent_last: u64,
    /// The largest frame bodies of this call, sent and received.
    frames: (u64, u64),
    /// What the running handler's key signed, until its line settles.
    signing: Mutex<Option<SignedReceipt>>,
    pub(crate) receipts: Vec<AskReceipt>,
}

impl<'a> CallAsks<'a> {
    pub(crate) fn new(
        spec: &'a OrganSpec,
        handlers: &'a AskHandlers<'a>,
        context: AskContext<'a>,
        call_verb: &'a str,
        grant: &'a str,
        deadline: Instant,
        inline_max: usize,
    ) -> Self {
        Self {
            spec,
            handlers,
            context,
            call_verb,
            grant,
            deadline,
            inline_max,
            asked: 0,
            per_verb: HashMap::new(),
            lent: 0,
            lent_last: 0,
            frames: (0, 0),
            signing: Mutex::new(None),
            receipts: Vec::new(),
        }
    }

    /// Answer bytes this call has lent the organ: they draw on the same
    /// booking as its outputs.
    pub(crate) fn lent_bytes(&self) -> u64 {
        self.lent
    }

    /// The largest frame bodies this call's process carried for it: the
    /// host's (its call, its answers), then the organ's (its asks; the
    /// reply is the caller's to add).
    pub(crate) fn frames(&self) -> (u64, u64) {
        self.frames
    }

    pub(crate) fn frame_sent(&mut self, len: u32) {
        self.frames.0 = self.frames.0.max(u64::from(len));
    }

    pub(crate) fn frame_received(&mut self, len: u64) {
        self.frames.1 = self.frames.1.max(len);
    }

    /// Measures `measured` against `row`, at the install grant's own value
    /// when it names one other than the row's factory value.
    fn measure(&self, row: EngineLimit, install: u64, measured: u64) {
        crate::measure::install_row(self.context.vault, row, install, measured);
    }

    /// Decides one ask: refuse it, or answer it through its handler. Each
    /// count and size is measured against its row, never refused.
    /// `watched` says whether a watchdog keeps the call's deadline; with
    /// none the handler is not run and the ask is refused, retryable.
    pub(crate) fn take(&mut self, ask: Ask, watched: bool) -> AskStep {
        let started = Instant::now();
        self.lent_last = 0;
        let line = line(&ask);
        let vault = self.context.vault;
        vault.measure_limit(EngineLimit::OrganVerbBytes, ask.verb.len() as u64);
        self.asked = self.asked.saturating_add(1);
        self.measure(
            EngineLimit::OrganAsks,
            u64::from(self.spec.max_asks),
            u64::from(self.asked),
        );
        let cap = self
            .spec
            .asks
            .iter()
            .find(|granted| granted.verb == ask.verb)
            .map(|granted| granted.max_per_call);
        if let Some(cap) = cap {
            let count = self.per_verb.entry(ask.verb.clone()).or_default();
            *count += 1;
            let count = u64::from(*count);
            self.measure(EngineLimit::OrganAskPerVerb, u64::from(cap), count);
        }
        let encoded = rmp_serde::to_vec_named(&ask.value).map_or(0, |bytes| bytes.len() as u64);
        vault.measure_limit(EngineLimit::OrganAskValueBytes, encoded);
        self.ask(ask, line, cap.is_some(), watched, started)
    }

    /// An ask past its counts: runs its handler, if the grant names it.
    fn ask(
        &mut self,
        ask: Ask,
        mut line: AskReceipt,
        granted: bool,
        watched: bool,
        started: Instant,
    ) -> AskStep {
        let Some(handler) = granted.then(|| self.handlers.get(&ask.verb)).flatten() else {
            let refusal = AskRefusal::new(
                AskCode::NotGranted,
                "the grant names no such ask, or the call has no handler for it",
            );
            return self.refuse(&ask, line, refusal);
        };
        if ask.verb == ASK_NET_FETCH {
            let (target, checked) = fetch::first_hop(&ask.value, &self.spec.fetch);
            self.context.vault.measure_limit(
                EngineLimit::OrganFetchPurposeBytes,
                fetch::purpose_bytes(&ask.value),
            );
            line.fetch = target;
            if let Err(refusal) = checked {
                return self.refuse(&ask, line, refusal);
            }
        }
        if !watched {
            let refusal = AskRefusal::new(
                AskCode::Failed,
                "the host could not keep the call's deadline while a handler ran",
            )
            .retryable();
            return self.refuse(&ask, line, refusal);
        }
        let request = AskRequest {
            verb: &ask.verb,
            value: &ask.value,
            organ: &self.spec.name,
            call_verb: self.call_verb,
            grant: self.grant,
            deadline: self.deadline,
            max_bytes: self.spec.max_ask_bytes.saturating_sub(self.lent),
            fetch: &self.spec.fetch,
            signing: &self.signing,
            room: Some(self.context.room),
            revoked: Stop(self.context.revoked),
        };
        // On record while the handler runs, so a handler that panics leaves
        // its line; the settled line replaces it once the handler returns.
        let mut running = line.clone();
        running.unanswered = Some(Unanswered::NotSent);
        self.receipts.push(running);
        // A handler that reads a body holds room for it as it reads.
        let before = self.context.room.held();
        let answered = {
            let _scope = HandlerScope::enter();
            handler.answer(&request)
        };
        let prepaid = self.context.room.held().saturating_sub(before);
        self.receipts.pop();
        line.handler_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        // A signature is on record whether or not it is delivered.
        line.signed = self
            .signing
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match answered {
            Ok(answered) => self.answer(&ask, line, answered, prepaid),
            Err(refusal) => {
                self.context.room.release(prepaid);
                self.refuse(&ask, line, refusal)
            }
        }
    }

    /// An ask the host took but did not run: its call was ending.
    pub(crate) fn skipped(&mut self, ask: &Ask) {
        self.lent_last = 0;
        let mut line = line(ask);
        line.unanswered = Some(Unanswered::NotRun);
        self.receipts.push(line);
    }

    /// The last ask's handler ran, but its answer was not sent: the organ
    /// was lent none of its bytes.
    pub(crate) fn unsent(&mut self) {
        if let Some(line) = self.receipts.last_mut() {
            line.unanswered.get_or_insert(Unanswered::NotSent);
        }
        self.lent -= self.lent_last;
        self.context.room.release(self.lent_last);
        self.lent_last = 0;
    }

    fn answer(
        &mut self,
        ask: &Ask,
        mut line: AskReceipt,
        answered: Answered,
        prepaid: u64,
    ) -> AskStep {
        let Answered { value, data, fetch } = answered;
        if fetch.is_some() {
            line.fetch = fetch;
        }
        // The value is answer bytes too: a fetch's final URL, or anything a
        // handler puts there, crosses inline and lands in the organ's heap.
        let value_len = rmp_serde::to_vec_named(&value).map_or(0, |bytes| bytes.len() as u64);
        let data_len = data.as_ref().map_or(0, |bytes| bytes.len() as u64);
        let charged = value_len.saturating_add(data_len);
        // The room the answer holds: what its handler held as it read, made
        // up to the whole answer, the booking grown when it passes it.
        let room = self.context.room;
        if charged < prepaid {
            room.release(prepaid - charged);
        } else if !room.hold(charged - prepaid, self.context.revoked) {
            room.release(prepaid);
            line.unanswered = Some(Unanswered::NotRun);
            self.receipts.push(line);
            return AskStep::End(HostError::Revoked);
        }
        if ask.verb == ASK_NET_FETCH {
            self.measure_fetch(&line, &value, data_len);
        }
        let mut region = None;
        let data = match data {
            None => None,
            Some(bytes) => {
                let content_hash = Hash32::of(&bytes);
                let payload = if bytes.len() <= self.inline_max {
                    Payload::Inline(ByteBuf::from(bytes))
                } else {
                    match SharedRegion::from_bytes(&bytes) {
                        Ok(made) => {
                            region = Some(made);
                            Payload::Slot(0)
                        }
                        Err(err) => {
                            let refusal = AskRefusal::new(
                                AskCode::Failed,
                                format!("the answer's region: {err}"),
                            )
                            .retryable();
                            room.release(charged);
                            return self.refuse(ask, line, refusal);
                        }
                    }
                };
                line.data_hash = Some(content_hash);
                line.data_len = data_len;
                Some(AskData {
                    len: data_len,
                    content_hash,
                    data: payload,
                })
            }
        };
        self.lent += charged;
        self.lent_last = charged;
        self.measure(
            EngineLimit::OrganAnswerBytes,
            self.spec.max_ask_bytes,
            self.lent,
        );
        line.answer_len = charged;
        line.answer_digest = Some(digest(&value));
        self.receipts.push(line);
        let answer = AskAnswer {
            call: ask.call,
            id: ask.id,
            outcome: AskOutcome::Answered { value, data },
        };
        AskStep::Answer(answer, region)
    }

    /// Measures a fetch's answer: its body against the grant's own bytes,
    /// its hops, its origin and its Content-Type, each kept whole.
    fn measure_fetch(&self, line: &AskReceipt, value: &rmpv::Value, body: u64) {
        let vault = self.context.vault;
        self.measure(
            EngineLimit::OrganFetchBytes,
            self.spec.fetch.max_bytes,
            body,
        );
        if let Some(target) = &line.fetch {
            vault.measure_limit(
                EngineLimit::OrganFetchOriginBytes,
                target.origin.len() as u64,
            );
            vault.measure_limit(
                EngineLimit::OrganFetchRedirects,
                u64::from(target.redirects),
            );
        }
        let content_type = fetch::decode::<FetchAnswer>(value)
            .and_then(|answer| answer.content_type)
            .map_or(0, |content_type| content_type.len() as u64);
        vault.measure_limit(EngineLimit::OrganContentTypeBytes, content_type);
    }

    fn refuse(&mut self, ask: &Ask, mut line: AskReceipt, refusal: AskRefusal) -> AskStep {
        self.context
            .vault
            .measure_limit(EngineLimit::OrganDetailBytes, refusal.detail.len() as u64);
        line.refused = Some(refusal.code);
        self.receipts.push(line);
        let answer = AskAnswer {
            call: ask.call,
            id: ask.id,
            outcome: AskOutcome::Refused(refusal),
        };
        AskStep::Answer(answer, None)
    }
}

impl Drop for CallAsks<'_> {
    /// Hands the call's lines to its handlers, however the call ended. A
    /// handler that panicked keeps what its key signed on its line.
    fn drop(&mut self) {
        let signing = self
            .signing
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let (Some(signed), Some(line)) = (signing, self.receipts.last_mut()) {
            line.signed = Some(signed);
        }
        self.handlers
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(self.receipts.iter().cloned());
    }
}

/// An ask's receipt line before anything is decided.
fn line(ask: &Ask) -> AskReceipt {
    AskReceipt {
        id: ask.id,
        verb: ask.verb.clone(),
        value_digest: digest(&ask.value),
        refused: None,
        answer_len: 0,
        answer_digest: None,
        data_hash: None,
        data_len: 0,
        fetch: None,
        handler_us: 0,
        unanswered: None,
        signed: None,
    }
}
