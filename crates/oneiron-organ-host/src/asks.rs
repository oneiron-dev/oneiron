//! Protocol 1.1 asks, the engine side: who answers, within which caps, and
//! what the receipt records.
//!
//! An organ asks inside a call. The host answers only when the install
//! grant names the verb, the caller supplied a handler for it, the call's
//! caps have room, and, for a fetch, the first hop is on the allowlist.
//! Otherwise it refuses, and the organ goes on or fails as it chooses.
//! Handlers run on the caller's own thread, inside the call's deadline;
//! while one runs, that thread may not call an organ.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use oneiron_organ_protocol::{
    ASK_NET_FETCH, ASK_VALUE_MAX, Ask, AskAnswer, AskCode, AskData, AskOutcome, AskRefusal,
    ByteBuf, Hash32, Payload, SharedRegion,
};

use crate::error::HostError;
use crate::fetch;
use crate::handlers::{Answered, AskHandlers, AskRequest, HandlerScope};
use crate::receipt::{AskReceipt, SignedReceipt, Unanswered, bound_text, digest};
use crate::spec::OrganSpec;

const MAX_DETAIL_BYTES: usize = 512;
const MAX_VERB_BYTES: usize = 64;

/// What the host does with one ask.
pub(crate) enum AskStep {
    /// Send this answer, with the region its bytes ride in, if any.
    Answer(AskAnswer, Option<SharedRegion>),
    /// Stop the call with this error.
    End(HostError),
}

/// One call's asks: its caps, its counts and its receipt lines.
pub(crate) struct CallAsks<'a> {
    spec: &'a OrganSpec,
    handlers: &'a AskHandlers<'a>,
    call_verb: &'a str,
    grant: &'a str,
    deadline: Instant,
    inline_max: usize,
    asked: u32,
    per_verb: HashMap<String, u32>,
    bytes_left: u64,
    /// Answer bytes lent so far, values and data.
    lent: u64,
    /// What the last ask's answer lent, given back if it is not sent.
    lent_last: u64,
    refused_past_cap: bool,
    /// What the running handler's key signed, until its line settles.
    signing: Mutex<Option<SignedReceipt>>,
    pub(crate) receipts: Vec<AskReceipt>,
}

impl<'a> CallAsks<'a> {
    pub(crate) fn new(
        spec: &'a OrganSpec,
        handlers: &'a AskHandlers<'a>,
        call_verb: &'a str,
        grant: &'a str,
        deadline: Instant,
        inline_max: usize,
    ) -> Self {
        Self {
            spec,
            handlers,
            call_verb,
            grant,
            deadline,
            inline_max,
            asked: 0,
            per_verb: HashMap::new(),
            bytes_left: spec.max_ask_bytes.min(spec.call_memory_bytes),
            lent: 0,
            lent_last: 0,
            refused_past_cap: false,
            signing: Mutex::new(None),
            receipts: Vec::new(),
        }
    }

    /// Answer bytes this call has lent the organ: they draw on the same
    /// booking as its outputs.
    pub(crate) fn lent_bytes(&self) -> u64 {
        self.lent
    }

    /// Decides one ask: refuse it, answer it through its handler, or end
    /// the call when the organ asks again after a `budget` refusal.
    /// `watched` says whether a watchdog keeps the call's deadline; with
    /// none the handler is not run and the ask is refused, retryable.
    pub(crate) fn take(&mut self, ask: Ask, watched: bool) -> AskStep {
        let started = Instant::now();
        self.lent_last = 0;
        let mut line = line(&ask);
        // One budget refusal, of either kind; any ask after it ends the call.
        if self.refused_past_cap {
            line.unanswered = Some(Unanswered::NotRun);
            self.receipts.push(line);
            return AskStep::End(HostError::AskBudget);
        }
        self.asked = self.asked.saturating_add(1);
        let cap = self
            .spec
            .asks
            .iter()
            .find(|granted| granted.verb == ask.verb)
            .map(|granted| granted.max_per_call);
        let over_verb = cap.is_some_and(|cap| {
            let count = self.per_verb.entry(ask.verb.clone()).or_default();
            *count += 1;
            *count > cap
        });
        if self.asked > self.spec.max_asks || over_verb {
            self.refused_past_cap = true;
            let refusal = AskRefusal::new(AskCode::Budget, "this call's asks are spent");
            return self.refuse(&ask, line, refusal);
        }
        let encoded = rmp_serde::to_vec_named(&ask.value).map_or(usize::MAX, |bytes| bytes.len());
        if encoded > ASK_VALUE_MAX {
            let refusal = AskRefusal::new(AskCode::TooLarge, "the ask's value is over 64 KiB");
            return self.refuse(&ask, line, refusal);
        }
        let Some(handler) = cap.and_then(|_| self.handlers.get(&ask.verb)) else {
            let refusal = AskRefusal::new(
                AskCode::NotGranted,
                "the grant names no such ask, or the call has no handler for it",
            );
            return self.refuse(&ask, line, refusal);
        };
        if ask.verb == ASK_NET_FETCH {
            let (target, checked) = fetch::first_hop(&ask.value, &self.spec.fetch);
            line.fetch = target;
            if let Err(refusal) = checked {
                return self.refuse(&ask, line, refusal);
            }
        }
        if self.bytes_left == 0 {
            self.refused_past_cap = true;
            let refusal = AskRefusal::new(AskCode::Budget, "this call's answer bytes are spent");
            return self.refuse(&ask, line, refusal);
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
            max_bytes: self.bytes_left,
            fetch: &self.spec.fetch,
            signing: &self.signing,
        };
        // On record while the handler runs, so a handler that panics leaves
        // its line; the settled line replaces it once the handler returns.
        let mut running = line.clone();
        running.unanswered = Some(Unanswered::NotSent);
        self.receipts.push(running);
        let answered = {
            let _scope = HandlerScope::enter();
            handler.answer(&request)
        };
        self.receipts.pop();
        line.handler_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        // A signature is on record whether or not it is delivered.
        line.signed = self
            .signing
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match answered {
            Ok(answered) => self.answer(&ask, line, answered),
            Err(refusal) => self.refuse(&ask, line, refusal),
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
        self.bytes_left += self.lent_last;
        self.lent_last = 0;
    }

    fn answer(&mut self, ask: &Ask, mut line: AskReceipt, answered: Answered) -> AskStep {
        let Answered { value, data, fetch } = answered;
        if fetch.is_some() {
            line.fetch = fetch;
        }
        // The value is answer bytes too: a fetch's final URL, or anything a
        // handler puts there, crosses inline and lands in the organ's heap.
        let value_len =
            rmp_serde::to_vec_named(&value).map_or(u64::MAX, |bytes| bytes.len() as u64);
        let data_len = data.as_ref().map_or(0, |bytes| bytes.len() as u64);
        let charged = value_len.saturating_add(data_len);
        if charged > self.bytes_left {
            let refusal = AskRefusal::new(
                AskCode::TooLarge,
                "the answer is over the call's answer bytes",
            );
            return self.refuse(ask, line, refusal);
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
        self.bytes_left -= charged;
        self.lent += charged;
        self.lent_last = charged;
        line.answer_digest = Some(digest(&value));
        self.receipts.push(line);
        let answer = AskAnswer {
            call: ask.call,
            id: ask.id,
            outcome: AskOutcome::Answered { value, data },
        };
        AskStep::Answer(answer, region)
    }

    fn refuse(&mut self, ask: &Ask, mut line: AskReceipt, mut refusal: AskRefusal) -> AskStep {
        refusal.detail = bound_text(&refusal.detail, MAX_DETAIL_BYTES);
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
        verb: bound_text(&ask.verb, MAX_VERB_BYTES),
        value_digest: digest(&ask.value),
        refused: None,
        answer_digest: None,
        data_hash: None,
        data_len: 0,
        fetch: None,
        handler_us: 0,
        unanswered: None,
        signed: None,
    }
}
