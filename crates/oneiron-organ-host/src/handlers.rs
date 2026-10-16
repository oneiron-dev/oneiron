//! The handlers a caller supplies for an organ's asks (protocol 1.1). They
//! hold nothing of a process, so a caller on any platform supplies them: the
//! local host runs them on the call's thread, and a mesh call runs them on
//! the asking node while the organ runs on another.

use std::cell::Cell;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use oneiron_organ_protocol::AskRefusal;

use crate::receipt::{AskReceipt, FetchTarget, SignedReceipt};
use crate::spec::FetchGrant;

/// Engine code that answers one ask verb for the calls it is supplied to.
pub trait AskHandler: Sync {
    /// # Errors
    /// A refusal, which the organ receives as the answer.
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal>;
}

/// One ask, as a handler sees it: the ask and the call it came from,
/// nothing of the vault.
#[derive(Debug)]
pub struct AskRequest<'a> {
    pub verb: &'a str,
    pub value: &'a rmpv::Value,
    pub organ: &'a str,
    /// The verb of the call the ask came from.
    pub call_verb: &'a str,
    pub grant: &'a str,
    /// The call's deadline. A handler returns before it; an answer after it
    /// is dropped and the call cancelled.
    pub deadline: Instant,
    /// The answer bytes the call has left.
    pub max_bytes: u64,
    /// The install grant's fetch allowlist.
    pub fetch: &'a FetchGrant,
    /// What a key signed for this ask, for the receipt.
    pub(crate) signing: &'a Mutex<Option<SignedReceipt>>,
}

impl AskRequest<'_> {
    /// Puts a signature on the ask's receipt line, in the host's own words.
    /// Record it before the key signs, then again with the signature's
    /// hash: the line keeps the last one however the ask ends, refused,
    /// unsent or panicked, so a key that signed and then failed still
    /// leaves its prehash on record.
    pub fn record_signing(&self, signed: SignedReceipt) {
        *self.signing.lock().unwrap_or_else(PoisonError::into_inner) = Some(signed);
    }
}

/// A handler's answer.
#[derive(Debug)]
pub struct Answered {
    pub value: rmpv::Value,
    pub data: Option<Vec<u8>>,
    /// For a fetch, where it went, for the receipt.
    pub fetch: Option<FetchTarget>,
}

impl Default for Answered {
    /// A nil value, no bytes.
    fn default() -> Self {
        Self {
            value: rmpv::Value::Nil,
            data: None,
            fetch: None,
        }
    }
}

/// The handlers a caller supplies for one call, by ask verb. They also
/// keep the receipt line of every ask the organ made, however the call
/// ended: a call that fails returns no receipt, but what its handlers did
/// stays on record here.
#[derive(Default)]
pub struct AskHandlers<'a> {
    handlers: Vec<(String, &'a dyn AskHandler)>,
    pub(crate) asked: Mutex<Vec<AskReceipt>>,
}

impl<'a> AskHandlers<'a> {
    /// No handlers: every ask is refused.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Adds the handler for `verb`, replacing any earlier one.
    #[must_use]
    pub fn with(mut self, verb: impl Into<String>, handler: &'a dyn AskHandler) -> Self {
        let verb = verb.into();
        self.handlers.retain(|(named, _)| named != &verb);
        self.handlers.push((verb, handler));
        self
    }

    /// The receipt line of every ask made on the calls these handlers
    /// served, in order, whether each call succeeded or not. Give each call
    /// its own set to keep the calls' lines apart.
    #[must_use]
    pub fn asked(&self) -> Vec<AskReceipt> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The ask verbs these handlers answer.
    pub(crate) fn verbs(&self) -> Vec<String> {
        self.handlers.iter().map(|(verb, _)| verb.clone()).collect()
    }

    pub(crate) fn get(&self, verb: &str) -> Option<&'a dyn AskHandler> {
        self.handlers
            .iter()
            .find(|(named, _)| named == verb)
            .map(|(_, handler)| *handler)
    }
}

impl fmt::Debug for AskHandlers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.handlers.iter().map(|(verb, _)| verb))
            .finish()
    }
}

thread_local! {
    /// Set while an ask handler runs on this thread.
    static IN_HANDLER: Cell<bool> = const { Cell::new(false) };
}

/// Whether this thread is running an ask handler.
pub(crate) fn in_handler() -> bool {
    IN_HANDLER.with(Cell::get)
}

/// Marks this thread as running a handler until dropped.
pub(crate) struct HandlerScope;

impl HandlerScope {
    pub(crate) fn enter() -> Self {
        IN_HANDLER.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for HandlerScope {
    fn drop(&mut self) {
        IN_HANDLER.with(|flag| flag.set(false));
    }
}
