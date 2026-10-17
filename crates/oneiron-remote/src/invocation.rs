//! Client invocation ids (ARCH-0080 §3, OF-580).
//!
//! Every verb call is one logical call and names itself to the server as 32
//! lowercase hex digits: a connected handle sends a fresh one per call as
//! `x-oneiron-invocation`, from the OS CSPRNG. A verb hook that asks first
//! answers the call `PENDING_ASK` (HTTP 202) naming that id and the ask;
//! [`OneironClient::retry`] resends the call under the same id, so the server
//! finds the saved call instead of opening a second ask.

use oneiron::memory::{MEMORY_CODE_PENDING_ASK, MemoryError};
use oneiron::runtime_hooks::{InvocationId, VerbHookStop};
use rand_core::{OsRng, RngCore as _};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Backend, OneironClient};

/// A fresh id for one new verb call.
pub(crate) fn mint() -> InvocationId {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    InvocationId(id)
}

/// The invocation a verb hook's pending ask names: the id the stopped call
/// ran under, to retry it with. `None` for any refusal but `PENDING_ASK`.
#[must_use]
pub fn pending_invocation(error: &MemoryError) -> Option<&str> {
    match error.hook.as_deref() {
        Some(VerbHookStop::Pending { invocation, .. }) if error.code == MEMORY_CODE_PENDING_ASK => {
            Some(invocation.as_str())
        }
        _ => None,
    }
}

impl OneironClient {
    /// Retries the call `pending` answered: `verb` with the same `input`,
    /// under the invocation id that call ran under (ARCH-0080 §3 Ask). While
    /// the ask is open it answers the same `PENDING_ASK`; once the ask is
    /// answered proceed, the saved call runs once and this returns its
    /// result; declined or expired, the hook's skip. `pending` must be a
    /// `PENDING_ASK` refusal ([`pending_invocation`]); anything else is
    /// refused before any call. Every other verb method starts a new call.
    /// Run one retry of a pending call at a time: two at once carry one id in
    /// flight, which the server reads as one nested call.
    pub fn retry<R: DeserializeOwned>(
        &self,
        pending: &MemoryError,
        verb: &str,
        input: &impl Serialize,
    ) -> Result<R, MemoryError> {
        let invocation = pending_invocation(pending)
            .and_then(InvocationId::parse_hex)
            .ok_or_else(|| {
                crate::error::bad_request(
                    "only a pending ask's call is retried under its invocation",
                    &["Call the verb again: a new call gets a new invocation."],
                )
            })?;
        self.ensure_dispatch_pid()?;
        if !oneiron::task_verb::sdk::AgentVerb::from_name(verb)
            .is_some_and(oneiron::task_verb::sdk::AgentVerb::is_facade)
        {
            return Err(
                oneiron::task_verb::sdk::wrong_root(verb).unwrap_or_else(|| {
                    crate::error::bad_request(
                        "unknown SDK agent verb",
                        &["Use a verb from the SDK catalog."],
                    )
                }),
            );
        }
        let input = serde_json::to_value(input).map_err(|_| {
            crate::error::bad_request(
                "SDK input encoding failed",
                &["Send the documented typed SDK input."],
            )
        })?;
        oneiron::task_verb::sdk::validate_input(verb, &input)?;
        match &self.backend {
            Backend::Remote(client) => client.call_as(verb, &input, invocation),
            Backend::Embedded(client) => {
                let result = client.invoke_as(verb, input, invocation)?;
                serde_json::from_value(result).map_err(|error| {
                    crate::error::transport_error(format!(
                        "the embedded SDK answered {verb} with a body this verb could not decode: {error}"
                    ))
                })
            }
        }
    }
}
