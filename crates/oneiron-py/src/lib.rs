//! `oneiron._native` — the private PyO3 extension behind the `oneiron` PyPI
//! package (ONE-1441 WIRE-P1).
//!
//! # Why the boundary is JSON
//!
//! Every DTO crosses as a JSON string. That is not a shortcut: the engine's
//! facade DTOs largely derive `serde` with snake_case field names, which IS
//! the Python naming convention. The one exception is retrieval metadata's
//! `confidenceAdjustment`: the engine/server wire uses camelCase, so recall
//! projects that key to `confidence_adjustment` before returning the Python
//! JSON dict. The alternative — hand-written `#[pyclass]` mirrors of every DTO —
//! would be a second domain model maintained by hand, which is the thing the
//! shared backend exists to prevent.
//!
//! # What is public
//!
//! Nothing here is the public package. `oneiron/__init__.py` wraps
//! `NativeClient` and exports `Oneiron` and `OneironError` only; the export
//! census asserts `not hasattr(oneiron, "NativeClient")`.

use oneiron::memory::{
    ClaimInput, MemoryError, MemoryPack, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use serde::Deserialize;

#[cfg(feature = "engine")]
mod embedded_engine;
// FIX 5342: the rooted-only host-root open.
mod host_root;
mod pairing;

/// One message inside a witnessed turn, with the SDK's optional fields.
///
/// Mirrors the engine DTO except that `is_visible` may be omitted (it defaults
/// to visible, matching every other binding), so a caller writing the
/// documented quickstart dict does not have to spell a field the contract says
/// is optional.
#[derive(Deserialize)]
struct WitnessMessageInput {
    id: Option<String>,
    author: WitnessAuthor,
    message_type: String,
    content: String,
    metadata: Option<serde_json::Value>,
    is_visible: Option<bool>,
    order: u32,
    /// This message's quote (OF-460): a span of one MESSAGE in the same
    /// room, cited by this message; omitted ⇒ no quote.
    #[serde(default)]
    quote: Option<oneiron::conversation_dag::QuoteSpan>,
}

/// One turn to witness, with an OPTIONAL timestamp (I14).
#[derive(Deserialize)]
struct WitnessTurnInput {
    conversation_ref: String,
    turn_ref: Option<String>,
    messages: Vec<WitnessMessageInput>,
    occurred_at: Option<f64>,
    /// A new project room thread root's audience; omitted ⇒ it reads as its
    /// room does.
    #[serde(default)]
    thread_audience: Option<std::collections::BTreeSet<oneiron::EntityId>>,
}

impl WitnessTurnInput {
    /// Lowers onto the engine DTO, stamping an omitted timestamp.
    ///
    /// The stamp comes from `oneiron_remote::stamp_occurred_at` — the same
    /// function the N-API binding calls — so "omitted means now, in Unix
    /// seconds, at the call boundary" has one implementation for both
    /// languages rather than one per language that agree until they do not.
    fn into_engine(self) -> Result<WitnessTurn, MemoryError> {
        let occurred_at = oneiron_remote::stamp_occurred_at(self.occurred_at)?;
        let messages = self
            .messages
            .into_iter()
            .map(|message| WitnessMessage {
                id: message.id,
                author: message.author,
                message_type: message.message_type,
                content: message.content,
                metadata: message.metadata,
                is_visible: message.is_visible.unwrap_or(true),
                order: message.order,
                quote: message.quote,
            })
            .collect();
        Ok(WitnessTurn {
            conversation_ref: self.conversation_ref,
            turn_ref: self.turn_ref,
            thread_audience: self.thread_audience,
            messages,
            occurred_at,
            assertions: Default::default(),
        })
    }
}

/// Raises the engine's refusal as a Python exception carrying the payload.
///
/// The exception's message is the serialized `{code, message, suggestions}`
/// triple, which `oneiron/__init__.py` parses back into `OneironError`. The
/// payload crosses as data, not prose, so the wrapper never has to recover a
/// code by matching on English.
fn raise(error: MemoryError) -> PyErr {
    let payload = serde_json::to_string(&error).unwrap_or_else(|_| {
        format!(
            "{{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":{:?},\"suggestions\":[]}}",
            error.message
        )
    });
    PyRuntimeError::new_err(payload)
}

/// The class of machine a host declares on an embedded open (FIX 5591, as
/// the napi opens read it; CALLS: HOST_OPEN_DEVICE_CLASS =
/// ExplicitHostInput): `"computer"` or `"phone"`, and `None` when it gave
/// none, which opens as a computer. Never read off the operating system;
/// any other name is `BAD_REQUEST`.
fn host_device_class(
    device_class: Option<&str>,
) -> PyResult<Option<oneiron::authority::MachineDeviceClass>> {
    use oneiron::authority::MachineDeviceClass;
    match device_class {
        None => Ok(None),
        Some("computer") => Ok(Some(MachineDeviceClass::Computer)),
        Some("phone") => Ok(Some(MachineDeviceClass::Phone)),
        Some(other) => Err(raise(MemoryError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!("unknown device_class {other:?}; pass \"computer\" or \"phone\""),
            &["Pass device_class \"computer\" or \"phone\", or omit it for a computer."],
        ))),
    }
}

/// Refuses a body that is not the documented shape, in the same vocabulary.
fn decode<'de, T: Deserialize<'de>>(json: &'de str, what: &str) -> PyResult<T> {
    serde_json::from_str(json).map_err(|error| {
        raise(MemoryError {
            code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(),
            message: format!("{what} is not the documented shape: {error}"),
            suggestions: vec![format!(
                "Check the {what} keys against the oneiron type stubs."
            )],
            successor_short_id: None,
            gate_denial: None,
            read_receipt: None,
            policy_denial: None,
            wrong_root: None,
            hook: None,
            retry_after: None,
        })
    })
}

/// Reports a serialization failure as a typed SDK error.
fn encode_error(error: serde_json::Error) -> PyErr {
    raise(MemoryError {
        code: oneiron::memory::MEMORY_CODE_INTERNAL.to_owned(),
        message: format!("could not serialize the response: {error}"),
        suggestions: vec!["This is an Oneiron SDK bug; please report it.".to_owned()],
        successor_short_id: None,
        gate_denial: None,
        read_receipt: None,
        policy_denial: None,
        wrong_root: None,
        hook: None,
        retry_after: None,
    })
}

/// Serializes a success DTO back to the Python side.
fn encode<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(encode_error)
}

/// Projects the engine/server's sole camelCase retrieval field for Python.
fn encode_recall(pack: &MemoryPack) -> PyResult<String> {
    let mut value = serde_json::to_value(pack).map_err(encode_error)?;
    let meta = value["retrieval_meta"]
        .as_object_mut()
        .expect("MemoryPack always serializes retrieval_meta as an object");
    if let Some(adjustment) = meta.remove("confidenceAdjustment") {
        meta.insert("confidence_adjustment".to_owned(), adjustment);
    }
    encode(&value)
}

/// The private native handle behind the `oneiron` Python package.
#[pyclass]
struct NativeClient {
    inner: oneiron_remote::OneironClient,
}

#[pymethods]
impl NativeClient {
    /// Opens an embedded vault; `path` omitted resolves to `~/.oneiron/default`.
    /// `device_class` is the host's declaration ([`host_device_class`]).
    #[staticmethod]
    #[pyo3(signature = (path=None, dimensions=None, device_class=None))]
    fn open(
        py: Python<'_>,
        path: Option<std::path::PathBuf>,
        dimensions: Option<usize>,
        device_class: Option<String>,
    ) -> PyResult<Self> {
        // Crash output never carries world text: the engine's hook goes in before
        // any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let options = oneiron_remote::OpenOptions {
            dimensions,
            device_class: host_device_class(device_class.as_deref())?,
        };
        let inner = py
            .detach(|| oneiron_remote::OneironClient::open(path.as_deref(), &options))
            .map_err(raise)?;
        Ok(Self { inner })
    }

    /// `open`, then this install's own machine profile from the vault's host
    /// root secret, its exact bytes borrowed for this call (FIX 5342).
    /// `device_class` is `open`'s.
    #[staticmethod]
    #[pyo3(signature = (path, host_root_secret, dimensions=None, device_class=None))]
    fn open_with_host_root(
        py: Python<'_>,
        path: Option<std::path::PathBuf>,
        host_root_secret: &[u8],
        dimensions: Option<usize>,
        device_class: Option<String>,
    ) -> PyResult<Self> {
        let device_class = host_device_class(device_class.as_deref())?;
        let inner = host_root::open(py, path, host_root_secret, dimensions, device_class)?;
        Ok(Self { inner })
    }

    /// What `open_with_host_root` did with its root, as JSON; `None` on
    /// every other handle.
    fn host_root_profile(&self) -> PyResult<Option<String>> {
        host_root::profile(&self.inner)
    }

    /// Binds a remote `oneiron-server`. `key` is the credential `pair`
    /// returned; every request is signed with it, and write identity is the
    /// server's.
    #[staticmethod]
    fn connect(py: Python<'_>, url: String, key: String) -> PyResult<Self> {
        let inner = py
            .detach(|| oneiron_remote::OneironClient::connect(&url, &key))
            .map_err(raise)?;
        Ok(Self { inner })
    }

    /// Redeems a pairing link once; returns the `{url, credential, pin, comm}`
    /// JSON `pairing::Paired` writes: the pin the link named or `null`, and
    /// the credential's comm reach.
    #[staticmethod]
    fn pair(py: Python<'_>, link: String) -> PyResult<String> {
        let paired = py
            .detach(|| oneiron_remote::OneironClient::pair_pinned(&link))
            .map_err(raise)?;
        encode(&pairing::Paired::from_engine(paired))
    }

    /// Returns a NEW handle bound to another actor; refuses when connected.
    fn as_actor(&self, py: Python<'_>, actor_key: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.as_actor(&actor_key))
            .map_err(raise)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    fn in_room_turn(&self, py: Python<'_>, room_ref: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.in_room_turn(&room_ref))
            .map_err(raise)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle whose every verb runs inside the off-record
    /// session `session_ref` names, bound to this handle's principal: the
    /// app host's actor when embedded (OF-063). It grants nothing.
    fn in_off_record_session(&self, py: Python<'_>, session_ref: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.in_off_record_session(&session_ref))
            .map_err(raise)?;
        Ok(Self { inner })
    }

    /// The lasting call receipt the last verb's reply stated, as
    /// `call:<32hex>`, whether it answered or refused. `None` for an embedded
    /// handle, before any call, after a call that reached no server, and for
    /// an anonymous off-record call.
    fn last_receipt_ref(&self) -> Option<String> {
        self.inner.last_receipt_ref()
    }

    /// Resends the call a `PENDING_ASK` refusal answered: `verb` with the
    /// same input, under the invocation id the refusal's `hook` names
    /// (ARCH-0080 §3, OF-580). `pending_json` is that refusal as its
    /// serialized MemoryError. The reply is the shared wire JSON for `verb`,
    /// not the projection its own method encodes (no `encode_recall`
    /// renaming). The id, the pending check and the input check all stay in
    /// `oneiron_remote::OneironClient::retry`.
    fn retry(
        &self,
        py: Python<'_>,
        pending_json: &str,
        verb: &str,
        input_json: &str,
    ) -> PyResult<String> {
        let pending: MemoryError = decode(pending_json, "pending")?;
        let input: serde_json::Value = decode(input_json, verb)?;
        let output = py
            .detach(|| {
                self.inner
                    .retry::<serde_json::Value>(&pending, verb, &input)
            })
            .map_err(raise)?;
        encode(&output)
    }

    /// Sends one event on a lens card the connected server rendered
    /// (OF-181). `request_json` is the route's `{event, idempotencyKey}`
    /// body, camelCase as the wire spells it; the reply is its wire JSON,
    /// `{"$state"}` or `{outcome, readReceipt}`. The route, the credential
    /// and the embedded refusal all stay in
    /// `oneiron_remote::OneironClient::lens_frame_event`.
    fn lens_frame_event(
        &self,
        py: Python<'_>,
        card_id: &str,
        request_json: &str,
    ) -> PyResult<String> {
        let request: oneiron_remote::LensFrameEventRequest =
            decode(request_json, "lens frame event")?;
        let output = py
            .detach(|| self.inner.lens_frame_event(card_id, &request))
            .map_err(raise)?;
        encode(&output)
    }

    /// Closes a lens card the connected server rendered and frees its frame
    /// (OF-181); the reply is the route's `{closed}`.
    fn close_lens_frame(&self, py: Python<'_>, card_id: &str) -> PyResult<String> {
        let output = py
            .detach(|| self.inner.close_lens_frame(card_id))
            .map_err(raise)?;
        encode(&output)
    }

    // BEGIN GENERATED AGENT VERBS
    fn vault_commitments_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_instances(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.instances")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.instances", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_proposals(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.proposals")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.proposals", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_fulfill(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.fulfill")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.fulfill", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_release(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.release")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.release", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commitments_supersede(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commitments.supersede")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commitments.supersede", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn fetch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "fetch")?;
        let output = py
            .detach(|| self.inner.agent_verb("fetch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn crawl(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "crawl")?;
        let output = py
            .detach(|| self.inner.agent_verb("crawl", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn report(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "report")?;
        let output = py
            .detach(|| self.inner.agent_verb("report", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn feedback_preview(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "feedback.preview")?;
        let output = py
            .detach(|| self.inner.agent_verb("feedback.preview", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn feedback_send(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "feedback.send")?;
        let output = py
            .detach(|| self.inner.agent_verb("feedback.send", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_reports_disclosure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.reports.disclosure")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.reports.disclosure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_reports_route(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.reports.route")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.reports.route", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_reports_outbound(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.reports.outbound")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.reports.outbound", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_wakes(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.wakes")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.wakes", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_scratchpad_recall(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.scratchpad.recall")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.scratchpad.recall", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_scratchpad_append(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.scratchpad.append")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.scratchpad.append", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_scratchpad_seal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.scratchpad.seal")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.scratchpad.seal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_memory_diary(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.memory.diary")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.memory.diary", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_memory_diary_reads(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.memory.diary.reads")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.memory.diary.reads", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_memory_diary_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.memory.diary.review")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.memory.diary.review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_standing_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.standing.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.standing.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_standing_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.standing.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.standing.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_standing_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.standing.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.standing.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_identity_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.identity.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.identity.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_identity_settle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.identity.settle")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.identity.settle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_mark(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.mark")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.mark", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_concern(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.concern")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.concern", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_concern_outcome(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.concern.outcome")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.concern.outcome", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_concern_move(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.concern.move")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.concern.move", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_diagnostics_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.diagnostics.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.diagnostics.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_diagnostics_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.diagnostics.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.diagnostics.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_inspect(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.inspect")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.coach.inspect", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_people_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.people.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.people.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_people_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.people.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.people.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_people_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.people.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.people.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_entities_look_before_mint(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.entities.look_before_mint")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.entities.look_before_mint", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_mention(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.mention")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.mention", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shape_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shape.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shape.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shape_plan(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shape.plan")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shape.plan", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shape_apply(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shape.apply")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shape.apply", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_message(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.message")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.message", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_grants_ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.grants.ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.grants.ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_companions_access_requests_answer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.companions.access_requests.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.companions.access_requests.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_personas_preview(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.personas.preview")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.personas.preview", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_personas_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.personas.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.personas.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_personas_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.personas.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.personas.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_memory_diary_query(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.memory.diary.query")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.memory.diary.query", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn cancel(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "cancel")?;
        let output = py
            .detach(|| self.inner.agent_verb("cancel", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn steer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "steer")?;
        let output = py
            .detach(|| self.inner.agent_verb("steer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn describe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "describe")?;
        let output = py
            .detach(|| self.inner.agent_verb("describe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_wave(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.wave")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.wave", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_spawn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.spawn")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.spawn", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_slots(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.slots")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.slots", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_launch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.launch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.launch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_budget(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.budget")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.budget", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_budget_land(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.budget.land")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.budget.land", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_lease_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.lease.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.lease.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_lease(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.lease")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.lease", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_lease_top_up(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.lease.top_up")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.lease.top_up", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_hold(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.hold")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.hold", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_hold_resume(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.hold.resume")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.hold.resume", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_local(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.local")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.local", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_reservations(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.reservations")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.reservations", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_settlements(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.settlements")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.settlements", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_rsi_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.rsi.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.rsi.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_rsi(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.rsi")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.rsi", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_rsi_top_up(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.rsi.top_up")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.rsi.top_up", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_rsi_hold(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.rsi.hold")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.budgets.rsi.hold", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_budgets_rsi_hold_resume(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.budgets.rsi.hold.resume")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.budgets.rsi.hold.resume", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_resume(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.resume")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.resume", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_resume_as(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.resume_as")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.resume_as", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_fanout_ack(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.fanout.ack")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.fanout.ack", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_accept(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.accept")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.accept", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commit_message(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commit_message")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commit_message", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_begin_message_stream(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.begin_message_stream")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.begin_message_stream", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_append_to_stream(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.append_to_stream")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.append_to_stream", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_flush_stream(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.flush_stream")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.flush_stream", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_finalize_stream(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.finalize_stream")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.finalize_stream", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cancel_stream(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cancel_stream")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cancel_stream", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_message_stream_partial(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.message_stream_partial")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.message_stream_partial", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_messages_durability(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.messages.durability")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.messages.durability", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_witness(&self, py: Python<'_>, turn_json: &str) -> PyResult<String> {
        let turn_json = decode::<WitnessTurnInput>(turn_json, "witness turn")?
            .into_engine()
            .map_err(raise)?;
        let output = py
            .detach(|| self.inner.vault_witness(&turn_json))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_upsert(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.upsert")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.upsert", input))
            .map_err(raise)?;
        encode(&output)
    }
    #[pyo3(signature = (query, effort=None, scope_json=None, limit=None, format=None, as_of=None, deadline_ms=None, media_json=None, query_affect_json=None))]
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per SDK argument of the verb"
    )]
    fn vault_recall(
        slf: PyRef<'_, Self>,
        query: String,
        effort: Option<&str>,
        scope_json: Option<&str>,
        limit: Option<usize>,
        format: Option<String>,
        as_of: Option<u64>,
        deadline_ms: Option<u64>,
        media_json: Option<&str>,
        query_affect_json: Option<&str>,
    ) -> PyResult<String> {
        let effort = oneiron_remote::parse_effort(effort.unwrap_or("medium")).map_err(raise)?;
        let scope_json = match scope_json {
            Some(value) => decode(value, "recall scope")?,
            None => oneiron::memory::RecallScope::default(),
        };
        let limit = limit.unwrap_or(10);

        let media_json: Option<oneiron::code_run::vault_read::ContextPackMediaQuery> = media_json
            .map(|value| decode(value, "recall media"))
            .transpose()?;
        let query_affect_json: Option<oneiron::task_verb::sdk::QueryAffect> = query_affect_json
            .map(|value| decode(value, "recall query affect"))
            .transpose()?;
        let inner = &slf.inner;
        let py = slf.py();
        let output = py
            .detach(|| {
                inner.vault_recall(
                    &query,
                    effort,
                    &scope_json,
                    limit,
                    format.as_deref(),
                    as_of,
                    deadline_ms,
                    media_json,
                    query_affect_json,
                )
            })
            .map_err(raise)?;
        encode_recall(&output)
    }
    fn vault_retrieval_aging_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.aging.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.aging.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_aging_configure(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.aging.configure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.aging.configure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_weights_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.weights.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.weights.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_weights_configure(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.weights.configure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.weights.configure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_hyde_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.hyde.configure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.hyde.configure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_hyde_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.hyde.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.hyde.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_hyde_pending(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.hyde.pending")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.hyde.pending", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_hyde_complete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.hyde.complete")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.hyde.complete", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_hyde_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.hyde.receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.hyde.receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_annotations_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.annotations.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.affect.annotations.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tagging_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tagging.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tagging.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tagging_tags(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tagging.tags")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tagging.tags", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tagging_history(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tagging.history")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tagging.history", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tagging_mentions(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tagging.mentions")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tagging.mentions", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_claims_consolidate(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.claims.consolidate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.affect.claims.consolidate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_coping_record(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.coping.record")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.affect.coping.record", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_coping_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.coping.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.affect.coping.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_coping_aggregate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.coping.aggregate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.affect.coping.aggregate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_wellness_policy_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.wellness.policy.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.affect.wellness.policy.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_wellness_policy_configure(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.affect.wellness.policy.configure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.affect.wellness.policy.configure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_wellness_derive(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.wellness.derive")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.affect.wellness.derive", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_affect_wellness_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.affect.wellness.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.affect.wellness.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cluster", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster_proposal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster.proposal")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cluster.proposal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cluster.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster_merge(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster.merge")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cluster.merge", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster_split(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster.split")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cluster.split", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cluster_resolve_proposal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cluster.resolve_proposal")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.cluster.resolve_proposal", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_recall(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.recall")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.recall", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_runs(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.runs")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.runs", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.run")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_turn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.turn")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.turn", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_outcomes_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.outcomes.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.outcomes.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_outcomes_end(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.outcomes.end")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.outcomes.end", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_trace(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.trace")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.trace", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_replay(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.replay")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.replay", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.policy.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_pin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.pin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.policy.pin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_train(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.train")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.policy.train", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_evaluate(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.evaluate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.policy.evaluate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.retrieval.policy.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_retrieval_policy_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.retrieval.policy.update")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.retrieval.policy.update", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_credential_attenuate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.credential.attenuate")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.credential.attenuate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_scope_position(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.scope.position")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.scope.position", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_scope_ceiling(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.scope.ceiling")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.scope.ceiling", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_export_scoped(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.export.scoped")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.export.scoped", input))
            .map_err(raise)?;
        encode(&output)
    }
    #[pyo3(signature = (limit=None, kinds=None))]
    fn vault_receipts(
        &self,
        py: Python<'_>,
        limit: Option<usize>,
        kinds: Option<Vec<String>>,
    ) -> PyResult<String> {
        let limit = limit.unwrap_or(100);
        let kinds = kinds.unwrap_or_default();
        let output = py
            .detach(|| self.inner.vault_receipts(limit, &kinds))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_assets_ingest(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.assets.ingest")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.assets.ingest", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_assets_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.assets.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.assets.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_search_vector(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.search.vector")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.search.vector", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_images_view(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.images.view")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.images.view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_receipts_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.receipts.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.receipts.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_admission_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.admission.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.admission.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_admission_receipts(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.admission.receipts")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.admission.receipts", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_explain_memory(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.explain.memory")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.explain.memory", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_explain_gate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.explain.gate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.explain.gate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_kv_get(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.kv.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.kv.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_kv_put(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.kv.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.kv.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_kv_delete(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.kv.delete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.kv.delete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_kv_search(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.kv.search")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.kv.search", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_kv_namespaces(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.kv.namespaces")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.kv.namespaces", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_install(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.install")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.install", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_amend(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.amend")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.amend", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_approve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_reject(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.reject")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.reject", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_verify(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.verify")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.verify", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_compliance_result(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.compliance.result")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.compliance.result", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_enroll(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.enroll")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.campaign.enroll", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_stage_evidence(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.stage.evidence")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.stage.evidence", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_unsubscribe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.unsubscribe")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.campaign.unsubscribe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_program_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.program.create")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.program.create", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_program_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.program.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.campaign.program.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_program_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.program.update")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.program.update", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_campaign_program_archive(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.campaign.program.archive")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.campaign.program.archive", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_turn_programs_arm(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.turn_programs.arm")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.turn_programs.arm", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_turn_programs_disarm(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.turn_programs.disarm")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.turn_programs.disarm", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_archive(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.archive")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.archive", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_members(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.members")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.members", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_saved_query_evaluate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.saved_query.evaluate")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.saved_query.evaluate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_report(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.report")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.report", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_digest(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.digest")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.digest", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_lens(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.lens")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.lens", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_link_wrong(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.link.wrong")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.link.wrong", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_owner_link_wrong(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.owner.link.wrong")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.owner.link.wrong", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_item_wrong(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.item.wrong")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.item.wrong", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_owner_item_wrong(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.owner.item.wrong")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.owner.item.wrong", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_enqueue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.enqueue")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.enqueue", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_schedules_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.schedules.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.schedules.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_schedules_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.schedules.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.schedules.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_schedules_clear(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.schedules.clear")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.schedules.clear", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_setting_changes_list(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.setting_changes.list")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.weave.setting_changes.list", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_setting_changes_answer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.setting_changes.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.weave.setting_changes.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_setting_changes_undo(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.setting_changes.undo")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.weave.setting_changes.undo", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_digest_feedback_put(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.digest_feedback.put")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.weave.digest_feedback.put", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_owner_digest_render(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.owner.digest.render")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.weave.owner.digest.render", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_inbox_concerns_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.inbox.concerns.review")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.inbox.concerns.review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_inbox_lens(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.inbox.lens")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.inbox.lens", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_inbox_groups(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.inbox.groups")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.inbox.groups", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_digest_render(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.digest.render")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.digest.render", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_weave_link_corrections(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.weave.link.corrections")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.weave.link.corrections", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_inbox_lens(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.inbox.lens")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.inbox.lens", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_bootstrap(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.bootstrap")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.bootstrap", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_default_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.default.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skill_hubs.default.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_restoreDefaults(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.restoreDefaults")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.restoreDefaults", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skill_hubs.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skill_hubs.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_publishers_admit(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.publishers.admit")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skill_hubs.publishers.admit", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_publishers_revoke(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.publishers.revoke")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skill_hubs.publishers.revoke", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_refs_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.refs.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skill_hubs.refs.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skill_hubs_refs_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skill_hubs.refs.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skill_hubs.refs.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_install(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.install")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.install", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sync(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sync")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sync", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_import(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.import")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.import", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_sync(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.sync")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.sync", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_receipts(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.receipts")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.receipts", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_convert(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.convert")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.convert", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_archive(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.archive")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.archive", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_restore(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.restore")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.restore", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_fork(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.fork")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.fork", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_rules_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.rules.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.rules.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_code_auto_install_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.code_auto_install.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.code_auto_install.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_permissions_approve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.permissions.approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.permissions.approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_start(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.start")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.optimize.start", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_result(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.result")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.optimize.result", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_goal_intake_complete(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.goal.intake.complete")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.projects.goal.intake.complete", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_goal_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.goal.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.goal.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.propose")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.propose", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_measure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.measure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.measure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_score(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.score")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.optimize.score", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.optimize.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_goal_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.goal.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.goal.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_goal_bind(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.goal.bind")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.goal.bind", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_preferences_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.preferences.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.preferences.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_preferences_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.preferences.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.preferences.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_tradeoff_asks(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.optimize.tradeoff_asks")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.tradeoff_asks", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_optimize_tradeoff_asks_pick(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.skills.optimize.tradeoff_asks.pick")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.optimize.tradeoff_asks.pick", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_governance_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.governance.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.governance.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_governance_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.governance.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.governance.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_hooks_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.hooks.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.hooks.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_hooks_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.hooks.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.hooks.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_hooks_grant_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.hooks.grant.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.hooks.grant.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_hooks_grant_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.hooks.grant.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.hooks.grant.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_hooks_qualify(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.hooks.qualify")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.hooks.qualify", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_preview(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.preview")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.preview", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_prepare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.prepare")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.connector.prepare", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.connector.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_qualify(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.qualify")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.connector.qualify", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_accept(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.accept")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.connector.accept", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.connector.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_grants_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.grants.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.connector.grants.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_connector_grants_put(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.connector.grants.put")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.connector.grants.put", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_remove(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.remove")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.remove", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sections.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sections.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_grant(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.grant")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sections.grant", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sections.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_suggest(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.suggest")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.sections.suggest", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_suggestions_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.suggestions.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.sections.suggestions.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_sections_suggestions_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.sections.suggestions.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.packs.sections.suggestions.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_chat_completions(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.chat.completions")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.chat.completions", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_connectors_proxy_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.connectors.proxy.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.connectors.proxy.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_connectors_proxy_revoke_write(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.connectors.proxy.revoke_write")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.connectors.proxy.revoke_write", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_connectors_subscriptions_put(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.connectors.subscriptions.put")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.connectors.subscriptions.put", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_connectors_subscriptions_list(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.connectors.subscriptions.list")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.connectors.subscriptions.list", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_connectors_subscriptions_revoke(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.connectors.subscriptions.revoke")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.connectors.subscriptions.revoke", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_setup_prepare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.setup.prepare")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.setup.prepare", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_setup_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.setup.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.setup.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_setup_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.setup.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.setup.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_packs_setup_verify(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.setup.verify")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.setup.verify", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_authority_audit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.authority.audit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.authority.audit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_authority_history_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.authority.history.export")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.authority.history.export", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_authority_history_import(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.authority.history.import")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.authority.history.import", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_wire_health_thresholds_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.wire_health.thresholds.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.wire_health.thresholds.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_wire_health_thresholds_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.wire_health.thresholds.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.wire_health.thresholds.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_slim_policy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.slim.policy")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.slim.policy", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_slim_state(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.slim.state")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.slim.state", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_slim_resume_step(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.slim.resume_step")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.slim.resume_step", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_slim_drop_heavy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.slim.drop_heavy")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.slim.drop_heavy", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_slim_resume(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.slim.resume")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.slim.resume", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_path_receipts(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.path_receipts")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.path_receipts", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_identity(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.identity")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.identity", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_bind_machine(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.bind_machine")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.bind_machine", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_set_alpn_grant(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.set_alpn_grant")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.set_alpn_grant", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_revoke_machine(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.revoke_machine")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.revoke_machine", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_mesh_dial(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.mesh.dial")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.mesh.dial", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_inspection_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.inspection.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.inspection.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_propose_delete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.propose_delete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.propose_delete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_propose_transfer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.propose_transfer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.shared.propose_transfer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_propose_remove_owner(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.propose_remove_owner")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.shared.propose_remove_owner", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_execute(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.execute")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.execute", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_outcomes(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.outcomes")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.outcomes", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_deletion(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.deletion")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.deletion", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_org_admin_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.org_admin.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.org_admin.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_org_admin_powers(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.org_admin.powers")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.org_admin.powers", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_reset_project_access(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.reset_project_access")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.members.reset_project_access", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_delegate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.delegate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.delegate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_projection(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.projection")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.projection", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_add(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.add")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.add", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_invitation_slip(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.invitation_slip")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.members.invitation_slip", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_change(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.change")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.change", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_remove(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.remove")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.remove", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_leave(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.leave")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.leave", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_invitations(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.invitations")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.invitations", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_accept(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.accept")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.accept", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_decline(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.decline")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.decline", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_members_withdraw_invitation(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.withdraw_invitation")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.members.withdraw_invitation", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_object(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.object")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.object", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_withdraw_objection(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.withdraw_objection")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.shared.withdraw_objection", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_started(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.started")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.started", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_matured(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.matured")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.matured", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_erase_ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.erase_ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.erase_ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_erase_asks(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.erase_asks")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.erase_asks", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_close_erase_ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.close_erase_ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.close_erase_ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_policy_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.policy.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.policy.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_policy_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.policy.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.policy.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_policy_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.policy.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.policy.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shared_policy_change(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shared.policy.change")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shared.policy.change", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_coreference_link(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.coreference.link")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.coreference.link", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_coreference_confirm(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.coreference.confirm")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.coreference.confirm", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_coreference_share_consent(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.federation.coreference.share_consent")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.coreference.share_consent", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_coreference_unlink(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.coreference.unlink")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.coreference.unlink", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_baseline(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.baseline")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.baseline", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_policy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.policy")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.policy", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_policy_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.policy.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.policy.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_ingress(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.ingress")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.ingress", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_disposition(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.disposition")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.disposition", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.review")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.review", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_review_release(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.review.release")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.review.release", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_review_reject(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.review.reject")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.review.reject", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_burst_replay(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.burst.replay")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.burst.replay", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_identity(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.identity")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.identity", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_grants_mint(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.grants.mint")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.grants.mint", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_offer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.offer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.offer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_accept(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.accept")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.accept", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_narrow(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.narrow")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.narrow", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_rescope_offer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.federation.connect.rescope.offer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.rescope.offer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_rescope_accept(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.federation.connect.rescope.accept")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.rescope.accept", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_disconnect(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.disconnect")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.disconnect", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_export(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.export")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.export", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_federation_connect_rejoin(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.federation.connect.rejoin")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.federation.connect.rejoin", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_name(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.name")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.trusted_contacts.name", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.trusted_contacts.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_consent(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.consent")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.consent", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.revoke")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.revoke", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_dial_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.dial.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.dial.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_tier_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.tier.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.tier.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_concern_asks(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.trusted_contacts.concern.asks")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.concern.asks", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_concern_authorize(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.trusted_contacts.concern.authorize")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.concern.authorize", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_concern_propose(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.trusted_contacts.concern.propose")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.concern.propose", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_trusted_contacts_concern_deliver(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.trusted_contacts.concern.deliver")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.trusted_contacts.concern.deliver", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_guests_share(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.guests.share")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.guests.share", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_guests_export_envelope(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.guests.export_envelope")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.guests.export_envelope", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_guests_reshare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.guests.reshare")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.guests.reshare", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_guests_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.guests.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.guests.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_guests_mint_slip(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.guests.mint_slip")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.guests.mint_slip", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_support_grants_mint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.support_grants.mint")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.support_grants.mint", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_support_grants_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.support_grants.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.support_grants.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_support_grants_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.support_grants.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.support_grants.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_residence_mode(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.residence.mode")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.residence.mode", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_residence_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.residence.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.residence.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_residence_index(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.residence.index")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.residence.index", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_residence_prune(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.residence.prune")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.residence.prune", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_residence_directives(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.residence.directives")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.residence.directives", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_start(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.start")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.start", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_witness(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.witness")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.witness", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_discard(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.discard")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.discard", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_recall(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.recall")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.recall", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_notes_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.notes.create")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.notes.create", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_claims_upsert(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.claims.upsert")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.claims.upsert", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn self_off_record_execute(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.off_record.execute")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.off_record.execute", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.status")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.status", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_start(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.start")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.rooms.start", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_witness(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.witness")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.witness", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_save(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.save")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.off_record.rooms.save", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_save_from_here(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.save_from_here")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.save_from_here", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.export")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.export", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_suggest_save(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.suggest_save")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.suggest_save", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_confirm_save(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.confirm_save")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.confirm_save", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_off_record_rooms_decline_save(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.off_record.rooms.decline_save")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.off_record.rooms.decline_save", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_records_erase_preview(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.records.erase_preview")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.records.erase_preview", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_records_erase_confirm(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.records.erase_confirm")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.records.erase_confirm", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_records_erase_sweep(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.records.erase_sweep")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.records.erase_sweep", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_create_child(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.create_child")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.create_child", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.archive", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_install(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.install")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.archive.install", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_record(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.record")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.archive.record", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.archive.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_best(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.best")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.archive.best", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_repropose(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.repropose")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.archive.repropose", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_archive_coverage(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.archive.coverage")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.archive.coverage", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_inventory(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.inventory")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.inventory", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_cohorts_setup(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.cohorts.setup")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.cohorts.setup", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_author_now(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.author_now")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.author_now", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_authoring_result(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.authoring.result")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.authoring.result", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_families(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.families")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.families", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_families_assign(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.families.assign")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.families.assign", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_cases(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.cases")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.cases", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_cases_record(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.cases.record")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.cases.record", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_cohorts(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.cohorts")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.cohorts", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_cohorts_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.cohorts.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.cohorts.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_exposure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.exposure")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.exposure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_sufficiency(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.sufficiency")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.sufficiency", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_labels_blocked(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.labels.blocked")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.labels.blocked", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_evals_labels_pick(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.evals.labels.pick")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.evals.labels.pick", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.coach.training_offers", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_trigger(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers.trigger")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.trigger", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_result(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers.result")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.result", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_answer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_undo(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.coach.training_offers.undo")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.undo", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_candidates(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.coach.training_offers.candidates")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.candidates", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_candidates_prepare(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.coach.training_offers.candidates.prepare")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.candidates.prepare", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_pilots_prepare(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.coach.training_offers.pilots.prepare")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.pilots.prepare", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_pilots_complete(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.coach.training_offers.pilots.complete")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.pilots.complete", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_coach_training_offers_pilots_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.coach.training_offers.pilots.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.coach.training_offers.pilots.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_fork(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.fork")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.fork", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_weave(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.weave")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.weave", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_measure_search(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.measure_search")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.measure_search", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_measure_held_out(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.measure_held_out")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.measure_held_out", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_evaluate_split(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.evaluate_split")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.evaluate_split", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_mark_invalid(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.mark_invalid")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.mark_invalid", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_prune(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.prune")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.prune", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_select(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.select")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.select", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_promotion_basis(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.promotion_basis")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.promotion_basis", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_reserve_confirmation(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.reserve_confirmation")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.reserve_confirmation", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_promote(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.promote")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.promote", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_reserve_work(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.reserve_work")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.reserve_work", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_settle_work(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.settle_work")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.settle_work", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_refund_work(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.refund_work")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.refund_work", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_reserve_exploration(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.reserve_exploration")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.reserve_exploration", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_budget(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.budget")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.research.budget", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_research_record_benchmark(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.research.record_benchmark")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.research.record_benchmark", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_authority_handoff_alarms(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.authority.handoff_alarms")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.authority.handoff_alarms", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_authority_handoff_alarms_acknowledge(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.authority.handoff_alarms.acknowledge")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.authority.handoff_alarms.acknowledge", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_roots_requests_cancel(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.roots.requests.cancel")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.roots.requests.cancel", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_cleanup_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.cleanup.run")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.cleanup.run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_usage_events_undecodable(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.usage.events.undecodable")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.usage.events.undecodable", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_usage_events_remove_undecodable(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.usage.events.remove_undecodable")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.usage.events.remove_undecodable", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_entities_mention(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.entities.mention")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.entities.mention", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_legal_holds_place(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.legal_holds.place")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.legal_holds.place", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_legal_holds_widen(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.legal_holds.widen")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.legal_holds.widen", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_legal_holds_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.legal_holds.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.legal_holds.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_legal_holds_log(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.legal_holds.log")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.legal_holds.log", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_legal_holds_lift_and_erase(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.legal_holds.lift_and_erase")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.legal_holds.lift_and_erase", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_courtesy_delete_send(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.courtesy_delete.send")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.courtesy_delete.send", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_courtesy_delete_sent(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.courtesy_delete.sent")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.courtesy_delete.sent", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_courtesy_delete_incoming(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.courtesy_delete.incoming")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.courtesy_delete.incoming", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_courtesy_delete_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.courtesy_delete.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.courtesy_delete.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.embedding_spaces.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_declare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.declare")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.declare", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.embedding_spaces.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_one_space(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.one_space")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.one_space", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_retire(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.retire")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.retire", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_move(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.move")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.embedding_spaces.move", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_move_check(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.move_check")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.move_check", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_move_approve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.move_approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.move_approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_move_undo(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.move_undo")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.move_undo", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_move_abandon(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.move_abandon")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.move_abandon", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_probes_list(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.probes.list")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.probes.list", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_probes_put(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.probes.put")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.probes.put", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_embedding_spaces_probes_delete(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.embedding_spaces.probes.delete")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.embedding_spaces.probes.delete", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_policy_owner_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.policy.owner.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.policy.owner.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_policy_owner_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.policy.owner.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.policy.owner.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_policy_owner_row_change(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.policy.owner.row.change")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.policy.owner.row.change", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_policy_outbound_decide(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.policy.outbound.decide")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.policy.outbound.decide", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_policy_relay_decide(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.policy.relay.decide")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.policy.relay.decide", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_approve_once(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.approve_once")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consent.approve_once", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_deny(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.deny")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consent.deny", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_create_standing_grant(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.create_standing_grant")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.create_standing_grant", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_registry(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.registry")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consent.registry", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_failure_signals_held(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.failure_signals_held")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.failure_signals_held", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consent.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_bypass_grant_warning(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.bypass_grant_warning")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.bypass_grant_warning", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_create_bypass_grant(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.create_bypass_grant")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.create_bypass_grant", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_active_bypass_grants(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.active_bypass_grants")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.active_bypass_grants", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_bypassed_effect_receipts(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.consent.bypassed_effect_receipts")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.bypassed_effect_receipts", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_policy(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.policy")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.policy", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_policy_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.policy.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.policy.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_policy_clear(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.policy.clear")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.policy.clear", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_stats(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.stats")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.stats", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_outcome(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.outcome")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.outcome", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_offers(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.offers")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.offers", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_answer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_trust_table(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.trust_table")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.trust_table", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_settings_unpin(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.consent.graduation.settings.unpin")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.settings.unpin", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consent_graduation_demote(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consent.graduation.demote")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consent.graduation.demote", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn self_consent_graduation_demote(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.consent.graduation.demote")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("self.consent.graduation.demote", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_gate_policy_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.gate.policy.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.gate.policy.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_gate_policy_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.gate.policy.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.gate.policy.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_gate_policy_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.gate.policy.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.gate.policy.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_gate_checker_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.gate.checker.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.gate.checker.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_gate_checker_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.gate.checker.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.gate.checker.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_learning_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.learning.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.learning.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_learning_projection(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.learning.projection")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.learning.projection", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_confess(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.confess")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.confess", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_audit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.audit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.audit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_pending(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.pending")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.pending", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.run")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_seal_complete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.seal.complete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.seal.complete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_learning(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.settings.learning")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.settings.learning", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_learning_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.settings.learning.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.settings.learning.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_learning_clear(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.settings.learning.clear")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.settings.learning.clear", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_secrets_lift_history(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.secrets.lift_history")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.secrets.lift_history", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_widen_proposals(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.widen_proposals")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.widen_proposals", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_widen_proposals_approve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.widen_proposals.approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.widen_proposals.approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_widen_proposals_decline(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.widen_proposals.decline")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.widen_proposals.decline", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.review")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_settle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.settle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.settle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_craft_candidates(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.craft_candidates")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.craft_candidates", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_craft_candidates_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.craft_candidates.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.craft_candidates.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_wake_policy_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.settings.wake_policy.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.settings.wake_policy.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_inference_defaults(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.settings.inference_defaults")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.settings.inference_defaults", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_settings_inference_defaults_replace(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.settings.inference_defaults.replace")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.settings.inference_defaults.replace", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_activate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.activate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.activate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_deactivate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.deactivate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.deactivate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_select(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.select")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.select", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_result_set_action(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.result_set.action")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.lenses.result_set.action", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_lenses_default(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.lenses.default")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.lenses.default", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_offer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.offer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.disclosure.offer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_ceiling_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.ceiling.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.disclosure.ceiling.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_ceiling_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.ceiling.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.disclosure.ceiling.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_ceiling_clear(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.ceiling.clear")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.disclosure.ceiling.clear", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_reveals(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.reveals")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.disclosure.reveals", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_disclosure_reveals_answer(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.disclosure.reveals.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.disclosure.reveals.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn reveal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "reveal")?;
        let output = py
            .detach(|| self.inner.agent_verb("reveal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn reveal_wait(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "reveal.wait")?;
        let output = py
            .detach(|| self.inner.agent_verb("reveal.wait", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn reveal_describe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "reveal.describe")?;
        let output = py
            .detach(|| self.inner.agent_verb("reveal.describe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_use(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.use")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.use", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_secrets_materialize(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.secrets.materialize")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.secrets.materialize", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_secrets_renew(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.secrets.renew")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.secrets.renew", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_secrets_teardown(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.secrets.teardown")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.secrets.teardown", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_secrets_use(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.secrets.use")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.secrets.use", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shares_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shares.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shares.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shares_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shares.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shares.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_shares_view(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.shares.view")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.shares.view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn host_compact(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "host.compact")?;
        let output = py
            .detach(|| self.inner.agent_verb("host.compact", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn host_wake(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "host.wake")?;
        let output = py
            .detach(|| self.inner.agent_verb("host.wake", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn host_budget_hit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "host.budget.hit")?;
        let output = py
            .detach(|| self.inner.agent_verb("host.budget.hit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_hooks_replay(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hooks.replay")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hooks.replay", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_hooks_regen_due(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hooks.regen.due")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hooks.regen.due", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_hooks_regen_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hooks.regen.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hooks.regen.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_hooks_regen_adopt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hooks.regen.adopt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hooks.regen.adopt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_publish_approval(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.publish_approval")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.publish_approval", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_publish(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.publish")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.publish", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_repoint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.repoint")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.repoint", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_pointer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.pointer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.pointer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_unpublish(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.unpublish")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.unpublish", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_link_token(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.link_token")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.link_token", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_register(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.live_preview.register")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.register", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_read(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.live_preview.read")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.read", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_close(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.live_preview.close")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.close", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_invite(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.live_preview.invite")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.invite", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_revoke_invite(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.artifacts.live_preview.revoke_invite")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.revoke_invite", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_share(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.live_preview.share")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.share", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_live_preview_revoke_share(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.artifacts.live_preview.revoke_share")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.live_preview.revoke_share", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_view(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.view")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_units(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.units")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.units", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_anchors_pin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.anchors.pin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.anchors.pin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.threads.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_comment(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.comment")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.threads.comment", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.threads.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.threads.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_assign(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.assign")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.threads.assign", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_threads_state(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.threads.state")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.threads.state", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn mount(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "mount")?;
        let output = py
            .detach(|| self.inner.agent_verb("mount", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_readdir(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.readdir")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.readdir", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_read_file(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.read_file")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.read_file", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_read_link(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.read_link")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.read_link", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_ls(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.ls")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.ls", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_find(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.find")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.find", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_grep(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.grep")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.grep", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_cat(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.cat")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.cat", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_head(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.head")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.head", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn graph_fs_wc(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "graph_fs.wc")?;
        let output = py
            .detach(|| self.inner.agent_verb("graph_fs.wc", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_diff(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.code.diff")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.diff", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_blame(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.code.blame")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.blame", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_view(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.code.proposal_view")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.proposal_view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_symbols_declare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.symbols.declare")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.symbols.declare", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_symbols_renew(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.symbols.renew")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.symbols.renew", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_symbols_release(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.symbols.release")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.symbols.release", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_submit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.proposal_submit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.proposal_submit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_conflict_record(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.conflict_record")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.conflict_record", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_conflict_view(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.conflict_view")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.conflict_view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.proposal_resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.proposal_resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.proposal_review")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.proposal_review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_settle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.proposal_settle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.proposal_settle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_proposal_settlement(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.proposal_settlement")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.proposal_settlement", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_oplog(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.oplog")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.oplog", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn execute_code(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "execute_code")?;
        let output = py
            .detach(|| self.inner.agent_verb("execute_code", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_model_heal_count(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.model_heal_count")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.model_heal_count", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_waits_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.waits.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.waits.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_waits_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.waits.receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.waits.receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_results_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.results.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.results.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_results_recover(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.results.recover")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.results.recover", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_results_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.results.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.results.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_results_slice(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.results.slice")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.results.slice", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_repo_diff(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.code.repo_diff")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.repo_diff", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_import(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.import")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.import", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_repos_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.repos.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.repos.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_forks_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.forks.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.forks.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_ingress_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.ingress.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.ingress.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_register(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.register")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.origin.register", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_mirror_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.mirror.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.origin.mirror.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_mirror_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.mirror.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.origin.mirror.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_mirror_strategy(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.mirror.strategy")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.mirror.strategy", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_mirror_clear(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.mirror.clear")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.mirror.clear", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_mirror_push(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.mirror.push")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.mirror.push", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_request(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.request")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.request", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_review(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.review")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.review", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_approve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_execute(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.execute")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.execute", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publish_cancel(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publish.cancel")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publish.cancel", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_authority_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.authority.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.authority.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_authority_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.authority.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.authority.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_origin_publications(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.origin.publications")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.origin.publications", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_claim(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.claim")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.claim", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_renew(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.renew")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.renew", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_reclaim(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.reclaim")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.reclaim", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_takeover(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.takeover")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.takeover", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_publish(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.publish")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.publish", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_settle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.settle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.settle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checkout_teardown(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checkout.teardown")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checkout.teardown", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_views_materialize(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.views.materialize")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.views.materialize", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_views_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.views.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.views.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_views_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.views.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.views.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_views_action(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.views.action")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.views.action", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_views_build(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.views.build")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.views.build", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_cache_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.cache.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.cache.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_cache_reuse(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.cache.reuse")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.cache.reuse", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_snapshots_ingest(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.snapshots.ingest")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.snapshots.ingest", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_snapshots_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.snapshots.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.snapshots.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_snapshots_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.snapshots.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.snapshots.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_symbols_definitions(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.symbols.definitions")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.symbols.definitions", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_enqueue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.enqueue")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.enqueue", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_stage(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.stage")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.merge_queue.stage", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_observe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.observe")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.observe", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_requeue_survivors(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.code.merge_queue.requeue_survivors")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.requeue_survivors", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_land_reviewed(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.land_reviewed")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.land_reviewed", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_settle_slow(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.settle_slow")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.settle_slow", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_recover(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.recover")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.recover", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_init(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.init")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.merge_queue.init", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_check(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.check")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.merge_queue.check", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_diagnose(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.diagnose")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.diagnose", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_check_status(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.check_status")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.check_status", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_checks_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.checks.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.checks.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_code_merge_queue_export_green(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.code.merge_queue.export_green")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.code.merge_queue.export_green", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_export(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_dreaming_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.dreaming.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.dreaming.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_dreaming_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.dreaming.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.dreaming.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_grants_mint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.grants.mint")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.grants.mint", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_grants_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.grants.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.grants.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_git_push_mint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.git_push.mint")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.git_push.mint", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_git_push_revoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.git_push.revoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.git_push.revoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_anchor_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.anchor.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.anchor.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_snapshots_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.snapshots.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.snapshots.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_snapshots_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.snapshots.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.snapshots.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_symbols_definitions(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.symbols.definitions")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.repo.symbols.definitions", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_views_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.views.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.views.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_views_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.views.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.views.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_merge_queue_observe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.merge_queue.observe")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.repo.merge_queue.observe", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_snapshots_ingest(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.snapshots.ingest")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.snapshots.ingest", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_work_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.work.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.work.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_symbols_declare(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.symbols.declare")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.symbols.declare", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_symbols_renew(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.symbols.renew")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.symbols.renew", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_symbols_release(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.symbols.release")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.symbols.release", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_proposal_submit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.proposal_submit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.proposal_submit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_merge_queue_enqueue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.merge_queue.enqueue")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.repo.merge_queue.enqueue", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_checkout_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.checkout.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.checkout.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_repo_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.repo.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.repo.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_base(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.base")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.base", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_standing_blocks_configure(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.standing_blocks.configure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.standing_blocks.configure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_standing_blocks_reconfigure(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.standing_blocks.reconfigure")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.standing_blocks.reconfigure", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_standing_blocks_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.standing_blocks.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.standing_blocks.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_standing_blocks_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.standing_blocks.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.standing_blocks.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_save(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.save")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workflows.save", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workflows.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workflows.update", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_dispatch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.dispatch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workflows.dispatch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_dispatch_bound(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.dispatch_bound")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.workflows.dispatch_bound", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workflows_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workflows.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workflows.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_task_types_pin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.task_types.pin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.task_types.pin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_task_types_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.task_types.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.task_types.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_spawn_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.spawn.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.spawn.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_spawn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.agents.spawn")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.spawn", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tasks_cancel_force(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tasks.cancel_force")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tasks.cancel_force", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_branches_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.branches.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.branches.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_pause(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.pause")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.pause", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_resume(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.resume")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.resume", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consults_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consults.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consults.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workspace_establish(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workspace.establish")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workspace.establish", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workspace_members_onboard(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workspace.members.onboard")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.workspace.members.onboard", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workspace_roster(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workspace.roster")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.workspace.roster", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_agents_export_pack(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.agents.export_pack")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.agents.export_pack", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_born_from(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.born_from")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.born_from", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_proposals(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.proposals")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.proposals", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_waits(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.waits")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.waits", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_release_wait(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.release_wait")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.release_wait", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_review_slides(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.review_slides")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.review_slides", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_critic_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.critic.review")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.critic.review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_propose_outline(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.propose_outline")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.propose_outline", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_outline(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.outline")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.outline", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_keep_outline(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.keep_outline")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.keep_outline", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_decline_outline(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.decline_outline")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.decline_outline", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_design_deck(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.design_deck")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.design_deck", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_create_deck(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.create_deck")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.create_deck", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_inspect_deck(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.inspect_deck")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.inspect_deck", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_propose_deck(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.propose_deck")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.propose_deck", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_propose_output(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.propose_output")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.propose_output", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_keep(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.keep")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.keep", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_discard(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.discard")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.discard", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_undo(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.undo")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.undo", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn can(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "can")?;
        let output = py
            .detach(|| self.inner.agent_verb("can", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn peek(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "peek")?;
        let output = py
            .detach(|| self.inner.agent_verb("peek", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn wait(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "wait")?;
        let output = py
            .detach(|| self.inner.agent_verb("wait", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_outcomes(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.outcomes")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.outcomes", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_messages(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.messages")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.messages", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_participants(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.participants")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.participants", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_render(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.render")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.render", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_find(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.find")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.find", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_trunk(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.trunk")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.trunk", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_reply_strips(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.reply_strips")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.reply_strips", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_claim(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.claim")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.claim", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_speak(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.speak")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.speak", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_audience_add(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_audience.add")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_audience.add", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_audience_open_full_history(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.rooms.thread_audience.open_full_history")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_audience.open_full_history", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_audience_remove(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_audience.remove")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_audience.remove", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_private_threads(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.private_threads")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.private_threads", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_delete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_delete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.thread_delete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_join_request(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_join.request")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_join.request", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_join_requests(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_join.requests")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_join.requests", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_join_approve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_join.approve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.rooms.thread_join.approve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_thread_join_deny(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.thread_join.deny")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.thread_join.deny", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_proposals(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.proposals")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.proposals", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_dismiss_card(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.dismiss_card")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.dismiss_card", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_confirm(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.confirm")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.confirm", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_roster_write(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.roster.write")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.roster.write", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_goal_intake(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.goal.intake")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.goal.intake", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_join(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.join")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.join", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_invite(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.invite")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.invite", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_consent(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.consent")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.consent", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_offer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.offer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.offer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_offer_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.offer.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.offer.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_offer_vote(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.offer.vote")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.offer.vote", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_offer_reopen(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.offer.reopen")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.offer.reopen", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_offers(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.offers")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.offers", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_goal_revisions(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.goal.revisions")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.projects.goal.revisions", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_goal_dismiss(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.goal.dismiss")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.projects.goal.dismiss", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_projects_route_tradeoff(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.projects.route_tradeoff")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.projects.route_tradeoff", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_conversations_turn_continue(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.conversations.turn.continue")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.conversations.turn.continue", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_conversations_turn_retry(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.conversations.turn.retry")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.conversations.turn.retry", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_messages_react(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.messages.react")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.messages.react", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_host(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.host")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.host", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_host_pin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.host.pin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.host.pin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_host_hand(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.host.hand")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.host.hand", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_upkeep_pending(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.upkeep.pending")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.upkeep.pending", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_upkeep_voice(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.upkeep.voice")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.upkeep.voice", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_rooms_sharing(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.rooms.sharing")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.rooms.sharing", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_companions_sharing_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.companions.sharing.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.companions.sharing.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_companions_sharing_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.companions.sharing.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.companions.sharing.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workspace_work_companion_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workspace.work_companion.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.workspace.work_companion.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_workspace_work_companion_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.workspace.work_companion.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.workspace.work_companion.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn self_skills_save(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.skills.save")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.skills.save", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_skills_fork(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.skills.fork")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.skills.fork", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_skills_callables(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.skills.callables")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.skills.callables", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_pack_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.pack_receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.pack_receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_outcomes_project(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.outcomes.project")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.outcomes.project", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_outcomes_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.outcomes.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.skills.outcomes.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_manifest_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.manifest.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.manifest.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_manifest_replace(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.manifest.replace")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.models.manifest.replace", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_oneironer_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.oneironer.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.oneironer.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_routes_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.routes.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.routes.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_routes_replace(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.routes.replace")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.routes.replace", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_roles_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.roles.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.roles.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_roles_invoke(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.roles.invoke")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.roles.invoke", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_settle(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.attribution.settle")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.settle", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.attribution.read")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.read", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_evidence_record(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.skills.attribution.evidence.record")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.evidence.record", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_project(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.attribution.project")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.project", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_judgments(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.attribution.judgments")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.judgments", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_proposals(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.skills.attribution.proposals")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.proposals", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_skills_attribution_positive_retire(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.skills.attribution.positive.retire")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.skills.attribution.positive.retire", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_steps_submit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.steps.submit")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.steps.submit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_steps_receipt(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.steps.receipt")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.steps.receipt", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_subscribe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.subscribe")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.subscribe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_events(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.events")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.events", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_detach(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.detach")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.detach", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_abort(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.abort")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.abort", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_streams_terminal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.streams.terminal")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.streams.terminal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_reply(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.reply")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.reply", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_receipts_context(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.receipts.context")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.receipts.context", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_asr_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.asr.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.asr.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_asr_hypothesis(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.asr.hypothesis")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.asr.hypothesis", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_asr_finalize(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.asr.finalize")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.asr.finalize", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_asr_close(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.asr.close")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.asr.close", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_start(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.start")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.start", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_audio(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.audio")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.audio", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_events(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.events")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.events", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_ack(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.ack")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.ack", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_usage(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.usage")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.usage", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_tool(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.tool")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.tool", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_end(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.end")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.end", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_voice_close(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.voice.close")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.voice.close", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_anonymous_chat(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.anonymous_chat")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.anonymous_chat", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_catalog_refresh(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.catalog.refresh")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.catalog.refresh", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_catalog_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.catalog.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.catalog.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_catalog_diff(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.catalog.diff")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.catalog.diff", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_trials_nominate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.trials.nominate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.trials.nominate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_trials_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.trials.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.trials.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_trials_approve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.trials.approve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.trials.approve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_trials_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.trials.run")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.trials.run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_trials_complete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.trials.complete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.trials.complete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_bindings_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.bindings.propose")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.models.bindings.propose", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_bindings_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.bindings.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.bindings.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_bindings_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.bindings.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.bindings.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_bindings_accept(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.bindings.accept")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.bindings.accept", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_models_bindings_deny(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.models.bindings.deny")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.models.bindings.deny", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_options(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.options")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.options", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_image(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.image")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.image", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_speech(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.speech")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.speech", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_voices_packs_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.voices.packs.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.voices.packs.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_voices_render_consent(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.voices.render_consent")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.voices.render_consent", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_voices_targets_provision(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.voices.targets.provision")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.voices.targets.provision", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_voices_targets_evict(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.voices.targets.evict")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.voices.targets.evict", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_voices_inspect(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.voices.inspect")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.voices.inspect", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_transcribe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.transcribe")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.transcribe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_embed(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.embed")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.embed", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_video(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.video")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.video", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_video_poll(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.video.poll")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.video.poll", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_video_cancel(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.video.cancel")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.video.cancel", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn ai_verdict(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "ai.verdict")?;
        let output = py
            .detach(|| self.inner.agent_verb("ai.verdict", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_graph_ask(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.graph.ask")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.graph.ask", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_graph_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.graph.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.graph.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_pause(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.pause")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.pause", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_backfill(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.backfill")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.backfill", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_answers(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.answers")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.answers", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_refresh(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.refresh")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.refresh", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_outcomes(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.outcomes")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.outcomes", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_outcomes_project(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.outcomes.project")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.questions.outcomes.project", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_questions_schedule(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.questions.schedule")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.questions.schedule", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_decisions_bands_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.decisions.bands.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.decisions.bands.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_decisions_bands_learn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.decisions.bands.learn")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.decisions.bands.learn", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_decisions_bands_enforce(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.decisions.bands.enforce")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.decisions.bands.enforce", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_decisions_asks_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.decisions.asks.answer")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.decisions.asks.answer", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_decisions_asks_climb(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.decisions.asks.climb")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.decisions.asks.climb", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_decisions_asks(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.decisions.asks")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.decisions.asks", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_call(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.call")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.call", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_schema(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.schema")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.schema", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_call_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.call_status")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.call_status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_commit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.commit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.commit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_remember(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.remember")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.remember", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_retract(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.retract")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.retract", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_forget(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.forget")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.forget", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_availability(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.availability")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.booking.availability", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_book(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.book")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.booking.book", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_reschedule(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.reschedule")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.booking.reschedule", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_cancel(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.cancel")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.booking.cancel", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_constraint_turn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.constraint_turn")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.booking.constraint_turn", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_booking_page_token(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.booking.page_token")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.booking.page_token", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_invite(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.invite")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.invite", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_ics_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.ics.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.ics.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_ics_poll(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.ics.poll")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.ics.poll", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_ics_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.ics.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.ics.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_passports_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.passports.read")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.passports.read", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_passports_history(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.passports.history")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.passports.history", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_connector_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.connector.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.connector.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_connector_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.connector.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.connector.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_connector_pull(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.connector.pull")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.connector.pull", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_connector_write(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.connector.write")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.connector.write", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_connector_kill(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.connector.kill")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.connector.kill", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_imip_configure(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.imip.configure")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.imip.configure", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn calendar_imip_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "calendar.imip.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("calendar.imip.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_ics_import(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.ics.import")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.ics.import", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_occurrences(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.occurrences")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.occurrences", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_instances_move(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.instances.move")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.instances.move", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_search(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.search")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.search", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_freebusy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.freebusy")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.freebusy", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_prep(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.prep")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.prep", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_event_outcome(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.event_outcome")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.event_outcome", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_check_in_due(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.check_in.due")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.calendar.check_in.due", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_check_in_answer(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.check_in.answer")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.check_in.answer", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_outcome_policy_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.outcome_policy.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.outcome_policy.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_outcome_policy_set(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.outcome_policy.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.outcome_policy.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_calendar_transcript_ingest(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.calendar.transcript.ingest")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.calendar.transcript.ingest", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.list", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_demote(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.demote")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.demote", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_list_filtered(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.list_filtered")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.list_filtered", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_read_filtered(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.read_filtered")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.read_filtered", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_history(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.history")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.history", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_delete(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.delete")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.delete", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_writes_critical_confirm_pending(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.writes.critical_confirm.pending")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.writes.critical_confirm.pending", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_writes_critical_confirm_clear(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.writes.critical_confirm.clear")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.writes.critical_confirm.clear", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_writes_critical_confirm_decline(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.writes.critical_confirm.decline")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.writes.critical_confirm.decline", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_writes_critical_confirm_receipt(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.writes.critical_confirm.receipt")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.writes.critical_confirm.receipt", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_writes_pending(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.writes.pending")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.writes.pending", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_hydrate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hydrate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hydrate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_refs_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.refs.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.refs.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_refs_links(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.refs.links")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.refs.links", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_search_vector_config(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.search.vector.config")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.search.vector.config", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_vectors_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.vectors.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.vectors.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_search_hybrid(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.search.hybrid")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.search.hybrid", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_search_temporal(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.search.temporal")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.search.temporal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_search_bm25(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.search.bm25")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.search.bm25", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_neighbors(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.neighbors")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.neighbors", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_structural_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.structural.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.structural.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_habits_checkin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.habits.checkin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.habits.checkin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_productivity_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.productivity.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.productivity.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_productivity_tree(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.productivity.tree")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.productivity.tree", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_admit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.admit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.admit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_links_issue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.links.issue")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.links.issue", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_send_for_signature(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.send_for_signature")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.esign.send_for_signature", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_notices_dispatch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.notices.dispatch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.notices.dispatch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_remind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.remind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.remind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_void(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.void")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.void", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_signing_act(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.signing.act")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.signing.act", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_signing_pdf(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.signing.pdf")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.signing.pdf", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_signing_image(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.signing.image")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.signing.image", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_signing_signature(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.signing.signature")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.esign.signing.signature", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_esign_seal_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.esign.seal.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.esign.seal.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_conversations_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.conversations.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.conversations.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_conversations_turns_create(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.conversations.turns.create")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.conversations.turns.create", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_conversations_records_append(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.conversations.records.append")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.conversations.records.append", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_batch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.batch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.batch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.put", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_import(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.import")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.import", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_head(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.head")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.head", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_read(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_commits(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.commits")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.commits", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_edit(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_fork_open(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.fork.open")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.fork.open", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_fork_edit(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.fork.edit")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.fork.edit", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_fork_diff(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.fork.diff")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.fork.diff", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_fork_merge(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.fork.merge")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.fork.merge", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_fork_discard(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.fork.discard")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.fork.discard", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_proposal_read(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.proposal.read")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.proposal.read", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_proposal_settle(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(request_json, "vault.artifacts.body.proposal.settle")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.proposal.settle", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_export(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_preview(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.preview")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.body.preview", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_review(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.review")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.review", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_merge(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.merge")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.merge", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_export(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.export")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.export", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_gate(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.gate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.gate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_oracle(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.oracle")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.oracle", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_body_deck_preview(
        &self,
        py: Python<'_>,
        request_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.artifacts.body.deck.preview")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.artifacts.body.deck.preview", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_append(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.append")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.append", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_artifacts_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_enqueue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.enqueue")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.enqueue", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_wake_status(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.wake.status")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consolidation.wake.status", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_step(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.step")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.step", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_checkpoint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.checkpoint")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.checkpoint", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_turn_programs_admission(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.turn_programs.admission")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.turn_programs.admission", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_program(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.program")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.program", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_program_step(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.program_step")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.program_step", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_program_checkpoint(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.program_checkpoint")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.runs.program_checkpoint", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_program_hold_release(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.program_hold.release")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.runs.program_hold.release", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_home_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.home.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.home.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_home_pick(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.home.pick")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consolidation.home.pick", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_lineage(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.lineage")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.lineage", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_promote(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.promote")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.promote", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_pin(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.pin")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.pin", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_frontier(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.frontier")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.frontier", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_accounting(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.accounting")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.consolidation.accounting", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_consolidation_evidence(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.consolidation.evidence")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.consolidation.evidence", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_evidence(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.evidence")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.evidence", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_evidence_replay(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.evidence.replay")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.evidence.replay", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_cadence(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.cadence")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.cadence", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_settlements(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.settlements")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.settlements", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_settlements_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.settlements.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.settlements.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_queue(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.queue")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.queue", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_retained(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.retained")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.retained", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_receipts(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.receipts")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.receipts", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_policy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.policy")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.policy", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_policy_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.policy.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.policy.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_recipe_policy(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.recipe_policy")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.recipe_policy", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_recipe_policy_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.recipe_policy.set")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.sieve.recipe_policy.set", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_lease(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.lease")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.lease", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_sieve_lease_refill(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.sieve.lease.refill")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.sieve.lease.refill", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_free_time_policy_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.free_time.policy.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.free_time.policy.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_free_time_policy_set(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.free_time.policy.set")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.free_time.policy.set", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_free_time_cycles(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.free_time.cycles")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.free_time.cycles", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_free_time_cycle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.free_time.cycle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.free_time.cycle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_vet(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.vet")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.vet", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_vetting(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.vetting")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.vetting", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_memory_signal_extraction(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.memory.signal_extraction")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.memory.signal_extraction", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_memory_signal_extraction_result(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.memory.signal_extraction.result")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.memory.signal_extraction.result", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_seed(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.seed")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.seed", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_provision(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.provision")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.provision", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.bind")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.bind", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_fulfill(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.fulfill")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.fulfill", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_rotate(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.rotate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.rotate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_release(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.release")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.release", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_route_inbound(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.channel_identities.route_inbound")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.route_inbound", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.channel_identities.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_selection_rules(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.channel_identities.selection.rules")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.selection.rules", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_selection_update(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.channel_identities.selection.update")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.selection.update", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_select(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.channel_identities.select")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.select", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_passports_get(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.channel_identities.passports.get")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.passports.get", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_channel_identities_passports_list(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value =
            decode(input_json, "vault.channel_identities.passports.list")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.channel_identities.passports.list", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_delivery_window_policy_put(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.delivery_window.policy.put")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.delivery_window.policy.put", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_delivery_window_policy_list(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.delivery_window.policy.list")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.delivery_window.policy.list", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_delivery_window_policy_retract(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.delivery_window.policy.retract")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.delivery_window.policy.retract", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_delivery_window_evaluate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.delivery_window.evaluate")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.delivery_window.evaluate", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn connector_outbound_schedule(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "connector.outbound.schedule")?;
        let output = py
            .detach(|| self.inner.agent_verb("connector.outbound.schedule", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_status(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.status")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.status", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_keep(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.keep")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.keep", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_patch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.patch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.patch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_regenerate(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.regenerate")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.summaries.regenerate", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_proposals_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.proposals.read")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.summaries.proposals.read", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_proposals_merge(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.proposals.merge")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.summaries.proposals.merge", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_proposals_switch(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.proposals.switch")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.summaries.proposals.switch", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_summaries_proposals_reject(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.summaries.proposals.reject")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.summaries.proposals.reject", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_bless_brief_kind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.bless_brief_kind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.bless_brief_kind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_author_brief(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.author_brief")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.author_brief", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_follow_citation(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.follow_citation")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.follow_citation", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.create", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_author_take(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.author_take")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.author_take", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_from_entity(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.from_entity")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.from_entity", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_history(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.history")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.history", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_fork(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.fork")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.fork", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_forks_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.forks.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.forks.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_proposals_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.proposals.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.proposals.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_proposals_read(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.proposals.read")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.proposals.read", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_proposals_merge(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.proposals.merge")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.proposals.merge", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_proposals_switch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.proposals.switch")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.proposals.switch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_proposals_reject(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.proposals.reject")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.proposals.reject", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_version_tree(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.version_tree")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.version_tree", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_history_purge(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.history_purge")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.history_purge", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_history_purge_execute(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.history_purge_execute")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.notes.history_purge_execute", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_history_purge_receipts(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.history_purge_receipts")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.notes.history_purge_receipts", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_editor_bind(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.editor.bind")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.editor.bind", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_editor_close(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.editor.close")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.editor.close", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.edit", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_seal(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.notes.seal")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.seal", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_lifecycle(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.notes.lifecycle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.lifecycle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_set_overrides(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.notes.set_overrides")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.set_overrides", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_notes_defaults(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.notes.defaults")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.defaults", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tasks_linear_mapping(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tasks.linear.mapping")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.tasks.linear.mapping", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tasks_linear_mapping_edit(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tasks.linear.mapping.edit")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.tasks.linear.mapping.edit", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_tasks_linear_provenance(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.tasks.linear.provenance")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.tasks.linear.provenance", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn self_run_attach(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.run.attach")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.run.attach", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_folds_describe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.folds.describe")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.folds.describe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_history(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.history")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.history", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_review(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.review")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.review", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_settle(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.settle")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.settle", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_runs_settlement(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.runs.settlement")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.runs.settlement", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_revert_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.revert_run")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.revert_run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_merge(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.merge")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.merge", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_split(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.split")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.split", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_facet(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.facet")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.facet", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_assert_distinct(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.assert_distinct")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.identity.assert_distinct", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_undo(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.undo")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.undo", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_resolve(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.resolve")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.resolve", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_events_get(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.events.get")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.identity.events.get", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_proposals_resolve(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.proposals.resolve")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.identity.proposals.resolve", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_identity_proposals_for_pair(
        &self,
        py: Python<'_>,
        input_json: &str,
    ) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.identity.proposals.for_pair")?;
        let output = py
            .detach(|| {
                self.inner
                    .agent_verb("vault.identity.proposals.for_pair", input)
            })
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_open(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.open")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.open", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_observe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.observe")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.observe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_find(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.find")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.find", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_click(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.click")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.click", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_click_at(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.click_at")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.click_at", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_type(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.type")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.type", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_select(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.select")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.select", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_wait_for(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.wait_for")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.wait_for", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_expect(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.expect")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.expect", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_screenshot(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.screenshot")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.screenshot", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_view(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.view")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.view", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_crop(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.crop")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.crop", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_zoom(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.zoom")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.zoom", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_batch(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.batch")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.batch", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_library_find(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.library.find")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.library.find", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_library_propose(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.library.propose")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.library.propose", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_library_retire(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.library.retire")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.library.retire", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_library_retired(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.library.retired")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.library.retired", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_library_run(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.library.run")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.library.run", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_handover(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.handover")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.handover", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_browser_switch_engine(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.browser.switch_engine")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.browser.switch_engine", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn vault_claims_supersede(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.supersede")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.supersede", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_fold(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.fold")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.fold", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_compact(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.compact")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.compact", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_unfold(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.unfold")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.unfold", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_folds(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.folds")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.folds", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn tasks_refuse(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.refuse")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.refuse", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_report_blocked(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.report_blocked")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.report_blocked", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_agents_spawn(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.agents.spawn")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.agents.spawn", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_leader_split(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.leader.split")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.leader.split", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_skills_call(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.skills.call")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.skills.call", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_refresh(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.refresh")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.refresh", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_subscribe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.subscribe")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.subscribe", input))
            .map_err(raise)?;
        encode(&output)
    }
    fn self_focus_unsubscribe(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "self.focus.unsubscribe")?;
        let output = py
            .detach(|| self.inner.agent_verb("self.focus.unsubscribe", input))
            .map_err(raise)?;
        encode(&output)
    }

    // END GENERATED AGENT VERBS
}

/// The private extension module: `oneiron._native`.
///
/// PyO3 0.28 flipped the `gil_used` default, so the module now declares
/// free-threaded support instead of forcing the GIL back on at import. That
/// default is kept rather than opted out of, because the preconditions already
/// hold: `NativeClient` is `Sync`, exposes only `&self` methods over a shared
/// `OneironClient`, and runs every backend call under `Python::detach` — two
/// Python threads can already be inside the engine at once on a GIL build. The
/// declaration is inert there and only takes effect on a free-threaded build.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeClient>()?;
    // The engine-backed served client, only in an `engine` build (OF-237).
    #[cfg(feature = "engine")]
    module.add_class::<embedded_engine::NativeEngine>()?;
    Ok(())
}
