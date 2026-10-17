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
}

/// One turn to witness, with an OPTIONAL timestamp (I14).
#[derive(Deserialize)]
struct WitnessTurnInput {
    conversation_ref: String,
    turn_ref: Option<String>,
    messages: Vec<WitnessMessageInput>,
    occurred_at: Option<f64>,
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
            })
            .collect();
        Ok(WitnessTurn {
            conversation_ref: self.conversation_ref,
            turn_ref: self.turn_ref,
            quote: None,
            messages,
            occurred_at,
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
    #[staticmethod]
    #[pyo3(signature = (path=None, dimensions=None))]
    fn open(
        py: Python<'_>,
        path: Option<std::path::PathBuf>,
        dimensions: Option<usize>,
    ) -> PyResult<Self> {
        // Crash output never carries world text: the engine's hook goes in before
        // any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let options = oneiron_remote::OpenOptions { dimensions };
        let inner = py
            .detach(|| oneiron_remote::OneironClient::open(path.as_deref(), &options))
            .map_err(raise)?;
        Ok(Self { inner })
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

    /// Redeems a pairing link once; returns `(url, credential)`.
    #[staticmethod]
    fn pair(py: Python<'_>, link: String) -> PyResult<(String, String)> {
        py.detach(|| oneiron_remote::OneironClient::pair(&link))
            .map_err(raise)
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

    /// The lasting call receipt the last verb's reply stated, as
    /// `call:<32hex>`, whether it answered or refused. `None` for an embedded
    /// handle, before any call, after a call that reached no server, and for
    /// an anonymous off-record call.
    fn last_receipt_ref(&self) -> Option<String> {
        self.inner.last_receipt_ref()
    }

    // BEGIN GENERATED AGENT VERBS
    fn report(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "report")?;
        let output = py
            .detach(|| self.inner.agent_verb("report", input))
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
    fn tasks_update(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "tasks.update")?;
        let output = py
            .detach(|| self.inner.agent_verb("tasks.update", input))
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
    fn vault_claims_upsert(&self, py: Python<'_>, claim_json: &str) -> PyResult<String> {
        let claim_json: ClaimInput = decode(claim_json, "claim")?;
        let output = py
            .detach(|| self.inner.vault_claims_upsert(&claim_json))
            .map_err(raise)?;
        encode(&output)
    }
    #[pyo3(signature = (query, effort=None, scope_json=None, limit=None, format=None, as_of=None, deadline_ms=None, media_json=None))]
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
                )
            })
            .map_err(raise)?;
        encode_recall(&output)
    }
    fn vault_export(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.export")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.export", input))
            .map_err(raise)?;
        encode(&output)
    }
    #[pyo3(signature = (limit=None))]
    fn vault_receipts(&self, py: Python<'_>, limit: Option<usize>) -> PyResult<String> {
        let limit = limit.unwrap_or(100);
        let output = py
            .detach(|| self.inner.vault_receipts(limit))
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
    fn vault_packs_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.packs.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.packs.put", input))
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
    fn vault_members_add(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.members.add")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.members.add", input))
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
    fn vault_hooks_replay(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.hooks.replay")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.hooks.replay", input))
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
    fn vault_code_repo_diff(&self, py: Python<'_>, request_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(request_json, "vault.code.repo_diff")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.code.repo_diff", input))
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
    fn vault_claims_list(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.list")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.list", input))
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
    fn vault_artifacts_put(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.artifacts.put")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.artifacts.put", input))
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
    fn vault_claims_seed(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.claims.seed")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.claims.seed", input))
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
    fn vault_notes_create(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.create")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.create", input))
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
    fn vault_notes_edit(&self, py: Python<'_>, input_json: &str) -> PyResult<String> {
        let input: serde_json::Value = decode(input_json, "vault.notes.edit")?;
        let output = py
            .detach(|| self.inner.agent_verb("vault.notes.edit", input))
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
    Ok(())
}
