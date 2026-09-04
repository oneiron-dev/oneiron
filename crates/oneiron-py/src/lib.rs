//! `oneiron._native` — the private PyO3 extension behind the `oneiron` PyPI
//! package (ONE-1441 WIRE-P1).
//!
//! # Why the boundary is JSON
//!
//! Every DTO crosses as a JSON string. That is not a shortcut: the engine's
//! facade DTOs already derive `serde` with snake_case field names, which IS
//! the Python naming convention, so a JSON boundary gives the Python package
//! the exact §HEAD-CONTRACT field spelling with NO translation layer to get
//! wrong. The alternative — hand-written `#[pyclass]` mirrors of every DTO —
//! would be a second domain model maintained by hand, which is the thing the
//! shared backend exists to prevent.
//!
//! # What is public
//!
//! Nothing here is the public package. `oneiron/__init__.py` wraps
//! `NativeClient` and exports `Oneiron` and `OneironError` only; the export
//! census asserts `not hasattr(oneiron, "NativeClient")`.

use oneiron::memory::{
    ClaimInput, MemoryError, WitnessAuthor, WitnessMessage, WitnessTurn,
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
    let payload =
        serde_json::to_string(&error).unwrap_or_else(|_| format!("{{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":{:?},\"suggestions\":[]}}", error.message));
    PyRuntimeError::new_err(payload)
}

/// Refuses a body that is not the documented shape, in the same vocabulary.
fn decode<'de, T: Deserialize<'de>>(json: &'de str, what: &str) -> PyResult<T> {
    serde_json::from_str(json).map_err(|error| {
        raise(MemoryError {
            code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(),
            message: format!("{what} is not the documented shape: {error}"),
            suggestions: vec![format!("Check the {what} keys against the oneiron type stubs.")],
            successor_short_id: None,
            gate_denial: None,
        })
    })
}

/// Serializes a success DTO back to the Python side.
fn encode<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|error| {
        raise(MemoryError {
            code: oneiron::memory::MEMORY_CODE_INTERNAL.to_owned(),
            message: format!("could not serialize the response: {error}"),
            suggestions: vec!["This is an Oneiron SDK bug; please report it.".to_owned()],
            successor_short_id: None,
            gate_denial: None,
        })
    })
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
    fn open(path: Option<std::path::PathBuf>, dimensions: Option<usize>) -> PyResult<Self> {
        let options = oneiron_remote::OpenOptions { dimensions };
        let inner =
            oneiron_remote::OneironClient::open(path.as_deref(), &options).map_err(raise)?;
        Ok(Self { inner })
    }

    /// Binds a remote `oneiron-server`; the slip crosses verbatim.
    #[staticmethod]
    fn connect(url: &str, key: &str) -> PyResult<Self> {
        let inner = oneiron_remote::OneironClient::connect(url, key).map_err(raise)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle bound to another actor; refuses when connected.
    fn as_actor(&self, actor_key: &str) -> PyResult<Self> {
        let inner = self.inner.as_actor(actor_key).map_err(raise)?;
        Ok(Self { inner })
    }

    /// Witnesses one conversational turn.
    fn witness(&self, turn_json: &str) -> PyResult<String> {
        let input: WitnessTurnInput = decode(turn_json, "the witness turn")?;
        let turn = input.into_engine().map_err(raise)?;
        let receipt = self.inner.witness(&turn).map_err(raise)?;
        encode(&receipt)
    }

    /// Upserts one claim through the gated claim-candidate path.
    fn claim_upsert(&self, claim_json: &str) -> PyResult<String> {
        let claim: ClaimInput = decode(claim_json, "the claim")?;
        let receipt = self.inner.claim_upsert(&claim).map_err(raise)?;
        encode(&receipt)
    }

    /// Effort-dialed retrieval into a memory pack.
    #[pyo3(signature = (query, effort=None, scope_json=None, limit=None, format=None))]
    fn recall(
        &self,
        query: &str,
        effort: Option<&str>,
        scope_json: Option<&str>,
        limit: Option<usize>,
        format: Option<&str>,
    ) -> PyResult<String> {
        let effort = oneiron_remote::parse_effort(effort.unwrap_or("standard")).map_err(raise)?;
        let scope = match scope_json {
            Some(json) => decode(json, "the recall scope")?,
            None => oneiron::memory::RecallScope::default(),
        };
        let limit = limit.unwrap_or(oneiron_remote::DEFAULT_RECALL_LIMIT);
        let pack = self
            .inner
            .recall(query, effort, &scope, limit, format)
            .map_err(raise)?;
        encode(&pack)
    }

    /// Gate decision receipts, newest first.
    #[pyo3(signature = (limit=None))]
    fn receipts(&self, limit: Option<usize>) -> PyResult<String> {
        let limit = limit.unwrap_or(oneiron_remote::DEFAULT_RECEIPTS_LIMIT);
        let receipts = self.inner.receipts(limit).map_err(raise)?;
        encode(&receipts)
    }
}

/// The private extension module: `oneiron._native`.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeClient>()?;
    Ok(())
}
