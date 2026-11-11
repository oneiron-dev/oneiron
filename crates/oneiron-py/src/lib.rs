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

use oneiron::authority::CustodyChange;
use oneiron::memory::{
    ClaimInput, MemoryError, MemoryPack, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::task_verb::sdk::{SecretCustodyViewReply, seal_custody_submit};
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
    /// The records this reply names as cited or created (OF-063), the
    /// engine's own shape, judged under the writer's own read; omitted ⇒ it
    /// asserts nothing.
    #[serde(default)]
    assertions: WitnessAssertions,
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
                parts: None,
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
            assertions: self.assertions,
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
            resets_at: Vec::new(),
            reason_codes: Vec::new(),
            legal_hold: None,
            room_join_hold: None,
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
        resets_at: Vec::new(),
        reason_codes: Vec::new(),
        legal_hold: None,
        room_join_hold: None,
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
    /// What keeps this handle's engine serving while the handle lives: the
    /// in-process engine a local attach came from (FIX 4895), handed on to
    /// every handle rebound from it; `None` on every other handle.
    keep: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
}

impl NativeClient {
    /// A handle rebound from this one, keeping what this one keeps.
    fn rebound(&self, inner: oneiron_remote::OneironClient) -> Self {
        Self {
            inner,
            keep: self.keep.clone(),
        }
    }
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
            hold_checkpoint_root_signer: false,
        };
        let inner = py
            .detach(|| oneiron_remote::OneironClient::open(path.as_deref(), &options))
            .map_err(raise)?;
        Ok(Self { inner, keep: None })
    }

    /// `open`, then this install's own machine profile from the vault's host
    /// root secret, its exact bytes borrowed for this call (FIX 5342).
    /// `device_class` is `open`'s. `hold_checkpoint_root_signer` holds this
    /// install's host root as the vault's checkpoint signer for the handle's
    /// life (FIX 5343); omitted is `false`.
    #[staticmethod]
    #[pyo3(signature = (path, host_root_secret, dimensions=None, device_class=None, hold_checkpoint_root_signer=None))]
    fn open_with_host_root(
        py: Python<'_>,
        path: Option<std::path::PathBuf>,
        host_root_secret: &[u8],
        dimensions: Option<usize>,
        device_class: Option<String>,
        hold_checkpoint_root_signer: Option<bool>,
    ) -> PyResult<Self> {
        let device_class = host_device_class(device_class.as_deref())?;
        let inner = host_root::open(
            py,
            path,
            host_root_secret,
            dimensions,
            device_class,
            hold_checkpoint_root_signer.unwrap_or(false),
        )?;
        Ok(Self { inner, keep: None })
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
        Ok(Self { inner, keep: None })
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
        Ok(self.rebound(inner))
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    fn in_room_turn(&self, py: Python<'_>, room_ref: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.in_room_turn(&room_ref))
            .map_err(raise)?;
        Ok(self.rebound(inner))
    }

    /// Returns a NEW handle whose every verb runs inside the off-record
    /// session `session_ref` names, bound to this handle's principal: the
    /// app host's actor when embedded (OF-063). It grants nothing.
    fn in_off_record_session(&self, py: Python<'_>, session_ref: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.in_off_record_session(&session_ref))
            .map_err(raise)?;
        Ok(self.rebound(inner))
    }

    /// Returns a NEW handle whose every read runs under the credential a
    /// delegated reader presented (FIX 647): the paired credential `pair`
    /// returned, verified once against this vault as the server's door
    /// verifies a served request's. Reads refuse when the slip's holder is
    /// not this handle's actor; rebindings keep the same proof, so every
    /// read still checks it against the bound actor. A handle without one
    /// reads as before. Refuses when connected: a connected handle reads
    /// under the credential it connected with.
    fn with_read_credential(&self, py: Python<'_>, credential: String) -> PyResult<Self> {
        let inner = py
            .detach(|| self.inner.with_read_credential(&credential))
            .map_err(raise)?;
        Ok(self.rebound(inner))
    }

    /// The lasting call receipt the last verb's reply stated, as
    /// `call:<32hex>`, whether it answered or refused. `None` for an embedded
    /// handle, before any call, after a call that reached no server, and for
    /// an anonymous off-record call.
    fn last_receipt_ref(&self) -> Option<String> {
        self.inner.last_receipt_ref()
    }

    /// The content-free hook notice beside the last facade reply.
    fn last_hook_notice(&self) -> Option<String> {
        self.inner.last_hook_notice()
    }

    /// The engine `[limits]` rows this client's own vault crossed, as the
    /// host kept them: one entry per row that asked, as JSON. `None` on a
    /// remote, attached, or rebound view; an empty list where no row crossed
    /// yet. The PID gate error propagates.
    fn native_limit_questions(&self) -> PyResult<Option<String>> {
        self.inner
            .native_limit_questions()
            .map_err(raise)?
            .map(|rows| {
                let values: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|row| {
                        serde_json::json!({"row": row.row, "bound": row.bound, "measured": row.measured})
                    })
                    .collect();
                encode(&values)
            })
            .transpose()
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
    /// `{"$state"}` (beside the card's refinement for a patch-profile
    /// caller) or `{outcome, readReceipt}`. The route, the credential and
    /// the embedded refusal all stay in
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

    /// Exports the whole vault into the file at `path`, owner only, as
    /// `vault.export` does: `format` is `archive` (the default) or `okf`.
    /// The file is created or truncated; the answer is the archive's
    /// format, length and BLAKE3 as JSON. Over a server the archive
    /// streams through a kept transfer, so no ceiling on a reply
    /// applies to it.
    #[pyo3(signature = (path, format=None))]
    fn export_to(
        &self,
        py: Python<'_>,
        path: std::path::PathBuf,
        format: Option<String>,
    ) -> PyResult<String> {
        let receipt = py
            .detach(|| {
                let file = std::fs::File::create(&path).map_err(|error| {
                    MemoryError::new(
                        oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                        format!("could not create the export file {path:?}: {error}"),
                        &["Check that the export path's parent directory exists and is writable."],
                    )
                })?;
                self.inner.vault_export_to(format.as_deref(), file)
            })
            .map_err(raise)?;
        encode(&receipt)
    }

    /// Seals a custody register or rotate on the caller's own side (FIX
    /// 11441): `view_json` is what `vault.secrets.custody.get` answered,
    /// `change` is `register` or `rotate`, `holder` the candidate the input
    /// is sealed to (the view's own install when `None`), `recipients` the
    /// candidates permitted to hold the bytes (the holder alone when empty)
    /// and `body` a register's whole record or a rotate's new value. Answers
    /// the `vault.secrets.custody.submit` input that carries it, as JSON. No
    /// vault is opened and no call is made.
    #[staticmethod]
    fn vault_secrets_custody_seal(
        view_json: &str,
        change: &str,
        holder: Option<&str>,
        recipients: Vec<String>,
        body: &[u8],
    ) -> PyResult<String> {
        let view: SecretCustodyViewReply = decode(view_json, "custody view")?;
        let change = CustodyChange::from_name(change)
            .filter(|change| matches!(change, CustodyChange::Register | CustodyChange::Rotate))
            .ok_or_else(|| {
                raise(MemoryError::bad_request(
                    "change must be register or rotate",
                ))
            })?;
        let sealed =
            seal_custody_submit(&view, change, holder, &recipients, None, body).map_err(raise)?;
        encode(&sealed)
    }
}

// The verb methods, generated from the verb table at build time (untangle slice 4.3; build.rs,
// crates/oneiron-sdk-build). A second `#[pymethods]` block: pyo3's `multiple-pymethods` feature.
include!(concat!(env!("OUT_DIR"), "/agent_verbs.rs"));

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
    #[cfg(feature = "engine")]
    module.add_class::<embedded_engine::NativeEngineConnection>()?;
    Ok(())
}
