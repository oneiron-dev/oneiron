//! Remote-backed NativeClient SDK seam with its stamped-turn input.

use napi_derive::napi;

use super::boundary::{boundary_error, facade_error};
use super::convert::{
    commit_receipt_from_engine, gate_receipt_from_engine, memory_pack_from_engine,
    query_affect_to_engine, recall_media_to_engine, recall_scope_to_engine,
    witness_receipt_from_engine, witness_turn_to_engine,
};
use super::dtos::{
    NapiClaimInput, NapiCommitReceipt, NapiGateReceipt, NapiMemoryPack, NapiQueryAffect,
    NapiRecallMedia, NapiRecallScope, NapiWitnessMessage, NapiWitnessReceipt, NapiWitnessTurn,
};
use super::input_error::witness_input_error;
use super::numeric::{claim_input_to_engine, dimensions_to_engine, limit_to_engine};

// ── ONE-1441 WIRE-P1: the shared-backend client behind the `oneiron` npm
//    package ───────────────────────────────────────────────────────────────
//
// `VaultBridge`/`ActorScopedVault` above stay exactly as they are for existing
// direct native consumers. `NativeClient` is the SDK seam: it holds one
// `oneiron_remote::OneironClient`, so the embedded and remote backends differ
// by a constructor and nothing else, and neither this file nor the TypeScript
// wrapper contains an endpoint, a timeout, or a route table.
//
// It is PRIVATE to the npm package. `packages/oneiron` re-exports `Oneiron` and
// `OneironError` only; this class is an implementation detail the wrapper
// holds and never hands out.

/// One turn to witness, with an OPTIONAL timestamp (ONE-1441 I14).
///
/// The only difference from [`NapiWitnessTurn`] is that `occurredAt` may be
/// omitted, which is the §HEAD-CONTRACT surface. Omission is stamped with
/// current wall-clock Unix seconds by `oneiron_remote::stamp_occurred_at` —
/// the same function the Python binding calls — so the stamping rule has one
/// implementation rather than one per language.
#[napi(object)]
pub struct NapiWitnessTurnInput {
    /// CONVERSATION ref (32-hex create-or-get, or existing short ref).
    pub conversation_ref: String,
    /// TURN ref (create-or-get); omitted ⇒ a fresh TURN.
    pub turn_ref: Option<String>,
    /// Messages, attributed to the bound actor unless `system`.
    pub messages: Vec<NapiWitnessMessage>,
    /// Unix seconds; omitted ⇒ stamped at the call boundary.
    pub occurred_at: Option<f64>,
    /// A new project room thread root's audience (32-hex PERSON and
    /// AGENT_DEF ids), fixed once set; omitted ⇒ it reads as its room does.
    pub thread_audience: Option<Vec<String>>,
}

impl NapiWitnessTurnInput {
    fn into_engine(self) -> napi::Result<oneiron::memory::WitnessTurn> {
        let stamped = oneiron_remote::stamp_occurred_at(self.occurred_at).map_err(facade_error)?;
        // Caller numbers are already validated; narrowing failure here is
        // an internal invariant failure, not bad input.
        let occurred_at = i64::try_from(stamped)
            .map_err(|_| boundary_error("occurred_at is out of range".to_owned()))?;
        witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: self.conversation_ref,
            turn_ref: self.turn_ref,
            messages: self.messages,
            occurred_at,
            thread_audience: self.thread_audience,
        })
        .map_err(witness_input_error)
    }
}

/// What `pair` returns: the server origin and the credential `connect` takes.
#[napi(object)]
pub struct NapiPaired {
    pub url: String,
    pub credential: String,
}

/// The private native handle behind `packages/oneiron`.
#[napi]
pub struct NativeClient {
    inner: oneiron_remote::OneironClient,
}

#[napi]
impl NativeClient {
    /// Opens an embedded vault; `path` omitted ⇒ `~/.oneiron/default`.
    #[napi(factory)]
    pub fn open(path: Option<String>, dimensions: Option<f64>) -> napi::Result<Self> {
        crate::facade::before_vault_open();
        let options = oneiron_remote::OpenOptions {
            dimensions: dimensions
                .map(dimensions_to_engine)
                .transpose()
                .map_err(facade_error)?,
        };
        let path = path.map(std::path::PathBuf::from);
        let inner =
            oneiron_remote::OneironClient::open(path.as_deref(), &options).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Binds a remote `oneiron-server`. `key` is the credential `pair`
    /// returned; every request is signed with it, and write identity is the
    /// server's.
    #[napi(factory)]
    pub fn connect(url: String, key: String) -> napi::Result<Self> {
        let inner = oneiron_remote::OneironClient::connect(&url, &key).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Redeems a pairing link once; returns the origin and the credential.
    #[napi]
    pub fn pair(link: String) -> napi::Result<NapiPaired> {
        let (url, credential) = oneiron_remote::OneironClient::pair(&link).map_err(facade_error)?;
        Ok(NapiPaired { url, credential })
    }

    /// Returns a NEW handle bound to another actor; refuses when connected.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<Self> {
        let inner = self.inner.as_actor(&actor_key).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    #[napi]
    pub fn in_room_turn(&self, room_ref: String) -> napi::Result<Self> {
        let inner = self.inner.in_room_turn(&room_ref).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle whose every verb runs inside the off-record
    /// session `session_ref` names, bound to this handle's principal: the
    /// app host's actor when embedded (OF-063). It grants nothing.
    #[napi]
    pub fn in_off_record_session(&self, session_ref: String) -> napi::Result<Self> {
        let inner = self
            .inner
            .in_off_record_session(&session_ref)
            .map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// The lasting call receipt the last verb's reply stated, as
    /// `call:<32hex>`, whether it answered or refused. `null` for an embedded
    /// handle, before any call, after a call that reached no server, and for
    /// an anonymous off-record call.
    #[napi]
    pub fn last_receipt_ref(&self) -> Option<String> {
        self.inner.last_receipt_ref()
    }

    /// Resends the call a `PENDING_ASK` refusal answered: `verb` with the
    /// same `input`, under the invocation id the refusal's `hook` names
    /// (ARCH-0080 §3, OF-580). `pending` is that refusal as its serialized
    /// MemoryError (`{code, message, suggestions, hook}`). While the ask is
    /// open it raises the same `PENDING_ASK`; once it is answered proceed,
    /// the saved call runs once. The reply is the shared wire JSON for
    /// `verb`, not the typed projection its own method would convert to.
    /// The id, the pending check and the input check all stay in
    /// `oneiron_remote::OneironClient::retry`.
    #[napi]
    pub fn retry(
        &self,
        pending: serde_json::Value,
        verb: String,
        input: serde_json::Value,
    ) -> napi::Result<serde_json::Value> {
        let pending: oneiron::MemoryError = serde_json::from_value(pending).map_err(|error| {
            facade_error(oneiron::MemoryError::new(
                oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                format!("pending is not a serialized refusal: {error}"),
                &["Pass the PENDING_ASK error the call raised, with its hook."],
            ))
        })?;
        self.inner
            .retry::<serde_json::Value>(&pending, &verb, &input)
            .map_err(facade_error)
    }

    /// Sends one event on a lens card the connected server rendered
    /// (OF-181): `request` is the route's `{event, idempotencyKey}` body, and
    /// the reply is its wire JSON, `{$state}` or `{outcome, readReceipt}`.
    /// The route, the credential and the embedded refusal all stay in
    /// `oneiron_remote::OneironClient::lens_frame_event`.
    #[napi]
    pub fn lens_frame_event(
        &self,
        card_id: String,
        request: serde_json::Value,
    ) -> napi::Result<serde_json::Value> {
        let request: oneiron_remote::LensFrameEventRequest = serde_json::from_value(request)
            .map_err(|error| {
                facade_error(oneiron::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                    format!("the lens frame event is not the documented shape: {error}"),
                    &["Send {event, idempotencyKey}, the event as the rendered card names it."],
                ))
            })?;
        let reply = self
            .inner
            .lens_frame_event(&card_id, &request)
            .map_err(facade_error)?;
        serde_json::to_value(reply).map_err(lens_frame_unencoded)
    }

    /// Closes a lens card the connected server rendered and frees its frame
    /// (OF-181); the reply is the route's `{closed}`.
    #[napi]
    pub fn close_lens_frame(&self, card_id: String) -> napi::Result<serde_json::Value> {
        let reply = self
            .inner
            .close_lens_frame(&card_id)
            .map_err(facade_error)?;
        serde_json::to_value(reply).map_err(lens_frame_unencoded)
    }
}

/// A lens-frame reply that would not encode back to its wire JSON.
fn lens_frame_unencoded(error: serde_json::Error) -> napi::Error {
    boundary_error(format!("could not encode the lens frame reply: {error}"))
}

mod agent_verbs;
