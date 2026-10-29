//! Remote-backed NativeClient SDK seam with its stamped-turn input.

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use super::boundary::{boundary_error, facade_error};
use super::convert::{
    commit_receipt_from_engine, memory_pack_from_engine, query_affect_to_engine,
    recall_media_to_engine, recall_scope_to_engine, witness_receipt_from_engine,
    witness_turn_to_engine,
};
use super::dtos::{
    NapiClaimInput, NapiCommitReceipt, NapiMemoryPack, NapiQueryAffect, NapiRecallMedia,
    NapiRecallScope, NapiWitnessAssertions, NapiWitnessMessage, NapiWitnessReceipt, NapiWitnessTurn,
};
use super::input_error::witness_input_error;
use super::js_json::js_json;
use super::numeric::{claim_input_to_engine, dimensions_to_engine, limit_to_engine};
use super::pairing::{NapiCheckpointPin, pin_from_engine};
use crate::boundary::host_device_class;

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
    /// A new project room thread root's audience seed (32-hex PERSON and
    /// AGENT_DEF ids), edited later through `vault.rooms.thread_audience`;
    /// omitted ⇒ it reads as its room does.
    pub thread_audience: Option<Vec<String>>,
    /// The records this reply names as cited or created (OF-063), judged by
    /// the engine under the writer's own read; omitted ⇒ it asserts nothing.
    pub assertions: Option<NapiWitnessAssertions>,
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
            assertions: self.assertions,
        })
        .map_err(witness_input_error)
    }
}

/// What `pair` returns: the server origin, the credential `connect` takes,
/// the checkpoint pin the link named (OF-469) and the credential's comm
/// reach (FIX 5058).
#[napi(object)]
pub struct NapiPaired {
    pub url: String,
    pub credential: String,
    /// The pin, already checked against the link's challenge and digest;
    /// omitted when the vault has no attested checkpoint. The caller keeps
    /// it beside the credential for a local replica to adopt by.
    pub pin: Option<NapiCheckpointPin>,
    /// Whom the paired credential may address, as the server took it:
    /// `parent`, `subtree`, `project` or `vault`.
    pub comm: String,
}

/// What `openWithHostRoot` did with the host root it was given (FIX 4730).
#[napi(object)]
pub struct NapiHostRootProfile {
    /// This open enrolled this install as an `Unanswered` machine; `false`
    /// when its live profile already stood, and nothing was written.
    pub enrolled: bool,
    /// The given root is not this vault's settled root, so it went unused:
    /// the handle stands under the settled root as before. Reported, never
    /// refused. Never with `enrolled`.
    pub wrong_root: bool,
}

/// The private native handle behind `packages/oneiron`.
#[napi]
pub struct NativeClient {
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

#[napi]
impl NativeClient {
    /// Opens an embedded vault; `path` omitted ⇒ `~/.oneiron/default`. The
    /// install enrols as the `deviceClass` its host declares (FIX 5560):
    /// `"computer"`, the default, or `"phone"`.
    #[napi(factory)]
    pub fn open(
        path: Option<String>,
        dimensions: Option<f64>,
        device_class: Option<String>,
    ) -> napi::Result<Self> {
        crate::facade::before_vault_open();
        let options = open_options(dimensions, device_class)?;
        let path = path.map(std::path::PathBuf::from);
        let inner =
            oneiron_remote::OneironClient::open(path.as_deref(), &options).map_err(facade_error)?;
        Ok(Self { inner, keep: None })
    }

    /// `open`, then this install's own machine profile from the vault's
    /// host root secret (FIX 4730): `oneiron_remote`'s rooted-only
    /// `open_with_host_root`. `hostRootSecret` is the secret's exact bytes,
    /// borrowed from JavaScript memory for this call only; the caller keeps
    /// them and clears them. `hostRootProfile` says what it did.
    /// `deviceClass` is `open`'s (FIX 5560).
    #[napi(factory)]
    pub fn open_with_host_root(
        path: Option<String>,
        dimensions: Option<f64>,
        host_root_secret: Buffer,
        device_class: Option<String>,
    ) -> napi::Result<Self> {
        crate::facade::before_vault_open();
        let options = open_options(dimensions, device_class)?;
        let path = path.map(std::path::PathBuf::from);
        let inner = oneiron_remote::OneironClient::open_with_host_root(
            path.as_deref(),
            &options,
            host_root_secret.as_ref(),
        )
        .map_err(facade_error)?;
        Ok(Self { inner, keep: None })
    }

    /// What `openWithHostRoot` did with its root, on the handle it returned;
    /// `null` on every other handle, one rebound from it included.
    #[napi]
    pub fn host_root_profile(&self) -> Option<NapiHostRootProfile> {
        self.inner
            .host_root_profile()
            .map(|profile| NapiHostRootProfile {
                enrolled: profile.enrolled,
                wrong_root: profile.wrong_root,
            })
    }

    /// Binds a remote `oneiron-server`. `key` is the credential `pair`
    /// returned; every request is signed with it, and write identity is the
    /// server's.
    #[napi(factory)]
    pub fn connect(url: String, key: String) -> napi::Result<Self> {
        let inner = oneiron_remote::OneironClient::connect(&url, &key).map_err(facade_error)?;
        Ok(Self { inner, keep: None })
    }

    /// Redeems a pairing link once; returns the origin, the credential, the
    /// checkpoint pin the link named, if any, and the credential's comm reach.
    #[napi]
    pub fn pair(link: String) -> napi::Result<NapiPaired> {
        let (url, credential, pin, comm) =
            oneiron_remote::OneironClient::pair_pinned(&link).map_err(facade_error)?;
        Ok(NapiPaired {
            url,
            credential,
            pin: pin.as_ref().map(pin_from_engine).transpose()?,
            comm: comm.as_str().to_owned(),
        })
    }

    /// Returns a NEW handle bound to another actor; refuses when connected.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<Self> {
        let inner = self.inner.as_actor(&actor_key).map_err(facade_error)?;
        Ok(self.rebound(inner))
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    #[napi]
    pub fn in_room_turn(&self, room_ref: String) -> napi::Result<Self> {
        let inner = self.inner.in_room_turn(&room_ref).map_err(facade_error)?;
        Ok(self.rebound(inner))
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
        Ok(self.rebound(inner))
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
        let (pending, input) = (js_json(pending), js_json(input));
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
        let request = js_json(request);
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

/// What an embedded open takes from JavaScript. The device class is the one
/// its host declares ([`host_device_class`]), `None` when it gave none.
fn open_options(
    dimensions: Option<f64>,
    device_class: Option<String>,
) -> napi::Result<oneiron_remote::OpenOptions> {
    let dimensions = dimensions
        .map(dimensions_to_engine)
        .transpose()
        .map_err(facade_error)?;
    let device_class = device_class
        .as_deref()
        .map(|class| host_device_class(Some(class)))
        .transpose()
        .map_err(|reason| {
            facade_error(oneiron::MemoryError::new(
                oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                reason,
                &["Pass deviceClass \"computer\" or \"phone\", or omit it for a computer."],
            ))
        })?;
    Ok(oneiron_remote::OpenOptions {
        dimensions,
        device_class,
    })
}

/// A lens-frame reply that would not encode back to its wire JSON.
fn lens_frame_unencoded(error: serde_json::Error) -> napi::Error {
    boundary_error(format!("could not encode the lens frame reply: {error}"))
}

#[path = "client/generated/agent_verbs.rs"]
mod agent_verbs;
// The engine-backed served client (OF-237), only in an `engine` build.
#[cfg(feature = "engine")]
mod embedded_engine;
