//! The UniFFI binding of the Oneiron SDK: the shared Rust client, language-bound.
//!
//! The exported [`Oneiron`] handle holds one [`oneiron_remote::OneironClient`],
//! the same client the napi and Python bindings hold. `open` binds an
//! embedded, in-process vault (no server, no Docker, no key: the on-device
//! Swift path); `connect` binds a remote `oneiron-server` through that
//! client's one HTTP stack. Every verb answers on either backend through the
//! client's one dispatcher, so this crate adds no transport, no route table
//! and no second error taxonomy.
//!
//! With the `engine` feature, `EmbeddedEngine` runs the full server inside
//! the app's process instead (`oneiron_server::embedded`): it opens the vault
//! the way `oneiron serve` does. Its `client(key)` binds `Oneiron` handles
//! the server serves in process, whose verbs cross the server's Router under
//! the caller's credential; its `local_client` attaches handles to the same
//! open vault, whose verbs answer through the client's embedded dispatcher.
//! Its `request` reaches the server's HTTP surface, and its
//! `open_connection` holds a connection of the app's own (`/ws`).
//!
//! The verb methods are generated from `scripts/sdk/agent-verbs.json` into
//! `facade_generated.rs`: one exported method per facade row, which calls that
//! row's typed client method through the lift/lower codecs in `codec`. A row
//! with hand-written records (`dto`) crosses through them. Every other row
//! crosses through the records and enums generated from the facade type
//! inventory into `facade_types_generated.rs`: one per engine struct or enum
//! the rows reach, each with the engine type's own serde wire shape, so a row
//! converts at its boundary through that shape. Only a shape UniFFI cannot
//! express (a `serde_json::Value`, a tuple, a type that holds itself by value)
//! stays a [`WireJson`] field inside its record; a tree that holds itself
//! only through a list is an ordinary record. A row whose type the inventory
//! could not read crosses as [`WireJson`] whole. There is no generic
//! `call(name, json)`; the one name-keyed method is `retry`, which only
//! resends a pending ask's call.
//! Every exported row is callable: the table names no definition-only row.
//!
//! The one foreign callback interface is the embedded engine's app host,
//! `AppHostCallbacks` (with `engine`). There is no subscription verb:
//! streaming belongs to the transport lane, not to a second socket minted
//! here.

#[macro_use]
mod contract;
mod codec;
mod dto;
#[cfg(feature = "engine")]
mod embedded_engine;
mod error;
mod facade_types_generated;

pub use dto::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, CitedMessage, ClaimInput,
    ClaimListFilter, ClaimView, ClaimViews, CommitReceipt, ConsolidationJobInput, DeleteReceipt,
    DreamerJobRef, DreamerJobView, Effort, EntityRead, EntityRefReceipt, EntityView, EntityViews,
    FacadeReceipt, ForgetSelector, HabitCheckinInput, LexicalHit, LexicalHits, MemoryItem,
    MemoryPack, MemoryProvenance, MentionProvenance, NeighborHit, NeighborHits, NeighborOpts,
    OpenOptions, OutboundDraftInput, OutboundIntentReceipt, Paired, PendingWrite, QueryAffect,
    QuoteSpan, ReadReceipt, ReadScope, RecallMedia, RecallScope, RerankReport, RerankSkip,
    RetrievalDegradation, RetrievalMeta, RetrievalQuality, SafeDeleteReason, ScopeHonesty,
    StructuralEdgeSpec, StructuralPutInput, TemporalHint, TextIndexField, WireJson, WitnessAuthor,
    WitnessMessage, WitnessReceipt, WitnessTurn,
};
#[cfg(feature = "engine")]
pub use embedded_engine::{
    AppHostCallbacks, EmbeddedEngine, EngineConnection, EngineHeader, EngineLimits, EngineReply,
    EngineRequest,
};
pub use error::OneironError;
pub use facade_types_generated::*;

use std::sync::Arc;

use codec::{Lift, Lower};

uniffi::setup_scaffolding!("OneironUniFFI");

/// The memory pack schema version this interface carries.
///
/// Sourced from the core constant, so the foreign surface can never pin a
/// stale number; every `MemoryPack.pack_version` the engine returns is it.
pub const HEAD_MEMORY_PACK_SCHEMA_VERSION: u32 = oneiron::MEMORY_PACK_VERSION;

/// The exported handle.
///
/// Both constructors return this same type, and a narrower actor scope is
/// still this same type. It holds the shared client and nothing else: no
/// second storage handle, transport, budget or callback. A handle from
/// `EmbeddedEngine::client` or `local_client` (with `engine`) also holds that
/// engine, so the server outlives every handle on its vault.
#[derive(uniffi::Object)]
pub struct Oneiron {
    inner: oneiron_remote::OneironClient,
    #[cfg(feature = "engine")]
    engine: Option<Arc<EmbeddedEngine>>,
}

#[uniffi::export]
impl Oneiron {
    /// Opens an embedded, in-process vault and returns an actor-bound handle.
    ///
    /// An omitted path resolves to `~/.oneiron/default`; omitted options use
    /// the engine defaults. The handle binds the embedded owner actor at once,
    /// so there is no actor ceremony before the first verb. A second process
    /// opening the same directory fails with `VAULT_LOCKED_SINGLE_WRITER`.
    #[uniffi::constructor]
    pub fn open(
        path: Option<String>,
        options: Option<OpenOptions>,
    ) -> Result<Arc<Self>, OneironError> {
        // Crash output never carries world text: the engine's hook goes in
        // before any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let dimensions: Option<usize> = options.and_then(|options| options.dimensions).lower()?;
        let path = path.map(std::path::PathBuf::from);
        let inner = oneiron_remote::OneironClient::open(
            path.as_deref(),
            &oneiron_remote::OpenOptions { dimensions },
        )?;
        Ok(Arc::new(Self {
            inner,
            #[cfg(feature = "engine")]
            engine: None,
        }))
    }

    /// Binds a remote `oneiron-server`.
    ///
    /// The key is the credential `pair` returned, passed verbatim; the foreign
    /// layer never parses it. This makes no request: every verb after it is
    /// signed with the credential's connection key, and write identity is the
    /// server's to decide.
    #[uniffi::constructor]
    pub fn connect(url: String, key: String) -> Result<Arc<Self>, OneironError> {
        let inner = oneiron_remote::OneironClient::connect(&url, &key)?;
        Ok(Arc::new(Self {
            inner,
            #[cfg(feature = "engine")]
            engine: None,
        }))
    }

    /// Returns a NEW handle bound to another actor; this one is unchanged.
    ///
    /// `actor_key` uses the pinned `human:<ref>` / `agent:<ref>` /
    /// `system:<ref>` grammar. A connected handle refuses with `FORBIDDEN`:
    /// a remote principal cannot widen or replace the actor its slip bound.
    pub fn as_actor(&self, actor_key: String) -> Result<Arc<Self>, OneironError> {
        let inner = self.inner.as_actor(&actor_key)?;
        Ok(Arc::new(Self {
            inner,
            #[cfg(feature = "engine")]
            engine: self.engine.clone(),
        }))
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    pub fn in_room_turn(&self, room_ref: String) -> Result<Arc<Self>, OneironError> {
        let inner = self.inner.in_room_turn(&room_ref)?;
        Ok(Arc::new(Self {
            inner,
            #[cfg(feature = "engine")]
            engine: self.engine.clone(),
        }))
    }

    /// The lasting call receipt the last verb's reply stated, as
    /// `call:<32hex>`, whether it answered or refused.
    ///
    /// Typed returns keep their shape; the ref rides beside them here. `None`
    /// for an embedded handle, before any call, after a call that reached no
    /// server, and for an anonymous off-record call.
    pub fn last_receipt_ref(&self) -> Option<String> {
        self.inner.last_receipt_ref()
    }

    /// Resends the call a `PENDING_ASK` refusal answered: `verb` with the
    /// same `input`, under the invocation id the refusal's hook names
    /// (ARCH-0080 §3, OF-580).
    ///
    /// `pending` is the caught `OneironError.Failure`'s `pending` payload;
    /// `input` is the verb's input as one JSON value. While the ask is open
    /// it fails with the same `PENDING_ASK`; once the ask is answered
    /// proceed, the saved call runs once and this returns its result. The
    /// reply is the verb's shared wire JSON, not the typed record the verb's
    /// own method lifts. The id, the pending check and the input check all
    /// stay in the shared client's `retry`.
    pub fn retry(
        &self,
        pending: WireJson,
        verb: String,
        input: WireJson,
    ) -> Result<WireJson, OneironError> {
        let pending: oneiron::MemoryError =
            serde_json::from_str(&pending.canonical_json).map_err(|error| {
                oneiron::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                    format!("pending is not a serialized refusal: {error}"),
                    &["Pass the pending payload of the PENDING_ASK failure the call raised."],
                )
            })?;
        let input: serde_json::Value = codec::decode(&verb, &input)?;
        let output = self
            .inner
            .retry::<serde_json::Value>(&pending, &verb, &input)?;
        codec::encode(&verb, &output)
    }

    /// Sends one event on a lens card the connected server rendered
    /// (OF-181).
    ///
    /// `request` is the route's `{event, idempotencyKey}` body as one JSON
    /// value, camelCase as the wire spells it; the reply is its wire JSON,
    /// `{"$state": ...}` for a local action or `{outcome, readReceipt}` for a
    /// deterministic tool. A card the server no longer holds fails
    /// `NOT_FOUND`: render the lens again. An embedded handle fails
    /// `BAD_REQUEST`: lens frames live on the server that rendered the card.
    pub fn lens_frame_event(
        &self,
        card_id: String,
        request: WireJson,
    ) -> Result<WireJson, OneironError> {
        let request: oneiron_remote::LensFrameEventRequest =
            codec::decode("lens_frame_event", &request)?;
        let reply = self.inner.lens_frame_event(&card_id, &request)?;
        codec::encode("lens_frame_event", &reply)
    }

    /// Closes a lens card the connected server rendered and frees its frame
    /// (OF-181); the reply is the route's `{closed}`. An embedded handle
    /// fails `BAD_REQUEST`.
    pub fn close_lens_frame(&self, card_id: String) -> Result<WireJson, OneironError> {
        let reply = self.inner.close_lens_frame(&card_id)?;
        codec::encode("close_lens_frame", &reply)
    }
}

/// Redeems a one-use pairing link and returns the origin and credential
/// `connect` takes.
#[uniffi::export]
pub fn pair(link: String) -> Result<Paired, OneironError> {
    let (url, credential) = oneiron_remote::OneironClient::pair(&link)?;
    Ok(Paired { url, credential })
}

include!("facade_generated.rs");
