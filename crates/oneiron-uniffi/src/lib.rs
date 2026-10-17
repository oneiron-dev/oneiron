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
//! The verb methods are generated from `scripts/sdk/agent-verbs.json` into
//! `facade_generated.rs`: one exported method per facade row, which calls that
//! row's typed client method through the lift/lower codecs in `codec`. A row
//! with UniFFI records crosses typed; a row without crosses its input and
//! output as the crate's [`WireJson`] leaf, parsed into the row's engine input
//! type and written from its typed output on the Rust side. That is a typed
//! call per verb with a JSON body, not a generic `call(name, json)`: there is
//! none. Definition rows the table has not made callable fail closed with a
//! typed `INVALID_STATE` error.
//!
//! This surface exports no foreign callback interface and no subscription
//! verb: streaming belongs to the transport lane, not to a second socket minted
//! here.

#[macro_use]
mod contract;
mod codec;
mod dto;
mod error;

pub use dto::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, CitedMessage, ClaimInput,
    ClaimListFilter, ClaimView, ClaimViews, CommitReceipt, ConsolidationJobInput, DeleteReceipt,
    DreamerJobRef, DreamerJobView, Effort, EntityRead, EntityRefReceipt, EntityView, EntityViews,
    FacadeReceipt, ForgetSelector, HabitCheckinInput, LexicalHit, LexicalHits, MemoryItem,
    MemoryPack, MemoryProvenance, NeighborHit, NeighborHits, NeighborOpts, OpenOptions,
    OutboundDraftInput, OutboundIntentReceipt, Paired, PendingWrite, ReadReceipt, ReadScope,
    RecallScope, RerankReport, RerankSkip, RetrievalDegradation, RetrievalMeta, RetrievalQuality,
    SafeDeleteReason, ScopeHonesty, StructuralEdgeSpec, StructuralPutInput, TemporalHint,
    TextIndexField, WireJson, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn,
};
pub use error::OneironError;

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
/// second storage handle, transport, budget or callback.
#[derive(uniffi::Object)]
pub struct Oneiron {
    inner: oneiron_remote::OneironClient,
}

/// Fails closed for a definition row the verb table has not made callable.
///
/// Calling one produces exactly the typed error shape every other refusal
/// has, rather than a panic, a sentinel or a silent no-op.
fn definition_only<T>(entrypoint: &str) -> Result<T, OneironError> {
    Err(OneironError::Failure {
        code: oneiron::MEMORY_CODE_INVALID_STATE.to_owned(),
        message: format!("{entrypoint} is defined but has no callable verb row yet"),
        suggestions: vec![
            "Use the verb table's callable rows; this one waits for its typed row.".to_owned(),
        ],
        attempted: None,
        replacement: None,
        schema_ref: None,
    })
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
        Ok(Arc::new(Self { inner }))
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
        Ok(Arc::new(Self { inner }))
    }

    /// Returns a NEW handle bound to another actor; this one is unchanged.
    ///
    /// `actor_key` uses the pinned `human:<ref>` / `agent:<ref>` /
    /// `system:<ref>` grammar. A connected handle refuses with `FORBIDDEN`:
    /// a remote principal cannot widen or replace the actor its slip bound.
    pub fn as_actor(&self, actor_key: String) -> Result<Arc<Self>, OneironError> {
        let inner = self.inner.as_actor(&actor_key)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Returns a NEW handle whose every verb runs as a turn in `room_ref`.
    pub fn in_room_turn(&self, room_ref: String) -> Result<Arc<Self>, OneironError> {
        let inner = self.inner.in_room_turn(&room_ref)?;
        Ok(Arc::new(Self { inner }))
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
}

/// Redeems a one-use pairing link and returns the origin and credential
/// `connect` takes.
#[uniffi::export]
pub fn pair(link: String) -> Result<Paired, OneironError> {
    let (url, credential) = oneiron_remote::OneironClient::pair(&link)?;
    Ok(Paired { url, credential })
}

include!("facade_generated.rs");
