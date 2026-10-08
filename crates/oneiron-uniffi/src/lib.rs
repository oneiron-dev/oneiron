//! Definition-only UniFFI interface surface for the WIRE head contract.
//!
//! This crate is a *contract artifact*, not a shipped SDK and not runtime
//! product wiring. It declares — with proc macros only, no interface
//! definition file and no build script — the constructors, verbs, records,
//! enums, and error shape that a UniFFI-generated binding exposes, and it
//! proves that declaration two ways:
//!
//! 1. Rust contract tests pin the load-bearing signatures with function pointers.
//! 2. A standalone Swift package under `swift/` compiles a never-run consumer
//!    against freshly generated bindings, so any name, field, optionality, or
//!    width drift breaks the build.
//!
//! Every constructor and verb body fails closed with a typed `INVALID_STATE`
//! error. The first runtime consumer replaces those bodies with core memory
//! facade calls; it does not alter the exported contract. Nothing here opens
//! storage, performs network I/O, mints a budget, or schedules an effect.
//!
//! There is exactly one Rust facade and N bindings. This surface exports no
//! foreign callback interface and no subscription verb: streaming belongs to
//! the transport lane, not to a second socket minted here.

#[macro_use]
mod contract;
mod dto;
mod error;

pub use dto::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, ClaimInput, ClaimListFilter,
    ClaimView, ClaimViews, CommitReceipt, ConsolidationJobInput, DeleteReceipt, DreamerJobRef,
    DreamerJobView, Effort, EntityRead, EntityRefReceipt, EntityView, EntityViews, FacadeReceipt,
    ForgetSelector, HabitCheckinInput, LexicalHit, LexicalHits, MemoryItem, MemoryPack,
    MemoryProvenance, NeighborHit, NeighborHits, NeighborOpts, OpenOptions, OutboundDraftInput,
    OutboundIntentReceipt, PendingWrite, ReadReceipt, ReadScope, RecallScope, RetrievalMeta,
    SafeDeleteReason, ScopeHonesty, StructuralEdgeSpec, StructuralPutInput, TextIndexField,
    WireJson, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn,
};
pub use error::OneironError;

use std::sync::Arc;

uniffi::setup_scaffolding!("OneironUniFFI");

/// The memory pack schema version this interface declares.
///
/// Sourced from the core constant so the foreign surface can never pin a
/// stale number. Populating live values from it is first-consumer scope.
pub const HEAD_MEMORY_PACK_SCHEMA_VERSION: u32 = oneiron::MEMORY_PACK_VERSION;

/// The exported handle.
///
/// Both constructors return this same type, and a narrower actor scope is
/// still this same type. Generated scaffolding owns the handle lifetime; no
/// storage handle, remote client, credential, budget, or callback is stored
/// here.
#[derive(uniffi::Object)]
pub struct Oneiron {
    _definition_only: (),
}

/// Fails closed for every definition-only entrypoint.
///
/// Accidental runtime use produces exactly the typed error shape the contract
/// promises rather than a panic, a sentinel, or a silent no-op.
fn definition_only<T>(entrypoint: &str) -> Result<T, OneironError> {
    Err(OneironError::Failure {
        code: oneiron::MEMORY_CODE_INVALID_STATE.to_owned(),
        message: format!("{entrypoint} is defined but has no runtime consumer wiring"),
        suggestions: vec![
            "Wire the generated interface through the core memory facade in the first-consumer lane."
                .to_owned(),
        ],
    })
}

#[uniffi::export]
impl Oneiron {
    /// Names embedded mode.
    ///
    /// An omitted path resolves to the engine's default directory and an
    /// omitted option set uses engine defaults once the runtime arm lands.
    /// Embedded ownership binds the core-owned default actor; this
    /// definition binds no actor.
    #[uniffi::constructor]
    pub fn open(
        path: Option<String>,
        options: Option<OpenOptions>,
    ) -> Result<Arc<Self>, OneironError> {
        let _ = (path, options);
        definition_only("open")
    }

    /// Names remote mode.
    ///
    /// The key is an opaque minted slip passed verbatim; the foreign layer
    /// never parses, splits, or validates it, and never chooses an actor.
    /// Runtime wiring consumes the single Rust remote client rather than
    /// adding a transport here.
    #[uniffi::constructor]
    pub fn connect(url: String, key: String) -> Result<Arc<Self>, OneironError> {
        let _ = (url, key);
        definition_only("connect")
    }

    /// Rebinds the handle to a narrower actor scope.
    ///
    /// Returns the same handle type; it does not mutate the receiver, and it
    /// is actor rebinding rather than a head-contract verb.
    pub fn as_actor(&self, actor_key: String) -> Result<Arc<Self>, OneironError> {
        let _ = actor_key;
        definition_only("asActor")
    }
}

include!("facade_generated.rs");
