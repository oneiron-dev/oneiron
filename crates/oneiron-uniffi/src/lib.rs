//! Definition-only UniFFI interface surface for the WIRE head contract.
//!
//! This crate is a *contract artifact*, not a shipped SDK and not runtime
//! product wiring. It declares — with proc macros only, no interface
//! definition file and no build script — the constructors, verbs, records,
//! enums, and error shape that a UniFFI-generated binding exposes, and it
//! proves that declaration two ways:
//!
//! 1. Rust contract tests pin the exported ledger against an independently
//!    maintained list and pin the load-bearing signatures with function
//!    pointers.
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

pub use contract::PINNED_HEAD_CONTRACT_VERBS;
pub use dto::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, ClaimInput, ClaimListFilter,
    ClaimView, CommitReceipt, CompanionRecordInput, ConsolidationJobInput, DeleteReceipt,
    DreamerJobRef, DreamerJobView, Effort, EntityRefReceipt, EntityView, FacadeReceipt,
    ForgetSelector, HabitCheckinInput, LexicalHit, MemoryItem, MemoryPack, MemoryProvenance,
    NeighborHit, NeighborOpts, OpenOptions, OutboundDraftInput, OutboundIntentReceipt,
    PendingWrite, RecallScope, RetrievalMeta, SafeDeleteReason, ScopeHonesty, StructuralEdgeSpec,
    StructuralPutInput, TextIndexField, WireJson, WitnessAuthor, WitnessMessage, WitnessReceipt,
    WitnessTurn,
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
    /// is actor rebinding rather than a head-contract verb, so it is absent
    /// from the pinned verb ledger.
    pub fn as_actor(&self, actor_key: String) -> Result<Arc<Self>, OneironError> {
        let _ = actor_key;
        definition_only("asActor")
    }
}

export_facade! {
    "witness" =>
    fn witness(&self, turn: WitnessTurn) -> WitnessReceipt;

    "recall" =>
    fn recall(
        &self,
        query: String,
        effort: Effort,
        scope: Option<RecallScope>,
        limit: u32,
        format: Option<String>
    ) -> MemoryPack;

    "receipts" =>
    fn receipts(&self, limit: u32) -> Vec<FacadeReceipt>;

    "commit" =>
    fn commit(&self, claims: Vec<ClaimInput>) -> Vec<CommitReceipt>;

    "claimUpsert" =>
    fn claim_upsert(&self, claim: ClaimInput) -> CommitReceipt;

    "remember" =>
    fn remember(&self, claim: ClaimInput) -> CommitReceipt;

    "claimRetract" =>
    fn claim_retract(&self, claim_ref: String) -> CommitReceipt;

    "forget" =>
    fn forget(&self, selector: ForgetSelector) -> Vec<CommitReceipt>;

    "claimList" =>
    fn claim_list(&self, filter: ClaimListFilter) -> Vec<ClaimView>;

    "claimHistory" =>
    fn claim_history(&self, claim_ref: String) -> Vec<ClaimView>;

    "safeDelete" =>
    fn safe_delete(&self, entity_ref: String, reason: SafeDeleteReason) -> DeleteReceipt;

    "pendingWrites" =>
    fn pending_writes(&self, limit: u32) -> Vec<PendingWrite>;

    "hydrate" =>
    fn hydrate(&self, refs: Vec<String>) -> Vec<EntityView>;

    "getEntity" =>
    fn get_entity(&self, entity_ref: String) -> Option<EntityView>;

    "queryBm25" =>
    fn query_bm25(&self, query: String, limit: u32) -> Vec<LexicalHit>;

    "neighbors" =>
    fn neighbors(&self, entity_ref: String, opts: NeighborOpts) -> Vec<NeighborHit>;

    "putStructural" =>
    fn put_structural(&self, input: StructuralPutInput) -> EntityRefReceipt;

    "putHabitCheckin" =>
    fn put_habit_checkin(&self, input: HabitCheckinInput) -> EntityRefReceipt;

    "putCompanionRecord" =>
    fn put_companion_record(&self, input: CompanionRecordInput) -> EntityRefReceipt;

    "admitImportedClaim" =>
    fn admit_imported_claim(&self, input: AdmitImportedClaimInput) -> CommitReceipt;

    "putBlobArtifact" =>
    fn put_blob_artifact(&self, input: BlobArtifactInput) -> EntityRefReceipt;

    "appendBlobVersion" =>
    fn append_blob_version(
        &self,
        artifact_ref: String,
        content: Vec<u8>,
        run_ref: Option<String>,
        occurred_at: Option<i64>,
        learned_at: Option<i64>
    ) -> BlobVersionView;

    "readBlobVersion" =>
    fn read_blob_version(&self, artifact_ref: String, version: u64) -> Option<Vec<u8>>;

    "enqueueConsolidation" =>
    fn enqueue_consolidation(&self, input: ConsolidationJobInput) -> DreamerJobRef;

    "dreamerJobStatus" =>
    fn dreamer_job_status(&self, job_ref: String) -> Option<DreamerJobView>;

    "seedClaims" =>
    fn seed_claims(&self, claims: Vec<ClaimInput>) -> Vec<CommitReceipt>;

    "scheduleOutbound" =>
    fn schedule_outbound(&self, draft: OutboundDraftInput) -> OutboundIntentReceipt;
}

#[cfg(test)]
impl Oneiron {
    /// Builds the handle the fail-closed test calls verbs on.
    ///
    /// Private on purpose: the external drift guard must never be able to
    /// construct a definition-only handle.
    fn test_definition_only() -> Self {
        Self {
            _definition_only: (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EXPORTED_UNIFFI_RUST_NAMES, EXPORTED_UNIFFI_VERBS, HEAD_MEMORY_PACK_SCHEMA_VERSION,
        Oneiron, OneironError, OpenOptions, PINNED_HEAD_CONTRACT_VERBS,
    };
    use std::path::Path;
    use std::sync::Arc;

    fn assert_invalid_state<T>(result: Result<T, OneironError>) {
        match result {
            Err(OneironError::Failure { code, message, .. }) => {
                assert_eq!(code, oneiron::MEMORY_CODE_INVALID_STATE);
                assert!(!message.is_empty());
            }
            Ok(_) => panic!("definition-only entrypoint unexpectedly succeeded"),
        }
    }

    #[test]
    fn constructor_signatures_match_head_contract() {
        type Handle = Result<Arc<Oneiron>, OneironError>;

        let _: fn(Option<String>, Option<OpenOptions>) -> Handle = Oneiron::open;
        let _: fn(String, String) -> Handle = Oneiron::connect;
        let _: fn(&Oneiron, String) -> Handle = Oneiron::as_actor;
    }

    #[test]
    fn memory_pack_schema_version_is_core_sourced() {
        assert_eq!(
            HEAD_MEMORY_PACK_SCHEMA_VERSION,
            oneiron::MEMORY_PACK_VERSION
        );
    }

    #[test]
    fn definition_only_entrypoints_fail_closed() {
        assert_invalid_state(Oneiron::open(None, None));
        assert_invalid_state(Oneiron::open(
            Some("/nonexistent/compile-only".to_owned()),
            Some(OpenOptions {
                dimensions: Some(1024),
            }),
        ));
        assert_invalid_state(Oneiron::connect(
            "https://example.invalid".to_owned(),
            "compile-only".to_owned(),
        ));

        let handle = Oneiron::test_definition_only();
        assert_invalid_state(handle.as_actor("human:compile-only".to_owned()));
        assert_invalid_state(handle.receipts(1));
        assert_invalid_state(handle.pending_writes(1));
        assert_invalid_state(handle.get_entity("compile-only".to_owned()));
        assert_invalid_state(handle.read_blob_version("compile-only".to_owned(), 1));
    }

    /// Proc-macro metadata plus the version-locked local bindgen binary are the
    /// only generation path: no interface definition file, no build script.
    #[test]
    fn crate_has_no_interface_definition_file_or_build_script() {
        fn visit(dir: &Path) {
            for entry in std::fs::read_dir(dir).expect("read UniFFI crate directory") {
                let path = entry.expect("read UniFFI crate entry").path();
                let name = path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or_default()
                    .to_owned();
                if name.starts_with('.') || name == "target" {
                    continue;
                }
                if path.is_dir() {
                    visit(&path);
                    continue;
                }
                assert_ne!(
                    path.extension().and_then(std::ffi::OsStr::to_str),
                    Some("udl"),
                    "interface definition file found: {}",
                    path.display(),
                );
                assert_ne!(name, "build.rs", "build script found: {}", path.display());
            }
        }

        visit(Path::new(env!("CARGO_MANIFEST_DIR")));
    }

    /// The in-crate half of the ledger guard; the external drift guard in
    /// `tests/contract.rs` re-checks it through the public crate root.
    #[test]
    fn exported_ledgers_are_positionally_paired() {
        assert_eq!(EXPORTED_UNIFFI_VERBS, PINNED_HEAD_CONTRACT_VERBS);
        assert_eq!(
            EXPORTED_UNIFFI_VERBS.len(),
            EXPORTED_UNIFFI_RUST_NAMES.len()
        );
    }
}
