use std::time::{SystemTime, UNIX_EPOCH};

pub mod access_grant;
pub mod affect;
pub mod analyzer;
pub mod batch;
pub(crate) mod bm25;
pub mod claim;
pub mod code_artifact;
pub mod code_revision;
pub mod code_symbol;
pub mod codebase;
pub mod context_pack;
pub mod deletion;
pub(crate) mod distance;
pub mod error;
pub mod federation;
pub(crate) mod fusion;
pub(crate) mod gate;
pub(crate) mod hnsw;
pub(crate) mod identity;
pub mod ingest;
pub(crate) mod limits;
pub mod maintain;
pub mod pipeline;
pub(crate) mod ppr;
pub mod provenance;
pub mod recovery;
pub mod serialize;
pub mod skill;
pub mod store;
pub(crate) mod sweep;
#[cfg(feature = "sync")]
pub mod sync;
pub mod tokenizer;
pub mod types;
mod vault;

pub use crate::access_grant::{
    ACCESS_GRANT_BODY_KEYS, ACCESS_GRANT_SCHEMA_VERSION, AccessGrant, AccessGrantCapability,
    AccessGrantScope, AccessGrantStatus, decode_access_grant_body, encode_access_grant_body,
};
pub use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, CopingOutcomeUpdate, CopingOutcomeValue,
    CopingStrategy, coping_delta_successful, coping_outcome_claim_candidate, coping_outcome_value,
    decode_coping_outcome_claim, decode_coping_outcome_value,
};
pub use crate::affect::{
    AFFECT_TRIGGER_PREDICATE, AffectTriggerValue, CLAIM_VAD_REAPPRAISAL_PREDICATE,
    ClaimVadConsolidation, ClaimVadReappraisal, ClaimVadTurnEvidence, VadDelta,
    affect_trigger_claim_candidate, affect_trigger_value, decode_affect_trigger_claim,
    decode_affect_trigger_value,
};
pub use crate::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, LangPolicy, LanguageHint, NormalizationPolicy, Token, TokenKind,
};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::bm25::Bm25Formula;
pub use crate::claim::{
    CLAIM_BODY_KEYS, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, MAX_PREDICATE_BYTES, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED,
    RESERVED_PREDICATE_NAMESPACE,
};
pub use crate::code_artifact::{
    CODE_ARTIFACT_BODY_KEYS, CODE_ARTIFACT_REPO_REF_MAX_BYTES, CODE_ARTIFACT_SUMMARY_HASH_LEN,
    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES, CodeArtifactBody, decode_code_artifact_body,
    encode_code_artifact_body,
};
pub use crate::code_revision::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, CodeRevision, CodeRevisionFork,
    CodeRevisionKind, decode_code_revision, decode_code_revision_fork, encode_code_revision,
    encode_code_revision_fork,
};
pub use crate::code_symbol::{
    CODE_SYMBOL_CHUNK_KEYS, CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_KIND_MAX_BYTES,
    CODE_SYMBOL_MANIFEST_BODY_KEYS, CODE_SYMBOL_MANIFEST_MAX_CHUNKS,
    CODE_SYMBOL_MANIFEST_MAX_SYMBOLS, CODE_SYMBOL_NAME_MAX_BYTES, CODE_SYMBOL_REVISION_KEYS,
    CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES, CODE_SYMBOL_TEXT_HASH_LEN, CodeChunk, CodeSymbolBlame,
    CodeSymbolManifest, CodeSymbolRevision, decode_code_symbol_manifest,
    derive_code_chunks_from_text_diff, derive_symbol_fingerprint, encode_code_symbol_manifest,
};
pub use crate::codebase::{
    CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_ENTRY_KEYS,
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_PROJECT_ID_MAX_BYTES, CODEBASE_REPO_REF_MAX_BYTES,
    CODEBASE_SNAPSHOT_BODY_KEYS, CODEBASE_SNAPSHOT_MAX_FILES, CodebaseFileEntry, CodebaseSnapshot,
    RepoRef, decode_codebase_snapshot, encode_codebase_snapshot,
};
pub use crate::context_pack::{ContextPackBuilder, SerializedContextPack};
pub use crate::deletion::{
    DecodedTombstoneValue, DeleteEntityOutcome, DeleteReason, TOMBSTONE_VALUE_LEGACY_LEN,
    TOMBSTONE_VALUE_V2_LEN, TombstoneReason, TombstoneValueV2, decode_tombstone_value,
};
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::federation::{
    FEDERATION_GRANT_BODY_KEYS, FEDERATION_GRANT_SCHEMA_VERSION, FederationGrant,
    FederationGrantPreset, FederationGrantRole, FederationGrantScope, decode_federation_grant_body,
    encode_federation_grant_body,
};
pub use crate::ingest::{
    INGEST_SOURCE_REGISTRY, IngestError, IngestHarnessConfig, IngestResult, IngestSource,
    IngestSourceConfig, IngestSourceFormat, IngestSourceRegistration, IngestSourceRegistry,
    IngestTrustCeiling, JSONL_TRANSCRIPT_SOURCE_ID, JsonlTranscriptSource,
    KNOWN_INGEST_HARNESS_CONFIG, NormalizedIngestBatch, NormalizedIngestClaim,
    NormalizedIngestRecord,
};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::{
    DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, PendingVectorEmbedding, PipelineBuilder,
    RetrievalWithPendingVectors, RetrievalWithTelemetry, WorldScope,
};
pub use crate::provenance::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeProvenanceClaimBody, EdgeRef,
    MODEL_SUBSTRATE_FIELD_MAX_BYTES, PREDICATE_EDGE_PROVENANCE, REASONING_EFFORT_MAX_BYTES,
    SupersessionStatus, decode_edge_provenance_body, derive_confirmation_status,
    validate_actor_class,
};
pub use crate::recovery::{
    QuarantinedArtifact, RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX, RECOVERY_ARTIFACT_MAGIC,
    RECOVERY_ARTIFACT_VERSION, RecoveryArtifact, RecoveryArtifactFailure, RecoveryArtifactLoad,
    decode_recovery_artifact, encode_recovery_artifact, load_recovery_artifact,
};
pub use crate::skill::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_MAX_DEPENDENCIES,
    SKILL_RECORD_BODY_KEYS, SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
    decode_skill_record, encode_skill_record,
};
pub use crate::store::{
    RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalScoreComponent, RetrievalSignal,
};
pub use crate::tokenizer::{
    ContextPackTokenizer, DEFAULT_CONTEXT_PACK_TOKENIZER, DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
    PackTokenizer, count_context_pack_tokens,
};
pub use crate::types::{
    Bm25RankProfile, ClaimCandidate, CompanionExportClassification, CompanionExpression,
    CompanionExpressionRegister, CompanionProvenance, CompanionRecord, CompanionRecordKey,
    CompanionRecordKind, CompanionRegister, CompanionScope, CompanionScopeResolution,
    CompanionScopeResolutionSource, CompanionSubject, ContextEntity, ContextPack,
    ContextPackRetrievalBudget, DecodedEdgeValue, EIRI_CONTEXT_VERSION_V4,
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PSYCH_PROFILE, EdgeActorClass,
    EdgeConfirmationStatus, EdgeInfo, EdgeKind, EdgeProvenanceFlags, EdgeValueLayout,
    EiriCompanionAssembly, EiriMemoryBoard, EiriMemoryBoardBudget, EiriMemoryBoardRow,
    EiriMemoryBoardSlot, EiriMemoryBoardSource, EiriSessionRagState, EmptyContext, EmptyReason,
    EntityId, FieldProfile, HnswConfig, HydratedShortIdDeletion, HydratedShortIdDeletionReason,
    HydratedShortIdDeletionSource, MemoryOperationKind, MemoryTimeline, MemoryTimelineRecord,
    MemoryTimelineRecordState, NamedMemoryVerb, NotificationItem, PackFormat, PackItemTokenStats,
    PackSectionTokenStats, PackStats, PackTokenStats, ResumeBudget, ResumeBundle, ScoredEntity,
    SessionContext, Signal, StructuralKindRegistration, TemporalAnchorMode, TemporalGranularity,
    TextAnalyzerConfig, TextIndexOptions, TimeRange, TokenAllocation, TypeByteBand,
    UnprocessedItem, Vad, VadAnnotation, VadAnnotationSource, VadComponent, VaultConfig,
    WriteActor, WriteEnvelope, WriteProvenance, companion_value_from_json, companion_value_to_json,
    decode_companion_record_body, encode_companion_record_body,
};
pub use crate::types::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
    decode_psych_profile_body, encode_psych_profile_body,
};
pub use crate::vault::{
    ActorBound, HydratedShortId, TextIndexStatus, Vault, VaultDoctorDbManifestReport,
    VaultDoctorHnswRecordState, VaultDoctorHnswReport, VaultDoctorReport,
};

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidKey);
    }

    let (chunks, rem) = bytes.as_chunks::<4>();
    debug_assert!(rem.is_empty());
    Ok(chunks
        .iter()
        .map(|bytes| f32::from_le_bytes(*bytes))
        .collect())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_bug;

#[cfg(test)]
pub(crate) mod test_util {
    //! Shared test helpers. Centralized to avoid drift between per-module
    //! copies of `open_test_vault`. Each module keeps its own `test_config()`
    //! because configs diverge (map sizes, dimensions, embedding model).
    use crate::types::VaultConfig;
    use crate::vault::Vault;

    /// Opens a temporary vault with the supplied config. Returns the
    /// `TempDir` so callers keep the directory alive for the vault's lifetime.
    pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), cfg).expect("open vault");
        clear_default_policy_manifest_for_legacy_tests(&vault);
        (dir, vault)
    }

    fn clear_default_policy_manifest_for_legacy_tests(vault: &Vault) {
        let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
                Ok(())
            })
            .expect("clear default policy manifest for legacy test fixture");
    }
}
