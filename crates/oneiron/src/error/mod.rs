#[cfg(feature = "sync")]
use std::error::Error as StdError;

use crate::affect::VadComponent;
use crate::temporal::TemporalExpressionParseError;

mod artifact;
mod claim;
mod code;
mod gate;
mod maintenance;
mod off_record;
mod record;
mod registry;
mod relay;
mod secret;
mod store;
mod sync;

pub use self::artifact::ArtifactError;
pub use self::claim::ClaimError;
pub use self::code::CodeError;
pub use self::gate::{GateDenial, GateDenialOutcome, GateDenialReason, GateError};
pub use self::maintenance::{CompactionPacketError, MaintenanceError};
pub use self::off_record::OffRecordError;
pub use self::record::RecordError;
pub use self::registry::RegistryError;
pub use self::relay::RelayError;
pub use self::secret::SecretError;
pub use self::store::{StoreError, VaultRootEntry, VaultRootProblem};
pub use self::sync::SyncError;
#[cfg(feature = "sync")]
pub use self::sync::{
    SyncConfigField, SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation,
    SyncRollbackError, SyncSelectorValidation,
};

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable coarse-grained category for [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Storage,
    Io,
    DimensionMismatch,
    InvalidVector,
    InvalidEdgeWeight,
    InvalidVad,
    EmbeddingModelChanged,
    HnswConfigChanged,
    StorageAbiVersionChanged,
    StorageSchemaVersionChanged,
    DbManifestMismatch,
    VaultRootPreflight,
    MapFull,
    InvalidConfig,
    InvalidTemporalExpression,
    EntityNotFound,
    AccessGrantAlreadyExists,
    OutboundGrantAlreadyExists,
    ConnectorKeyAlreadyExists,
    ChannelIdentityAlreadyExists,
    CounterpartyContactAlreadyExists,
    CompanionRecordAlreadyExists,
    ConcurrentWrite,
    ArithmeticOverflow,
    InvariantViolation,
    InvalidKey,
    InvalidFederationGrantBody,
    InvalidAuthorityLogBody,
    InvalidAccessGrantBody,
    InvalidOutboundGrantBody,
    InvalidConnectorKeyBody,
    ConnectorCharterCompile,
    ConnectorCharterApprovalMismatch,
    ConnectorCharterMissing,
    InvalidChannelIdentityBody,
    WorkspaceMailboxAutonomyNotReady,
    InvalidCounterpartyContactBody,
    InvalidCommRecordBody,
    InvalidDiagnosticBody,
    InvalidDisclosureScope,
    DisclosureClampViolation,
    InvalidConsentBound,
    InvalidConsentGrantRow,
    InvalidConsentEffectFacts,
    ConsentOwnerNotAuthenticated,
    ConsentUnauthenticatedActor,
    ConsentCatastropheNotRememberable,
    ConsentGrantNotFound,
    ConsentGrantRevoked,
    ConsentApproveOnceSpent,
    InvalidTaskBody,
    CorruptedIndex,
    ContextPackValidation,
    IndexOverflow,
    MissingPostingEntry,
    InvalidEntityType,
    InvalidFacet,
    InvalidRelationship,
    InvalidFacetOfEdge,
    InvalidClaimBody,
    InvalidPsychProfileBody,
    InvalidPersonaSnapshot,
    PersonaSnapshotConsentStale,
    InvalidCodeArtifactBody,
    InvalidBlobArtifactBody,
    InvalidLfsObject,
    InvalidNoteBody,
    InvalidWitnessMessageBody,
    InvalidAnchor,
    AnnotationThreadNotFound,
    InvalidEditManifest,
    EditRoundtripFailed,
    EditProposalAlreadySettled,
    EditProposalStale,
    SettleNotAuthorized,
    InvalidSkillBody,
    SkillEditGateRetry,
    SkillContentAnchorTypeMismatch,
    InvalidAgentDefBody,
    AgentDefinitionNotFound,
    AgentDefinitionDisabled,
    SeededAgentDefinitionConflict,
    AgentNotDispatchable,
    InvalidAgentDispatchInput,
    InvalidRecoveryArtifact,
    RecoveryArtifactQuarantineExhausted,
    InvalidCodebaseSnapshotBody,
    HostedMediaHashMatchKnownMatch,
    InvalidCodeSymbolManifestBody,
    InvalidRepoMutationRecord,
    RepoMutationFailed,
    RepoMutationRecoveryDiverged,
    InvalidPredicate,
    ReservedPredicate,
    SourceNotTrustedForAuto,
    GateWriteRejected,
    FamilyRequiresAutoGrant,
    ActorLacksClaimAuthority,
    GateConsentStale,
    MaintenanceKindNotWritable,
    StructuralKindZoneViolation,
    StructuralKindCollision,
    InvalidStructuralKindRegistration,
    InvalidAttemptQueueRecord,
    InvalidAttemptQueueTransition,
    SurfaceEventCorrelationKindCollision,
    EntityTypeImmutable,
    InvalidTimeRange,
    EdgeNotFound,
    ProvenanceOnStructuralEdge,
    ActorClassMismatch,
    InvalidProvenanceBody,
    InvalidModelSubstrate,
    EmitAdjacentReceiptRequired,
    ClaimAlreadyClosed,
    WriteVerbTargetStale,
    ClaimSelfSupersession,
    ProvenanceClaimLifecycle,
    NotAProvenanceClaim,
    ProvenanceClaimAlreadyClosed,
    ProvenanceClaimIdInUse,
    ProvenanceSubjectMismatch,
    ProvenanceSelfSupersession,
    ProvenancePrecedenceViolation,
    EdgeIsProvenanced,
    CycleDetected,
    ChildOfCardinality,
    IncompatibleAnalyzer,
    Bm25FieldSchemaChanged,
    InvalidRankProfile,
    AnalyzerAssetMissing,
    AnalyzerError,
    UpstreamToolFailure,
    #[cfg(feature = "sync")]
    CrdtDecodeError,
    #[cfg(feature = "sync")]
    WindowNotFound,
    #[cfg(feature = "sync")]
    WindowBusy,
    #[cfg(feature = "sync")]
    SyncProtocolError,
    #[cfg(feature = "sync")]
    SyncEngineError,
    #[cfg(feature = "sync")]
    MaintenanceIngestQuotaExceeded,
    InvalidRedactionReceiptBody,
    KillSwitchDisabled,
    OffRecordSessionAlreadyExists,
    OffRecordSessionNotFound,
    OffRecordSessionClosing,
    OffRecordOverlayFull,
    OffRecordOverlayLeaseClosed,
    OffRecordPromoteUnauthenticated,
    OffRecordTaintedBaseWrite,
    OffRecordWitnessDoorRejected,
    OffRecordGuestTurnRefRejected,
    OffRecordTalkOnly,
    OffRecordTurnNotInJournal,
    #[cfg(feature = "sync")]
    RedactionReceiptDivergence,
    #[cfg(feature = "sync")]
    ReceiptAttestationInvalid,
    #[cfg(feature = "sync")]
    ReceiptLeaseUnknown,
    #[cfg(feature = "sync")]
    ReceiptLeaseRevoked,
    IdentityTopologyRejected,
    IdentityTopologyUnarmed,
    IdentityProposalAmendmentOutOfScope,
    DeltaCaptureUnavailable,
    InvalidIdentityTopologyEventBody,
    ReservedEdgeKind,
    #[cfg(feature = "sync")]
    IdentityTopologyEventDivergence,
    AuthorityLogAppendOnlyViolation,
    AuthorityLogStoreKeyMismatch,
    InvalidSecretCustodyBody,
    SecretNameInUse,
    SecretCustodyNotActive,
    SecretBindingDenied,
    ManifestWidensFloor,
    SecretTierDenied,
    SecretRefNotFound,
    SecretLeaseNotFound,
    SecretLeaseNotActive,
    SecretLeasePathNotDeclared,
    SecretLeasePathConflict,
    SecretLeasePathRefused,
    SecretLeaseReceiptWriteFailed,
    InvalidSecretLeaseBody,
    InvalidSecretRotationBody,
    TaintedArtifactStale,
    MicroVmBackendUnavailable,
    MicroVmBackendError,
    MicroVmOverlayError,
    MicroVmCredentialDestinationDenied,
    RelayAttestationInvalidServiceIdentity,
    RelayAttestationClassMismatch,
    RelayAttestationEdgeServiceConflict,
    RelayHostedLegalPolicyInvalid,
    PolicyManifestInvalid,
    CodeEmissionMissingDreamerRunId,
    CodeReviewContextRequired,
    CodeReviewUnsupportedOperation,
    CodeReviewMissingReviewerRunId,
    CodeReviewRunIdNotDistinct,
    CodeReviewMissingArtifactRefs,
    CodeReviewAuthoringRunIdMismatch,
    CodeBlastRadiusMissingTouchedSymbols,
    CodeBlastRadiusUnknownSymbol,
    RelayVaultReceiptUntrusted,
    PolicyVerdictNotInForce,
    CodeMemoryInvalidAnchor,
    CodeMemoryInvalidAnchorTransfer,
    CodeMemoryBlocksCycle,
    CodeMemoryBlocksActorDenied,
    CodeMemoryBlocksSourceUntrusted,
    CodeMemoryAlwaysOnInvalid,
    CodeMemoryLimitExceeded,
    CompactionPacketRejected,
    GitHttpInvalidRepoName,
    GitHttpRepoNotFound,
    GitHttpServeFailed,
    ReceivePackDoorRejected,
    ReceivePackLandingRefused,
    VaultCleanupRestoreNotArchived,
    VaultCleanupArchiveMarkerUndecodable,
    VaultCleanupProposalNotFound,
    VaultCleanupWakeTriggerRejected,
    VaultRead,
}

/// Crate error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// LMDB-backed storage error.
    #[error("storage error: {0}")]
    Storage(heed::Error),
    /// Filesystem or operating system error.
    #[error("io error: {0}")]
    Io(std::io::Error),
    /// Vector dimension does not match vault configuration.
    #[error("dimension mismatch: expected {expected}, got {got}")]
    DimensionMismatch { expected: usize, got: usize },
    /// Vector contains NaN or infinity values.
    #[error("invalid vector component at index {index}: {value}")]
    InvalidVector { index: usize, value: f32 },
    /// Edge weight is NaN, infinite, or outside the contract range \[0, 1\]
    /// (contracts.ts `edgeKinds` weight pin; enforced on every write path).
    #[error("invalid edge weight: {value} (contract range [0, 1])")]
    InvalidEdgeWeight { value: f32 },
    /// VAD tuple contains non-finite or out-of-range values.
    #[error("invalid VAD component {component:?}: {value}")]
    InvalidVad { component: VadComponent, value: f32 },
    /// LMDB map is full and requires a larger map size.
    #[error("lmdb map is full")]
    MapFull,
    /// Invalid runtime configuration input.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// Natural-language temporal retrieval hint could not be parsed.
    #[error("invalid temporal expression: {0}")]
    InvalidTemporalExpression(TemporalExpressionParseError),
    /// Requested entity does not exist.
    #[error("entity not found")]
    EntityNotFound,
    /// A concurrent write invalidated an operation that relied on a stable snapshot.
    #[error("concurrent write detected: {0}")]
    ConcurrentWrite(&'static str),
    /// A counter or version increment exceeded supported bounds.
    #[error("arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
    /// Internal state violated an invariant that should be preserved by the crate.
    #[error("invariant violation: {0}")]
    InvariantViolation(&'static str),
    /// Encountered malformed key or value bytes.
    #[error("invalid key or value bytes")]
    InvalidKey,
    /// Index metadata or neighbor storage is internally inconsistent.
    #[error("corrupted index: {0}")]
    CorruptedIndex(&'static str),
    /// Index bookkeeping overflowed its supported range.
    #[error("index overflow: {0}")]
    IndexOverflow(&'static str),
    /// Entity type byte is not in any known range.
    #[error("invalid entity type: {0}")]
    InvalidEntityType(u8),
    /// A type-0 (CLAIM) entity body failed the pinned structural validation
    /// (D11 key set / D18 fail-closed gate). Nothing was written.
    #[error("invalid claim body: {0}")]
    InvalidClaimBody(&'static str),
    /// Occurred interval is reversed (`occurred_start > occurred_end`).
    /// The entity envelope stores an interval (ARCH-0002 / contracts.ts
    /// `entityValueEnvelope`); reversed input is rejected fail-closed, never
    /// silently repaired (M2 pinned decision D3). `start == end` is a legal
    /// point event.
    #[error("invalid time range: occurred_start {start} > occurred_end {end}")]
    InvalidTimeRange { start: u64, end: u64 },
    /// Requested edge record does not exist. The provenance path never
    /// upserts a subject edge — it would have to invent weight/created_at.
    #[error("edge not found")]
    EdgeNotFound,
    /// An upstream tool or connector call failed outside local config
    /// validation. The code is caller-safe and pre-sanitized by the adapter.
    #[error("upstream tool failure: tool={tool}, code={code}")]
    UpstreamToolFailure { tool: &'static str, code: String },
    /// Artifact-domain failure, see [`ArtifactError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// Claim-domain failure, see [`ClaimError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Claim(#[from] ClaimError),
    /// Code-domain failure, see [`CodeError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Code(#[from] CodeError),
    /// Gate-domain failure, see [`GateError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Gate(#[from] GateError),
    /// Maintenance-domain failure, see [`MaintenanceError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Maintenance(#[from] MaintenanceError),
    /// OffRecord-domain failure, see [`OffRecordError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    OffRecord(#[from] OffRecordError),
    /// Record-domain failure, see [`RecordError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// Registry-domain failure, see [`RegistryError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Relay-domain failure, see [`RelayError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// Secret-domain failure, see [`SecretError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// Store-domain failure, see [`StoreError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Sync-domain failure: CRDT windows, the sync protocol and engine,
    /// replay receipts and identity topology. Transparent, so Display and
    /// `source()` are the leaf's.
    #[error(transparent)]
    Sync(#[from] SyncError),
}

// The `#[from]` on the `Maintenance` wrapper only gives
// `From<MaintenanceError>`. The one-hop conversion every `?` on a
// `CompactionPacketError` already relied on is kept here by hand.
impl From<CompactionPacketError> for Error {
    fn from(value: CompactionPacketError) -> Self {
        Self::Maintenance(MaintenanceError::from(value))
    }
}

// `VaultRead` carries thiserror's `#[from]`, which after the move only gives
// `From<VaultReadError> for CodeError`. The one-hop conversion every `?` on a
// `VaultReadError` already relied on is kept here by hand.
impl From<crate::code_run::vault_read::VaultReadError> for Error {
    fn from(value: crate::code_run::vault_read::VaultReadError) -> Self {
        Self::Code(CodeError::VaultRead(value))
    }
}

impl Error {
    /// Constructs a typed sync protocol validation failure.
    #[cfg(feature = "sync")]
    #[must_use]
    pub fn sync_protocol(context: SyncProtocolValidation) -> Self {
        Self::Sync(SyncError::sync_protocol(context))
    }

    /// Constructs a typed sync engine failure while preserving its source.
    #[cfg(feature = "sync")]
    pub fn sync_engine<E>(context: SyncEngineContext, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Sync(SyncError::sync_engine(context, source))
    }

    /// Constructs a sync engine failure for a failed rollback after an earlier
    /// engine/storage operation had already failed.
    #[cfg(feature = "sync")]
    pub fn sync_engine_rollback<Operation, Rollback>(
        context: SyncEngineContext,
        operation: Operation,
        rollback: Rollback,
    ) -> Self
    where
        Operation: StdError + Send + Sync + 'static,
        Rollback: StdError + Send + Sync + 'static,
    {
        Self::Sync(SyncError::sync_engine_rollback(
            context, operation, rollback,
        ))
    }

    /// Returns the typed Gate denial taxonomy for
    /// [`GateError::GateWriteRejected`].
    #[must_use]
    pub fn gate_denial(&self) -> Option<GateDenial> {
        match self {
            Self::Gate(inner) => inner.gate_denial(),
            _ => None,
        }
    }

    pub(crate) fn invalid_vector_component(vector: &[f32]) -> Option<Self> {
        vector
            .iter()
            .copied()
            .enumerate()
            .find_map(|(index, value)| {
                (!value.is_finite()).then_some(Self::InvalidVector { index, value })
            })
    }

    /// Returns the stable category for this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Storage(_) => ErrorKind::Storage,
            Self::Io(_) => ErrorKind::Io,
            Self::DimensionMismatch { .. } => ErrorKind::DimensionMismatch,
            Self::InvalidVector { .. } => ErrorKind::InvalidVector,
            Self::InvalidEdgeWeight { .. } => ErrorKind::InvalidEdgeWeight,
            Self::InvalidVad { .. } => ErrorKind::InvalidVad,
            Self::MapFull => ErrorKind::MapFull,
            Self::InvalidConfig(_) => ErrorKind::InvalidConfig,
            Self::InvalidTemporalExpression(_) => ErrorKind::InvalidTemporalExpression,
            Self::EntityNotFound => ErrorKind::EntityNotFound,
            Self::ConcurrentWrite(_) => ErrorKind::ConcurrentWrite,
            Self::ArithmeticOverflow(_) => ErrorKind::ArithmeticOverflow,
            Self::InvariantViolation(_) => ErrorKind::InvariantViolation,
            Self::InvalidKey => ErrorKind::InvalidKey,
            Self::CorruptedIndex(_) => ErrorKind::CorruptedIndex,
            Self::IndexOverflow(_) => ErrorKind::IndexOverflow,
            Self::InvalidEntityType(_) => ErrorKind::InvalidEntityType,
            Self::InvalidClaimBody(_) => ErrorKind::InvalidClaimBody,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::EdgeNotFound => ErrorKind::EdgeNotFound,
            Self::UpstreamToolFailure { .. } => ErrorKind::UpstreamToolFailure,
            Self::Artifact(inner) => inner.kind(),
            Self::Claim(inner) => inner.kind(),
            Self::Code(inner) => inner.kind(),
            Self::Gate(inner) => inner.kind(),
            Self::Maintenance(inner) => inner.kind(),
            Self::OffRecord(inner) => inner.kind(),
            Self::Record(inner) => inner.kind(),
            Self::Registry(inner) => inner.kind(),
            Self::Relay(inner) => inner.kind(),
            Self::Secret(inner) => inner.kind(),
            Self::Store(inner) => inner.kind(),
            Self::Sync(inner) => inner.kind(),
        }
    }

    /// Returns whether retrying the same operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConcurrentWrite(_) => true,
            Self::UpstreamToolFailure { .. } => true,
            // ONE-1449: the gate committed nothing, so the same call over a
            // settled ledger is the whole remedy. This is the one arm a
            // scheduler reads to tell "retry me" from "answered no".
            Self::Artifact(ArtifactError::SkillEditGateRetry(_)) => true,
            // Transient by construction: the refusal clears once the last
            // external window handle drops (ONE-1150).
            #[cfg(feature = "sync")]
            Self::Sync(SyncError::WindowBusy { .. }) => true,
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
            ),
            _ => false,
        }
    }
}

impl From<heed::Error> for Error {
    fn from(value: heed::Error) -> Self {
        match value {
            heed::Error::Mdb(heed::MdbError::MapFull) => Self::MapFull,
            other => Self::Storage(other),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

// Compile-time assertion that Error: Send + Sync + 'static.
// Ungated (runs in all profiles); replaces the previous runtime test
// that was gated behind #[cfg(all(test, feature = "sync"))].
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Error>();
};
