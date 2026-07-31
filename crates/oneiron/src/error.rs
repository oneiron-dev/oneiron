#[cfg(feature = "sync")]
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

use crate::affect::VadComponent;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::registry::{ENTITY_TYPE_FACET, TypeByteBand};
use crate::temporal::TemporalExpressionParseError;

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable Gate rejection outcome for typed caller handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateDenialOutcome {
    Pending,
    Deny,
}

impl GateDenialOutcome {
    /// Stable string used in audit logs and existing [`Error::GateWriteRejected`] fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Deny => "deny",
        }
    }

    /// Parses the stable string form used by [`Error::GateWriteRejected`].
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for GateDenialOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable Gate rejection reason for typed caller handling and audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateDenialReason {
    DenyMissingActorClass,
    DenyMissingActorProvenance,
    DenyMissingPolicyManifestVersion,
    DenyPolicyFailClosed,
    PendingActorCeiling,
    PendingSourceTrust,
    PendingCriticalityFloor,
    PendingPolicyManifestAuthority,
    PendingExternalEffectAuthority,
}

impl GateDenialReason {
    /// Stable `gate.*` code used in audit logs and existing [`Error::GateWriteRejected`] fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DenyMissingActorClass => "gate.deny.missing_actor_class",
            Self::DenyMissingActorProvenance => "gate.deny.missing_actor_provenance",
            Self::DenyMissingPolicyManifestVersion => "gate.deny.missing_policy_manifest_version",
            Self::DenyPolicyFailClosed => "gate.deny.policy_fail_closed",
            Self::PendingActorCeiling => "gate.pending.actor_ceiling",
            Self::PendingSourceTrust => "gate.pending.source_trust",
            Self::PendingCriticalityFloor => "gate.pending.criticality_floor",
            Self::PendingPolicyManifestAuthority => "gate.pending.policy_manifest_authority",
            Self::PendingExternalEffectAuthority => "gate.pending.external_effect_authority",
        }
    }

    /// Parses a stable `gate.*` reason code.
    #[must_use]
    pub fn from_code(value: &str) -> Option<Self> {
        match value {
            "gate.deny.missing_actor_class" => Some(Self::DenyMissingActorClass),
            "gate.deny.missing_actor_provenance" => Some(Self::DenyMissingActorProvenance),
            "gate.deny.missing_policy_manifest_version" => {
                Some(Self::DenyMissingPolicyManifestVersion)
            }
            "gate.deny.policy_fail_closed" => Some(Self::DenyPolicyFailClosed),
            "gate.pending.actor_ceiling" => Some(Self::PendingActorCeiling),
            "gate.pending.source_trust" => Some(Self::PendingSourceTrust),
            "gate.pending.criticality_floor" => Some(Self::PendingCriticalityFloor),
            "gate.pending.policy_manifest_authority" => Some(Self::PendingPolicyManifestAuthority),
            "gate.pending.external_effect_authority" => Some(Self::PendingExternalEffectAuthority),
            _ => None,
        }
    }

    /// Outcome associated with this rejection reason.
    #[must_use]
    pub fn outcome(self) -> GateDenialOutcome {
        match self {
            Self::DenyMissingActorClass
            | Self::DenyMissingActorProvenance
            | Self::DenyMissingPolicyManifestVersion
            | Self::DenyPolicyFailClosed => GateDenialOutcome::Deny,
            Self::PendingActorCeiling
            | Self::PendingSourceTrust
            | Self::PendingCriticalityFloor
            | Self::PendingPolicyManifestAuthority
            | Self::PendingExternalEffectAuthority => GateDenialOutcome::Pending,
        }
    }
}

impl fmt::Display for GateDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed view over [`Error::GateWriteRejected`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDenial {
    outcome: GateDenialOutcome,
    reason_codes: Vec<GateDenialReason>,
}

impl GateDenial {
    /// Gate rejection outcome.
    #[must_use]
    pub fn outcome(&self) -> GateDenialOutcome {
        self.outcome
    }

    /// Stable Gate rejection reasons.
    #[must_use]
    pub fn reason_codes(&self) -> &[GateDenialReason] {
        &self.reason_codes
    }
}

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
    InvalidCounterpartyContactBody,
    InvalidCommRecordBody,
    InvalidDisclosureScope,
    DisclosureClampViolation,
    InvalidTaskBody,
    CorruptedIndex,
    ContextPackValidation,
    IndexOverflow,
    MissingPostingEntry,
    InvalidEntityType,
    InvalidFacet,
    InvalidFacetOfEdge,
    InvalidClaimBody,
    InvalidPsychProfileBody,
    InvalidPersonaSnapshot,
    PersonaSnapshotConsentStale,
    InvalidCodeArtifactBody,
    InvalidBlobArtifactBody,
    InvalidAnchor,
    AnnotationThreadNotFound,
    InvalidEditManifest,
    EditRoundtripFailed,
    EditProposalAlreadySettled,
    EditProposalStale,
    SettleNotAuthorized,
    InvalidSkillBody,
    InvalidAgentDefBody,
    SystemAgentDisabled,
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
    GateConsentStale,
    MaintenanceKindNotWritable,
    StructuralKindBandViolation,
    StructuralKindCollision,
    InvalidStructuralKindRegistration,
    InvalidAttemptQueueRecord,
    InvalidAttemptQueueTransition,
    EntityTypeImmutable,
    InvalidTimeRange,
    EdgeNotFound,
    ProvenanceOnStructuralEdge,
    ActorClassMismatch,
    InvalidProvenanceBody,
    InvalidModelSubstrate,
    EmitAdjacentReceiptRequired,
    ClaimAlreadyClosed,
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
    OffRecordTurnNotFenced,
    OffRecordPromoteUnauthenticated,
    OffRecordFencedTurnWriteRejected,
    OffRecordTalkOnly,
    OffRecordExportRefused,
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
    InvalidIdentityTopologyEventBody,
    ReservedEdgeKind,
    #[cfg(feature = "sync")]
    IdentityTopologyEventDivergence,
}

/// Sync configuration field rejected by protocol setup validation.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncConfigField {
    EphemeralTimeoutMs,
    MaxEphemeralPayloadBytes,
    MaxEphemeralSnapshotBytes,
}

#[cfg(feature = "sync")]
impl SyncConfigField {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EphemeralTimeoutMs => "ephemeral_timeout_ms",
            Self::MaxEphemeralPayloadBytes => "max_ephemeral_payload_bytes",
            Self::MaxEphemeralSnapshotBytes => "max_ephemeral_snapshot_bytes",
        }
    }
}

#[cfg(feature = "sync")]
impl fmt::Display for SyncConfigField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable selector-validation reason for sync protocol failures.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncSelectorValidation {
    TooLarge,
    RequestTooShort,
    Length,
    LengthOverflow,
    RequestTruncated,
    MessagePackEncode,
    Decode,
    TrailingBytes,
    MustBeMap,
    UnsupportedSchemaVersion,
    GrantNotFound,
    GrantHeader,
    GrantWrongType,
    GrantScopeMismatch,
    MemberNotGranted,
    GrantInactive,
    WorldMustBeMap,
    WorldKind,
    AllWorldHasExtraFields,
    BaseWorldHasExtraFields,
    ForeignWorldId,
    UnknownWorldKind,
    KeyMustBeString,
    UnknownKey,
    DuplicateKey,
    MissingKey,
    WorldKey,
    WorldUnknownKey,
    WorldDuplicateKey,
    WorldMissingKey,
    MissingRequiredValue,
    EntityIdMustBeHex,
    InvalidEntityId,
    EntityListMustBeArray,
    BandsMustBeArray,
    BandMustBeString,
    UnknownBand,
}

#[cfg(feature = "sync")]
impl SyncSelectorValidation {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "sync selector too large",
            Self::RequestTooShort => "sync selector request too short",
            Self::Length => "sync selector length",
            Self::LengthOverflow => "sync selector length overflow",
            Self::RequestTruncated => "sync selector request truncated",
            Self::MessagePackEncode => "sync selector MessagePack encode failed",
            Self::Decode => "sync selector decode",
            Self::TrailingBytes => "sync selector trailing bytes",
            Self::MustBeMap => "sync selector must be a map",
            Self::UnsupportedSchemaVersion => "sync selector unsupported schema version",
            Self::GrantNotFound => "sync selector grant not found",
            Self::GrantHeader => "sync selector grant header",
            Self::GrantWrongType => "sync selector grant wrong type",
            Self::GrantScopeMismatch => "sync selector grant scope mismatch",
            Self::MemberNotGranted => "sync selector member not granted",
            Self::GrantInactive => "sync selector grant inactive",
            Self::WorldMustBeMap => "sync selector world must be a map",
            Self::WorldKind => "sync selector world kind",
            Self::AllWorldHasExtraFields => "sync selector all world has extra fields",
            Self::BaseWorldHasExtraFields => "sync selector base world has extra fields",
            Self::ForeignWorldId => "sync selector foreign world id",
            Self::UnknownWorldKind => "sync selector unknown world kind",
            Self::KeyMustBeString => "sync selector key must be string",
            Self::UnknownKey => "sync selector unknown key",
            Self::DuplicateKey => "sync selector duplicate key",
            Self::MissingKey => "sync selector missing key",
            Self::WorldKey => "sync selector world key",
            Self::WorldUnknownKey => "sync selector world unknown key",
            Self::WorldDuplicateKey => "sync selector world duplicate key",
            Self::WorldMissingKey => "sync selector world missing key",
            Self::MissingRequiredValue => "sync selector missing required value",
            Self::EntityIdMustBeHex => "sync selector entity id must be hex",
            Self::InvalidEntityId => "sync selector invalid entity id",
            Self::EntityListMustBeArray => "sync selector entity list must be array",
            Self::BandsMustBeArray => "sync selector bands must be array",
            Self::BandMustBeString => "sync selector band must be string",
            Self::UnknownBand => "sync selector unknown band",
        }
    }
}

#[cfg(feature = "sync")]
impl fmt::Display for SyncSelectorValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sync protocol row family guarded by a scoped prune.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncProtocolPruneScope {
    WindowUpdateRows,
    SweepUpdateRows,
}

/// Typed validation context for sync protocol failures.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncProtocolValidation {
    InvalidConfig {
        field: SyncConfigField,
    },
    Selector {
        reason: SyncSelectorValidation,
    },
    ScopedPrune {
        scope: SyncProtocolPruneScope,
        prefix: String,
        key: String,
    },
    SweepSnapshotRace,
    SweepUpdateRowsRace,
    FederatedTombstoneAdmission,
    TombstoneRemovalDelta,
}

#[cfg(feature = "sync")]
impl fmt::Display for SyncProtocolValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => write!(f, "{field} must be positive"),
            Self::Selector { reason } => write!(f, "{reason}"),
            Self::ScopedPrune { scope, prefix, key } => match scope {
                SyncProtocolPruneScope::WindowUpdateRows => {
                    write!(
                        f,
                        "u:w: prune scoped to {prefix}* refused foreign key {key}"
                    )
                }
                SyncProtocolPruneScope::SweepUpdateRows => write!(
                    f,
                    "sweep u:w: prune scoped to {prefix}* refused foreign key {key}"
                ),
            },
            Self::SweepSnapshotRace => {
                f.write_str("sweep raced: d:w: snapshot changed between read and write")
            }
            Self::SweepUpdateRowsRace => {
                f.write_str("sweep raced: u:w: row set changed between read and write")
            }
            Self::FederatedTombstoneAdmission => {
                f.write_str("federated tombstone updates require delete admission")
            }
            Self::TombstoneRemovalDelta => {
                f.write_str("tombstone removal delta (tombstones are permanent)")
            }
        }
    }
}

/// Local sync engine operation that failed under the protocol layer.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncEngineContext {
    LoroMapInsert,
    LoroMapDelete,
    LoroExportAllUpdates,
    LoroExportUpdates,
    LoroExportSnapshot,
    LoroExportShallowSnapshot,
    LoroSetPeerId,
    LoroRevert,
    RebootstrapEncode,
    DreamerProgressTransport,
}

#[cfg(feature = "sync")]
impl SyncEngineContext {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoroMapInsert => "loro map insert",
            Self::LoroMapDelete => "loro map delete",
            Self::LoroExportAllUpdates => "loro export all updates",
            Self::LoroExportUpdates => "loro export updates",
            Self::LoroExportSnapshot => "loro export snapshot",
            Self::LoroExportShallowSnapshot => "loro export shallow snapshot",
            Self::LoroSetPeerId => "loro set peer id",
            Self::LoroRevert => "loro revert",
            Self::RebootstrapEncode => "re-bootstrap encode",
            Self::DreamerProgressTransport => "dreamer progress transport",
        }
    }
}

#[cfg(feature = "sync")]
impl fmt::Display for SyncEngineContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source error for rollback failures that occur after an earlier sync engine
/// operation already failed.
#[cfg(feature = "sync")]
#[derive(Debug)]
pub struct SyncRollbackError {
    operation: Box<dyn StdError + Send + Sync + 'static>,
    rollback: Box<dyn StdError + Send + Sync + 'static>,
}

#[cfg(feature = "sync")]
impl SyncRollbackError {
    #[must_use]
    pub fn new<Operation, Rollback>(operation: Operation, rollback: Rollback) -> Self
    where
        Operation: StdError + Send + Sync + 'static,
        Rollback: StdError + Send + Sync + 'static,
    {
        Self {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        }
    }

    #[must_use]
    pub fn operation(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self.operation.as_ref()
    }

    #[must_use]
    pub fn rollback(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self.rollback.as_ref()
    }
}

#[cfg(feature = "sync")]
impl fmt::Display for SyncRollbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "operation failed: {}; rollback failed: {}",
            self.operation, self.rollback
        )
    }
}

#[cfg(feature = "sync")]
impl StdError for SyncRollbackError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.rollback)
    }
}

/// LMDB file inside a vault root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultRootEntry {
    Data,
    Lock,
}

impl VaultRootEntry {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::Data => "data.mdb",
            Self::Lock => "lock.mdb",
        }
    }
}

impl fmt::Display for VaultRootEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_name())
    }
}

/// Typed reason a vault root failed the filesystem preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultRootProblem {
    /// A live store already owns the same root or an aliased LMDB file.
    DuplicateOpenRoot { open_path: PathBuf },
    /// Only one of LMDB's paired environment files exists.
    IncompleteLmdbPair {
        present: VaultRootEntry,
        missing: VaultRootEntry,
    },
    /// An LMDB environment file is not a regular file.
    NonRegularEntry { entry: VaultRootEntry },
    /// An LMDB environment file is a symlink.
    SymlinkEntry { entry: VaultRootEntry },
    /// `data.mdb` and `lock.mdb` point at the same underlying file.
    AliasedLmdbFiles {
        first: VaultRootEntry,
        second: VaultRootEntry,
    },
    /// A hard-linked LMDB file can make multiple filesystem roots name one
    /// vault. Those roots cannot safely own separate LMDB environments.
    MultipleHardLinks {
        entry: VaultRootEntry,
        link_count: u64,
    },
    /// This platform cannot report stable file identity and hard-link counts
    /// for existing LMDB environment files.
    UnsupportedPlatform { entry: VaultRootEntry },
}

impl fmt::Display for VaultRootProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateOpenRoot { open_path } => {
                write!(f, "duplicates live vault root {}", open_path.display())
            }
            Self::IncompleteLmdbPair { present, missing } => {
                write!(f, "found {present} without {missing}")
            }
            Self::NonRegularEntry { entry } => {
                write!(f, "{entry} is not a regular file")
            }
            Self::SymlinkEntry { entry } => {
                write!(f, "{entry} is a symlink")
            }
            Self::AliasedLmdbFiles { first, second } => {
                write!(f, "{first} and {second} refer to the same file")
            }
            Self::MultipleHardLinks { entry, link_count } => {
                write!(f, "{entry} has {link_count} hard links")
            }
            Self::UnsupportedPlatform { entry } => {
                write!(f, "{entry} cannot be safely preflighted on this platform")
            }
        }
    }
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
    /// Stored embedding model differs from requested model.
    #[error("embedding model changed: stored={stored}, requested={requested}")]
    EmbeddingModelChanged { stored: String, requested: String },
    /// Persisted HNSW config differs from the requested runtime config.
    #[error("hnsw config changed: stored={stored}, requested={requested}")]
    HnswConfigChanged { stored: String, requested: String },
    /// The vault was created with a different storage ABI. This gates
    /// on-disk edge-kind discriminants, edge value layouts, and entity type
    /// bytes before callers can silently decode them incorrectly.
    #[error("storage ABI version changed: stored={stored:?}, current={current}")]
    StorageAbiVersionChanged { stored: Option<u16>, current: u16 },
    /// The vault's DB-level schema version is not handled by this build. A
    /// future migration runner can use this as its dispatch point.
    #[error("storage schema version changed: stored={stored:?}, current={current}")]
    StorageSchemaVersionChanged { stored: Option<u16>, current: u16 },
    /// The LMDB named database set does not match the ARCH-0019 manifest.
    #[error("DB manifest mismatch: missing={missing:?}, unexpected={unexpected:?}")]
    DbManifestMismatch {
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
    /// The vault root failed deterministic filesystem preflight before LMDB open.
    #[error("vault root preflight failed at {}: {problem}", path.display())]
    VaultRootPreflight {
        path: PathBuf,
        problem: VaultRootProblem,
    },
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
    /// AccessGrant creation attempted to reuse an existing entity id.
    #[error("access grant already exists")]
    AccessGrantAlreadyExists,
    /// StandingOutboundGrant creation attempted to reuse an existing entity id.
    #[error("outbound grant already exists")]
    OutboundGrantAlreadyExists,
    /// ConnectorKey registration attempted to reuse an existing entity id or
    /// an existing non-revoked `(connector, actor_entity_ref)` tuple.
    #[error("connector key already exists")]
    ConnectorKeyAlreadyExists,
    /// ChannelIdentity creation attempted to reuse an existing id or assignment key.
    #[error("channel identity already exists")]
    ChannelIdentityAlreadyExists,
    /// CounterpartyContact creation attempted to reuse an existing id or
    /// (identity_ref, counterparty) key.
    #[error("counterparty contact already exists")]
    CounterpartyContactAlreadyExists,
    /// Companion register creation attempted to reuse an existing id or key.
    #[error("companion record already exists")]
    CompanionRecordAlreadyExists,
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
    /// A FEDERATION_GRANT (type 124) body failed structural validation.
    #[error("invalid federation grant body: {0}")]
    InvalidFederationGrantBody(&'static str),
    #[error("invalid authority log body: {0}")]
    InvalidAuthorityLogBody(&'static str),
    /// Index metadata or neighbor storage is internally inconsistent.
    #[error("corrupted index: {0}")]
    CorruptedIndex(&'static str),
    /// Context-pack assembly found a cross-record anomaly before surfacing output.
    #[error("context pack validation failed for entity {}: {reason}", id.to_hex())]
    ContextPackValidation { id: EntityId, reason: &'static str },
    /// Index bookkeeping overflowed its supported range.
    #[error("index overflow: {0}")]
    IndexOverflow(&'static str),
    /// Expected posting or metadata row is missing from an index.
    #[error("missing posting entry")]
    MissingPostingEntry,
    /// Entity type byte is not in any known range.
    #[error("invalid entity type: {0}")]
    InvalidEntityType(u8),
    /// The active facet supplied to the retrieval pipeline does not resolve to
    /// an EXISTING FACET entity (type byte 13, per contracts.ts §1). Rejected
    /// fail-closed at query setup: a bogus id (`found = None`, no such entity)
    /// or an id whose type byte is not FACET (`found = Some(other_type)`) is a
    /// typed error, never a silent treat-everything-as-other-facet. Strict
    /// mode must never drop every scoped claim because the active facet was
    /// invalid. Nothing is queried.
    #[error(
        "invalid active facet {}: resolved type {found:?}, expected FACET ({ENTITY_TYPE_FACET})",
        facet.to_hex()
    )]
    InvalidFacet { facet: EntityId, found: Option<u8> },
    /// A public `FacetOf` (u8 17) edge write failed the ONE-1645 write-time
    /// type table: the source must be an existing CLAIM or TURN and the target
    /// an existing FACET. A missing endpoint row is unknowable-typed
    /// (`None`) and rejected on the same footing as a wrong type — a facet
    /// stamp's endpoints must be established facts before the stamp. The batch
    /// aborts atomically; nothing was written.
    #[error(
        "invalid FacetOf edge {} (type {src_type:?}) -> {} (type {tgt_type:?}): expected CLAIM/TURN -> FACET",
        src.to_hex(),
        tgt.to_hex()
    )]
    InvalidFacetOfEdge {
        src: EntityId,
        src_type: Option<u8>,
        tgt: EntityId,
        tgt_type: Option<u8>,
    },
    /// A type-0 (CLAIM) entity body failed the pinned structural validation
    /// (D11 key set / D18 fail-closed gate). Nothing was written.
    #[error("invalid claim body: {0}")]
    InvalidClaimBody(&'static str),
    /// A PSYCH_PROFILE entity body failed pinned structural validation.
    /// Nothing was written.
    #[error("invalid psych profile body: {0}")]
    InvalidPsychProfileBody(&'static str),
    /// A persona snapshot compile/export input (OF-325) failed pinned
    /// validation — malformed export record body, blank consent grantor,
    /// blank agent-take attribution, or a strike-list that names unknown
    /// rows. Nothing was written.
    #[error("invalid persona snapshot: {0}")]
    InvalidPersonaSnapshot(&'static str),
    /// A persona snapshot export presented consent bound to a different
    /// compile stamp than the compile being exported (OF-325: consent is
    /// content-addressed to the previewed compile; a recompile invalidates
    /// prior consent). Nothing was written.
    #[error(
        "persona snapshot export consent is stale: consent bound to {consent_stamp}, compile stamp is {compile_stamp}"
    )]
    PersonaSnapshotConsentStale {
        consent_stamp: String,
        compile_stamp: String,
    },
    /// A CODE_ARTIFACT entity body failed the pinned replay-key validation.
    /// Nothing was written.
    #[error("invalid CODE artifact body: {0}")]
    InvalidCodeArtifactBody(&'static str),
    /// A BLOB_ARTIFACT entity body or version record failed pinned
    /// structural validation. Nothing was written.
    #[error("invalid BLOB artifact body: {0}")]
    InvalidBlobArtifactBody(&'static str),
    /// An anchored-annotation anchor or locator failed structural validation.
    /// Nothing was written.
    #[error("invalid anchor: {0}")]
    InvalidAnchor(&'static str),
    /// The referenced anchored-annotation thread does not exist on the
    /// artifact. Nothing was written.
    #[error("anchored-annotation thread not found")]
    AnnotationThreadNotFound,
    /// An ARTL-3 edit manifest failed encode, decode, or schema validation.
    #[error("invalid edit manifest: {0}")]
    InvalidEditManifest(&'static str),
    /// An ARTL-3 edit round-trip stage failed: unreadable OPC package,
    /// malformed cell reference, or a session-side failure. The input bytes
    /// are never mutated.
    #[error("edit round-trip failed: {0}")]
    EditRoundtripFailed(&'static str),
    /// An ARTL-4 settle (select or discard) targeted an `EditProposal` that was
    /// already settled — settlement is consume-once (OF-368 D5/D6): exactly one
    /// of select or discard consumes a retained output, and a second settle of
    /// any kind is refused. The prior outcome (`selected` / `discarded`) is
    /// reported. Nothing was written.
    #[error("edit proposal already settled: prior outcome was {outcome}")]
    EditProposalAlreadySettled { outcome: &'static str },
    /// An ARTL-4 settle-select targeted a proposal whose base no longer matches
    /// the artifact head — an intervening edit moved the head since the proposal
    /// was produced (OF-368 D5). Committing these bytes would clobber the
    /// intervening version and replay a stale manifest onto newer anchors, so
    /// the settle is refused. Nothing was written.
    #[error("edit proposal is stale: its base no longer matches the artifact head")]
    EditProposalStale,
    /// An ARTL-4 settle was not authorized: standing-grant consent found no
    /// covering brief×verb-class bundle grant (OF-368 D6). Fail-closed —
    /// nothing was written.
    #[error("settle not authorized: {0}")]
    SettleNotAuthorized(&'static str),
    /// A SKILL entity body failed pinned reliability/provenance validation.
    /// Nothing was written.
    #[error("invalid SKILL body: {0}")]
    InvalidSkillBody(&'static str),
    /// An AGENT_DEF entity body failed pinned structural/lifecycle validation
    /// or the update-immutability gate. Nothing was written.
    #[error("invalid AGENT_DEF body: {0}")]
    InvalidAgentDefBody(&'static str),
    /// A fork or dispatch targeted a system-agent preset that is toggled off
    /// on this vault. Nothing was written.
    #[error("system agent preset disabled: {0}")]
    SystemAgentDisabled(&'static str),
    /// A dispatch target failed the dispatchability predicate. Nothing was
    /// enqueued.
    #[error("agent not dispatchable: {0}")]
    AgentNotDispatchable(&'static str),
    /// An agent dispatch payload input failed pinned structural validation.
    #[error("invalid agent dispatch input: {0}")]
    InvalidAgentDispatchInput(&'static str),
    /// An AccessGrant control-plane record failed pinned structural
    /// validation. Nothing was written.
    #[error("invalid access grant body: {0}")]
    InvalidAccessGrantBody(&'static str),
    /// A StandingOutboundGrant record failed pinned structural validation.
    /// Nothing was written.
    #[error("invalid outbound grant body: {0}")]
    InvalidOutboundGrantBody(&'static str),
    /// A CONNECTOR_KEY record (or one of its budget rows / lifecycle
    /// transitions) failed pinned structural validation. Nothing was written.
    #[error("invalid connector key body: {0}")]
    InvalidConnectorKeyBody(&'static str),
    /// A connector charter failed deterministic compilation (GOV-10).
    /// Fail-closed: nothing was staged.
    #[error("connector charter compile failed at line {line_number}: {message}")]
    ConnectorCharterCompile { line_number: u32, message: String },
    /// A charter approve re-presented a compiled hash that does not match
    /// the staged proposal. Enforcement is unchanged.
    #[error("connector charter approval hash mismatch")]
    ConnectorCharterApprovalMismatch,
    /// A charter approve/discard found no staged proposal on the key.
    #[error("connector charter proposal not found")]
    ConnectorCharterMissing,
    /// A ChannelIdentity record failed pinned structural validation.
    /// Nothing was written.
    #[error("invalid channel identity body: {0}")]
    InvalidChannelIdentityBody(&'static str),
    /// A CounterpartyContact record failed pinned structural validation.
    /// Nothing was written.
    #[error("invalid counterparty contact body: {0}")]
    InvalidCounterpartyContactBody(&'static str),
    /// A COMM_RECORD body failed pinned structural validation. Nothing was
    /// written.
    #[error("invalid comm record body: {0}")]
    InvalidCommRecordBody(&'static str),
    /// A DisclosureScope body failed pinned structural validation. Nothing
    /// was written.
    #[error("invalid disclosure scope: {0}")]
    InvalidDisclosureScope(&'static str),
    /// A non-admitted entity survived into an assembled context pack. The
    /// pack build FAILS rather than leaks (OF-365 fail-closed sweep).
    #[error("disclosure clamp violation: {0}")]
    DisclosureClampViolation(&'static str),
    /// A TASK record failed pinned role-field validation. Nothing was written.
    #[error("invalid TASK body: {0}")]
    InvalidTaskBody(&'static str),
    /// A recovery artifact shell failed magic, version, length, or checksum
    /// validation before its payload could be used.
    #[error("invalid recovery artifact: {0}")]
    InvalidRecoveryArtifact(&'static str),
    /// A recovery artifact was invalid, but every sibling `.invalid-N`
    /// quarantine target was occupied.
    #[error(
        "recovery artifact quarantine suffix space exhausted for {}",
        path.display()
    )]
    RecoveryArtifactQuarantineExhausted { path: PathBuf },
    /// A CODE_ARTIFACT codebase snapshot sidecar failed pinned structural
    /// validation. Nothing was written.
    #[error("invalid codebase snapshot body: {0}")]
    InvalidCodebaseSnapshotBody(&'static str),
    /// A hosted-media hash-match provider reported a known match. Nothing was
    /// written; provider metadata is preserved for incident handling.
    #[error(
        "hosted media hash-match known match: provider={provider:?}, reference={reference:?}, path={path:?}, content_hash={}",
        bytes_to_hex_lower(content_hash.as_ref())
    )]
    HostedMediaHashMatchKnownMatch {
        provider: Box<str>,
        reference: Box<str>,
        path: Box<str>,
        content_hash: Box<[u8; 32]>,
    },
    /// A CODE_ARTIFACT symbol/chunk sidecar failed pinned structural
    /// validation. Nothing was written.
    #[error("invalid code symbol manifest body: {0}")]
    InvalidCodeSymbolManifestBody(&'static str),
    /// A repo mutation queue request or persisted oplog row failed pinned
    /// structural validation. Nothing was written.
    #[error("invalid repo mutation record: {0}")]
    InvalidRepoMutationRecord(&'static str),
    /// A serialized repo mutation reached the git/worktree layer and failed.
    #[error("repo mutation failed: {0}")]
    RepoMutationFailed(String),
    /// A prepared repo mutation cannot be recovered automatically because the
    /// current repo state matches neither side of its write-ahead intent.
    #[error(
        "repo mutation recovery diverged for sequence {seq}; current state matches neither the recorded pre-state nor expected post-state"
    )]
    RepoMutationRecoveryDiverged {
        seq: u64,
        pre_action_fork_hash: Box<[u8; 32]>,
        expected_post_action_fork_hash: Option<Box<[u8; 32]>>,
        actual_fork_hash: Box<[u8; 32]>,
    },
    /// Claim predicate violates the pinned D17 grammar (≥2 segments of
    /// `[a-z][a-z0-9_]*` joined by `.`, total ≤128 bytes).
    #[error("invalid claim predicate {predicate:?}: {reason}")]
    InvalidPredicate {
        predicate: String,
        reason: &'static str,
    },
    /// Claim predicate lives in the reserved `edge.*` namespace, which only
    /// the engine's internal provenance path may write (D17).
    #[error("reserved claim predicate namespace: {predicate:?}")]
    ReservedPredicate { predicate: String },
    /// The source-trust ceiling does not explicitly permit this provenance
    /// source to write an auto-approved Claim. Route the write through the
    /// proposed/inbox review path instead of silently auto-approving it.
    #[error(
        "claim source {claim_source} is not trusted for auto approval; route as proposed/inbox review"
    )]
    SourceNotTrustedForAuto { claim_source: &'static str },
    /// The Gate evaluator rejected a local write before persistence. The
    /// outcome is `pending` or `deny`, and `reason_codes` are stable
    /// `gate.*` strings suitable for caller routing and audit breadcrumbs.
    /// [`Error::gate_denial`] exposes the same fields as typed taxonomy values.
    #[error("gate write rejected: outcome={outcome}, reasons={reason_codes:?}")]
    GateWriteRejected {
        outcome: &'static str,
        reason_codes: Vec<&'static str>,
    },
    /// A pending consent approval attempted to approve bytes or a policy
    /// read-frontier different from the original pending Gate decision.
    #[error("gate consent approval is stale for claim {}", claim_id.to_hex())]
    GateConsentStale { claim_id: EntityId },
    /// Registered maintenance-band entity kind (type bytes 120+, e.g.
    /// REDACTION_AUDIT) rejected on a public write path. Maintenance records
    /// are engine-authored only; this is distinct from
    /// [`Error::InvalidEntityType`], which covers genuinely unknown bytes.
    #[error("maintenance entity kind {0} is engine-authored and not writable via the public API")]
    MaintenanceKindNotWritable(u8),
    /// Pack StructuralKind registration claimed a byte outside its declared
    /// band or inside a band the runtime registry must not allocate.
    #[error(
        "structural kind band violation for type byte {type_byte}: declared={declared_band:?}, actual={actual_band:?}: {reason}"
    )]
    StructuralKindBandViolation {
        type_byte: u8,
        declared_band: TypeByteBand,
        actual_band: TypeByteBand,
        reason: &'static str,
    },
    /// Pack StructuralKind registration collided with an existing type byte.
    #[error("structural kind type-byte collision: {0}")]
    StructuralKindTypeByteCollision(u8),
    /// Pack StructuralKind registration collided with an existing short-id prefix.
    #[error("structural kind short-id prefix collision: {0:?}")]
    StructuralKindPrefixCollision(String),
    /// Pack StructuralKind registration failed boundary vetting.
    #[error("invalid structural kind registration: {0}")]
    InvalidStructuralKindRegistration(&'static str),
    /// An AttemptQueue input or persisted record failed structural validation.
    #[error("invalid attempt queue record: {0}")]
    InvalidAttemptQueueRecord(&'static str),
    /// An AttemptQueue lifecycle operation was requested from a valid but
    /// incompatible state. This is caller-visible transition rejection, not
    /// persisted-record corruption.
    #[error("invalid attempt queue transition: action={action}, state={state}")]
    InvalidAttemptQueueTransition {
        action: &'static str,
        state: &'static str,
    },
    /// The type byte of an existing entity record is immutable on re-put
    /// (M2 pinned decision D2). The short-id prefix is derived from the type
    /// byte at first insert, so re-typing would leave the record addressed
    /// under another type's prefix. Delete-and-recreate is the escape hatch.
    #[error(
        "entity type is immutable: entity {} has type {existing}, re-put attempted type {attempted}",
        id.to_hex()
    )]
    EntityTypeImmutable {
        id: EntityId,
        existing: u8,
        attempted: u8,
    },
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
    /// `edge.provenance` may only attach to SEMANTIC edge kinds; structural
    /// kinds (12-byte layout) never carry the two hot flags.
    #[error("edge.provenance subject kind {kind} is structural, not semantic")]
    ProvenanceOnStructuralEdge { kind: u8 },
    /// The caller-supplied `actor_class` is incompatible with the actor
    /// entity's kind (D13: PERSON → human|agent, MACHINE → system, anything
    /// else is never an actor). The engine never defaults an actor class.
    #[error("actor class {actor_class} is incompatible with actor entity type {actor_entity_type}")]
    ActorClassMismatch {
        actor_entity_type: u8,
        actor_class: u8,
    },
    /// An `edge.provenance` value record failed the pinned structural
    /// validation (the 10-key snake_case ABI — ONE-1138 vocabulary).
    /// Nothing was written.
    #[error("invalid edge.provenance body: {0}")]
    InvalidProvenanceBody(&'static str),
    /// A MODEL substrate descriptor failed validation (ONE-1138): an
    /// `ensure_model_substrate` name/version that is empty or oversized, or
    /// a provenance `substrate_ref` that does not name a stored MODEL
    /// (type byte 121) entity. Nothing was written.
    #[error("invalid model substrate: {0}")]
    InvalidModelSubstrate(&'static str),
    /// A receipt surface that is defined only for emit-adjacent receipts
    /// (the OF-369/RS9 context field-set, the OF-326 session-local receipt
    /// log) was given a non-emit receipt kind. Non-emit receipts project
    /// from their own stored substrates and never carry emit context.
    /// Nothing was written.
    #[error("{surface} requires an emit-adjacent receipt kind, got {kind}")]
    EmitAdjacentReceiptRequired {
        surface: &'static str,
        kind: &'static str,
    },
    /// A claim lifecycle transition (`supersede_claim` / `retract_claim`)
    /// targeted a claim whose `life` status is not `active`. Superseded and
    /// retracted claims are closed history (ARCH-0003: all non-current
    /// states are still stored — claims are never silently deleted) and
    /// cannot transition again. Nothing was written.
    #[error("claim already closed: lifecycle status is {status:?}")]
    ClaimAlreadyClosed { status: ClaimLifecycleStatus },
    /// `supersede_claim` was called with `new_id == old_id` — a claim
    /// cannot supersede itself. Nothing was written.
    #[error("claim cannot supersede itself")]
    ClaimSelfSupersession,
    /// A generic claim lifecycle op (`supersede_claim` / `retract_claim`)
    /// targeted a reserved-namespace (`edge.*`) provenance Claim. Provenance
    /// Claims drive the subject edge's derived hot flags, so their lifecycle
    /// is owned exclusively by the edge-provenance lifecycle API (the
    /// `put_edge_provenance` / `retract_edge_provenance` surface), which
    /// re-stamps the edge whenever the Claim changes. The generic ops reject
    /// instead of bypassing that re-stamp. Nothing was written.
    #[error(
        "claim predicate {predicate:?} is a reserved edge.* provenance claim; use the edge-provenance lifecycle API (put_edge_provenance / retract_edge_provenance), not the generic claim lifecycle ops"
    )]
    ProvenanceClaimLifecycle { predicate: String },
    /// A provenance lifecycle operation (retract / supersede) named an
    /// entity that is not an `edge.provenance` Claim — wrong type byte or
    /// wrong predicate. Nothing was written.
    #[error("not an edge.provenance claim: {0}")]
    NotAProvenanceClaim(&'static str),
    /// A provenance lifecycle operation targeted a Claim whose lifecycle is
    /// no longer `active` (double-retract, or supersede-after-close). The
    /// first close wins; nothing was written.
    #[error("edge.provenance claim is already closed: lifecycle is {lifecycle}")]
    ProvenanceClaimAlreadyClosed { lifecycle: &'static str },
    /// A provenance write named a `claim_id` that already exists in storage.
    /// Provenance claim ids are WRITE-ONCE: re-putting an existing id would
    /// overwrite the stored Claim in place — resurrecting a retracted or
    /// superseded wrapper as a fresh `active` body, bypassing
    /// [`Error::ProvenanceClaimAlreadyClosed`] (ARCH-0003: "claims are never
    /// silently deleted"). The lifecycle operations (retract / supersede)
    /// are the only mutators of an existing provenance Claim. Nothing was
    /// written.
    #[error("edge.provenance claim id already in use: provenance claim ids are write-once")]
    ProvenanceClaimIdInUse,
    /// The prior Claim named in a supersede call addresses a different
    /// EdgeRef than the incoming Claim. Supersession is per subject edge —
    /// two Claims naming different EdgeRefs never supersede each other.
    #[error("edge.provenance subject mismatch: prior and new claims address different EdgeRefs")]
    ProvenanceSubjectMismatch,
    /// A provenance Claim cannot supersede itself (`prior_claim_id` equals
    /// `new_claim_id`).
    #[error("edge.provenance claim cannot supersede itself")]
    ProvenanceSelfSupersession,
    /// D14 precedence violation: the incoming Claim's envelope `learned_at`
    /// is older than the live frontier for its subject edge, so it can never
    /// take precedence ("a newer Claim takes precedence"). The engine
    /// refuses to write a dead-on-arrival provenance Claim.
    #[error(
        "edge.provenance precedence violation: incoming learned_at {incoming_learned_at} predates the live frontier {frontier_learned_at}"
    )]
    ProvenancePrecedenceViolation {
        incoming_learned_at: u64,
        frontier_learned_at: u64,
    },
    /// A plain (provenance-free) edge put targeted an edge that carries a
    /// 26-byte provenanced value — the silent-downgrade hole pinned by
    /// ONE-1113 (ARCH-0034 #write-protection, ratified 2026-06-13): "an
    /// unattributed write can never displace attributed truth as current
    /// state". The write is rejected typed and routed — never a silent strip
    /// of the two hot-flag bytes, never a silent preserve of them under the
    /// caller's new value. Both edge directions stay byte-identical and the
    /// live `edge.provenance` Claim stays live; nothing was written.
    #[error(
        "edge (kind {kind}) is provenanced: a plain edge put cannot displace attributed truth; modify the relation via put_edge_provenance / the actor-bound surface (as_actor), set weight via set_edge_weight, set VAD via set_edge_vad"
    )]
    EdgeIsProvenanced { kind: u8 },
    /// Tree operation would create a cycle.
    #[error("cycle detected in tree hierarchy")]
    CycleDetected,
    /// ChildOf write would give a child more than one parent (single-parent
    /// tree pin; validated atomically over each batch).
    #[error("childof requires a single parent")]
    ChildOfCardinality,
    /// Text analyzer manifest on disk does not match the current analyzer
    /// configuration. Per-language mode (Morphological vs Portable) flipped
    /// because a dict appeared or disappeared between index time and open
    /// time (plan ONE-317 §4.2).
    ///
    /// # Recovery
    ///
    /// Reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, call [`MaintenanceBuilder::clear_text_index`] to drop the
    /// stale postings, reopen with the default `false` value so the empty
    /// index seeds a fresh manifest, then reindex documents to restore
    /// search results.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error(
        "text analyzer changed since index was built (lang={lang:?}): stored={stored_mode} current={current_mode}; reopen with VaultConfig::skip_text_index_manifest_check=true, run clear_text_index, reopen normally, and reindex documents to restore search"
    )]
    IncompatibleAnalyzer {
        lang: String,
        stored_mode: &'static str,
        current_mode: &'static str,
    },
    /// BM25F field schema on disk does not match the current build. Channels
    /// in [`crate::analyzer::AnalyzerChannel`] were added, removed, or
    /// renumbered between index time and open time.
    ///
    /// # Recovery
    ///
    /// Same as [`Error::IncompatibleAnalyzer`]: reopen with
    /// [`VaultConfig::skip_text_index_manifest_check`] set to `true`, run
    /// [`MaintenanceBuilder::clear_text_index`], reopen normally, then
    /// reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error(
        "bm25f field schema changed since index was built; reopen with VaultConfig::skip_text_index_manifest_check=true, run clear_text_index, reopen normally, and reindex documents to restore search"
    )]
    Bm25FieldSchemaChanged,
    /// A caller-supplied BM25F rank profile carries an invalid scoring
    /// parameter: a non-finite or negative channel weight, a `b` outside
    /// `[0.0, 1.0]`, a non-finite or non-positive BM25+ `delta`, or an
    /// override on a reserved channel that v1 analyzers never emit
    /// (`Shingle` / `Synonym` / `Phonetic`). Rank profiles are
    /// scoring-only (ARCH-0031), so nothing on disk was touched; fix the
    /// profile and retry the query.
    #[error("invalid bm25 rank profile: {parameter} = {value}")]
    InvalidRankProfile { parameter: &'static str, value: f64 },
    /// A dict asset declared in the stored manifest is missing from disk
    /// (e.g., `system.dic` was deleted after indexing). Restore the file or
    /// use the same recovery path as [`Error::IncompatibleAnalyzer`]:
    /// reopen with [`VaultConfig::skip_text_index_manifest_check`] set to
    /// `true`, run [`MaintenanceBuilder::clear_text_index`], reopen
    /// normally, and reindex documents.
    ///
    /// [`VaultConfig::skip_text_index_manifest_check`]: crate::VaultConfig::skip_text_index_manifest_check
    /// [`MaintenanceBuilder::clear_text_index`]: crate::MaintenanceBuilder::clear_text_index
    #[error("analyzer asset missing: {0}")]
    AnalyzerAssetMissing(String),
    /// Generic analyzer error (dict load failure, manifest encode failure,
    /// etc.). Wraps the underlying cause as a string to avoid leaking
    /// transitive Sudachi/jieba/lindera error types into the public surface.
    #[error("analyzer error: {0}")]
    AnalyzerError(String),
    /// An upstream tool or connector call failed outside local config
    /// validation. The code is caller-safe and pre-sanitized by the adapter.
    #[error("upstream tool failure: tool={tool}, code={code}")]
    UpstreamToolFailure { tool: &'static str, code: String },
    /// Malformed CRDT update bytes.
    #[cfg(feature = "sync")]
    #[error("crdt decode error ({context}): {source}")]
    CrdtDecodeError {
        context: &'static str,
        #[source]
        source: loro::LoroError,
    },
    /// No persisted state for the requested window.
    #[cfg(feature = "sync")]
    #[error("sync window not found: {window_key}")]
    WindowNotFound { window_key: String },
    /// `WindowManager::unload_window` refused to deregister a window that
    /// still has external `Arc<LoadedWindow>` holders (ONE-1150).
    /// Deregistering anyway would let a subsequent `open_window` construct a
    /// SECOND live doc for the same window key: the outstanding handle's doc
    /// would keep accepting writes that bypass Observer A routing, and the
    /// manager's `window()` lookup — the seam delete routing uses to commit
    /// tombstones through the live doc — would miss it, sending deletes down
    /// the transient path while the orphaned doc still holds the deleted
    /// body. Fail-closed: nothing was persisted or deregistered; the window
    /// stays registered and discoverable. Retry after the last external
    /// handle drops, or use the manager's forced-eviction path
    /// (`discard_window`) when the doc state is known-stale.
    /// `outstanding_handles` counts external holders only (the registry's
    /// own reference is excluded).
    #[cfg(feature = "sync")]
    #[error(
        "sync window busy: {window_key} has {outstanding_handles} outstanding external handle(s); unload refused — retry after the last handle drops"
    )]
    WindowBusy {
        window_key: String,
        outstanding_handles: usize,
    },
    /// Sync protocol violation.
    #[cfg(feature = "sync")]
    #[error("sync protocol error: {context}")]
    SyncProtocolError { context: SyncProtocolValidation },
    /// Local sync engine operation failed below the protocol validation layer.
    #[cfg(feature = "sync")]
    #[error("sync engine error ({context}): {source}")]
    SyncEngineError {
        context: SyncEngineContext,
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },
    /// A signed maintenance-band op arriving through a sync replay door would
    /// exceed this device's local per-peer ingest quota for the current quota
    /// window. The op is quarantined and can be lazily re-admitted by a later
    /// rematerialization pass once a new quota window is under budget.
    #[cfg(feature = "sync")]
    #[error(
        "maintenance ingest quota exceeded for peer {peer_key_hex}: accepted {accepted_count}/{max_ops_per_peer_window} in quota window starting {window_start_secs} ({quota_window_secs}s)"
    )]
    MaintenanceIngestQuotaExceeded {
        peer_key_hex: String,
        accepted_count: u32,
        max_ops_per_peer_window: u32,
        window_start_secs: u64,
        quota_window_secs: u64,
    },
    /// A REDACTION_AUDIT (type 120) blob arriving through a sync replay door
    /// failed structural validation against the pinned contracts.ts
    /// `redactionAuditReceipt` field set (request_id, scope, reason,
    /// requested_at, soft_complete_at, hard_purge_complete_at,
    /// sweep_queued_at?, sweep_complete_at?, affected_revision_ids,
    /// verification — opaque identifiers + timestamps only). Fail-closed:
    /// nothing was written; the replay doors quarantine the blob (`x:`
    /// family, ONE-1134).
    #[error("invalid redaction audit receipt body: {0}")]
    InvalidRedactionReceiptBody(&'static str),
    /// Off-record entry is disabled by the vault-level kill-switch. The
    /// refusal occurs before any in-process registry or overlay mutation.
    #[error("off-record sessions are disabled by configuration")]
    KillSwitchDisabled,
    /// Off-record session enter (OF-326) found an existing record for the
    /// session ref. Enter is explicit and single-shot; the ref frees up when
    /// the session closes.
    #[error("off-record session already exists: {session_ref}")]
    OffRecordSessionAlreadyExists { session_ref: String },
    /// An off-record session operation (OF-326) targeted a session ref with
    /// no live record (never entered, or already closed).
    #[error("off-record session not found: {session_ref}")]
    OffRecordSessionNotFound { session_ref: String },
    /// A mutator (tag, promote, note-context-receipt, mode flip) targeted an
    /// off-record session whose close is in flight — the closing flag froze
    /// the record so close's multi-transaction deletion pass cannot race a
    /// mutation. Nothing was written; the session is evaporating.
    #[error("off-record session {session_ref} is closing: the record is frozen")]
    OffRecordSessionClosing { session_ref: String },
    /// An in-memory session overlay insert would exceed its configured hard
    /// byte budget. The candidate mutation is not published.
    #[error(
        "off-record overlay is full: budget {budget_bytes} bytes, attempted {attempted_bytes} bytes"
    )]
    OffRecordOverlayFull {
        budget_bytes: usize,
        attempted_bytes: usize,
    },
    /// A generation-stamped session overlay lease was requested or used
    /// after the overlay began closing or was cleared.
    #[error("off-record overlay generation {generation} is closed")]
    OffRecordOverlayLeaseClosed { generation: u64 },
    /// Promote (OF-326) targeted a turn that is not fenced by this
    /// off-record session — promote lifts exactly one live fence.
    #[error("turn {turn_ref} is not fenced by off-record session {session_ref}")]
    OffRecordTurnNotFenced {
        session_ref: String,
        turn_ref: String,
    },
    /// Promote (OF-326 / ONE-1645) is a widening op: it moves a fenced turn
    /// into the durable vault, so it must be authenticated to the owner
    /// principal by the same actor-identity vocabulary as every other consent
    /// surface. The supplied actor did not authenticate the principal (ref
    /// mismatch, blank ref, or an unverified voice path). The fence stands and
    /// nothing was written.
    #[error(
        "off-record promote in session {session_ref} is not authenticated: actor {actor_ref} does not authenticate the owner principal"
    )]
    OffRecordPromoteUnauthenticated {
        session_ref: String,
        actor_ref: String,
    },
    /// The entity write door found an off-record fence that is no longer
    /// owned by a live, mutable session. This is the permanent fail-closed
    /// guard for a tag-before-write turn after close; the error deliberately
    /// carries the caller-supplied turn id, never the evaporated session ref.
    #[error(
        "off-record fenced turn {turn_ref} cannot be written: its session is closed or closing"
    )]
    OffRecordFencedTurnWriteRejected { turn_ref: String },
    /// OF-326 talk-only: the intent originated from a session currently in
    /// off-record mode, where outbound/commitment verbs are disabled. Exit
    /// prompt semantics — wanting the action means exiting off-record mode.
    #[error(
        "off-record session {session_ref} is talk-only: outbound and commitment verbs are disabled; exit off-record mode to take this action"
    )]
    OffRecordTalkOnly { session_ref: String },
    /// A whole-vault export cannot run while an off-record session is still
    /// live. Refusing the operation is preferable to producing an artifact
    /// whose fenced rows would outlive the session's delete-at-close pass.
    #[error("whole-vault export refused while off-record session is open: {session_ref}")]
    OffRecordExportRefused { session_ref: String },
    /// A sync replay door delivered DIVERGENT bytes for an EXISTING
    /// REDACTION_AUDIT receipt id. Receipts are immutable audit records
    /// (contracts.ts `redactionAuditReceipt.immutability`; the ARCH-0023b
    /// audit/guardrail stream class quarantines divergent same-identity
    /// payloads, never silent LWW): the local bytes are kept and the remote
    /// payload is quarantined (ONE-1134).
    #[cfg(feature = "sync")]
    #[error(
        "redaction audit receipt {} is immutable: divergent remote bytes are quarantined, local bytes kept",
        id.to_hex()
    )]
    RedactionReceiptDivergence { id: EntityId },
    /// A NEW REDACTION_AUDIT receipt arriving through a sync replay door
    /// failed Ed25519 attestation verification (ONE-1140): the embedded
    /// `att_sig` does not verify over the pinned transcript (domain ||
    /// entity_id || envelope_header || body-with-empty-verification), or
    /// the `att_pk` disagrees with the lease registry binding for
    /// `att_client`. Fail-closed: nothing written; the replay doors
    /// quarantine the blob (`x:` family).
    #[cfg(feature = "sync")]
    #[error(
        "redaction audit receipt {} attestation invalid: signature/pubkey fails verification",
        id.to_hex()
    )]
    ReceiptAttestationInvalid { id: EntityId },
    /// A NEW REDACTION_AUDIT receipt claims an `att_client` with NO `ls:`
    /// lease binding in the local registry mirror (ONE-1140). Fail-closed:
    /// quarantined, not accepted — the rejected bytes stay in the CRDT map,
    /// so the next forward rematerialization re-admits the receipt once the
    /// lease mirror catches up (OD-10 lazy re-admission).
    #[cfg(feature = "sync")]
    #[error("redaction audit receipt claims unleased client {client_id:016x}")]
    ReceiptLeaseUnknown { client_id: u64 },
    /// A NEW REDACTION_AUDIT receipt claims an `att_client` whose lease
    /// binding is REVOKED (ONE-1140, OD-7/OD-8: revoked is terminal; the
    /// only door-enforced status — expired still verifies). Fail-closed:
    /// quarantined, never accepted.
    #[cfg(feature = "sync")]
    #[error("redaction audit receipt claims revoked client {client_id:016x}")]
    ReceiptLeaseRevoked { client_id: u64 },
    /// An ARCH-0055 identity-topology op was rejected by the (state, op)
    /// transition table, its storage guards, or undo-currency evaluation.
    #[error("identity topology op rejected: {0:?}")]
    IdentityTopologyRejected(crate::identity_topology::IdentityTopologyRejection),
    /// A type-76 IDENTITY_TOPOLOGY_EVENT body failed structural validation
    /// (D18 fail-closed on every path that can admit the byte).
    #[error("invalid identity topology event body: {0}")]
    InvalidIdentityTopologyEventBody(&'static str),
    /// A public edge write named a kind whose topology writes are reserved
    /// to an engine door (`merged_into` / `split_into` — the ARCH-0055
    /// apply/undo door is the only writer).
    #[error("edge kind is reserved to an engine door: {0}")]
    ReservedEdgeKind(&'static str),
    /// A replicated identity-topology event carried divergent bytes for an
    /// existing event id — equivocation on an immutable single-writer
    /// stream (ARCH-0023b): local bytes are kept, the remote payload is
    /// quarantined.
    #[cfg(feature = "sync")]
    #[error("identity topology event divergence for {}", id.to_hex())]
    IdentityTopologyEventDivergence { id: EntityId },
    /// The identity-topology apply door for this op kind is declared but not
    /// armed yet (facet minting arms in ONE-1745; distinct_from assertion in
    /// ONE-1746). Fail-closed so no ledger event records an op that had no
    /// effect.
    #[error("identity topology op is not armed yet: {0}")]
    IdentityTopologyUnarmed(&'static str),
}

impl Error {
    /// Constructs a typed sync protocol validation failure.
    #[cfg(feature = "sync")]
    #[must_use]
    pub fn sync_protocol(context: SyncProtocolValidation) -> Self {
        Self::SyncProtocolError { context }
    }

    /// Constructs a typed sync engine failure while preserving its source.
    #[cfg(feature = "sync")]
    pub fn sync_engine<E>(context: SyncEngineContext, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::SyncEngineError {
            context,
            source: Box::new(source),
        }
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
        Self::sync_engine(context, SyncRollbackError::new(operation, rollback))
    }

    /// Returns the typed Gate denial taxonomy for [`Error::GateWriteRejected`].
    #[must_use]
    pub fn gate_denial(&self) -> Option<GateDenial> {
        let Self::GateWriteRejected {
            outcome,
            reason_codes,
        } = self
        else {
            return None;
        };

        let outcome = GateDenialOutcome::parse(outcome)?;
        let mut typed_reasons = Vec::with_capacity(reason_codes.len());
        for reason_code in reason_codes {
            let reason = GateDenialReason::from_code(reason_code)?;
            if reason.outcome() != outcome {
                return None;
            }
            typed_reasons.push(reason);
        }

        Some(GateDenial {
            outcome,
            reason_codes: typed_reasons,
        })
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
            Self::EmbeddingModelChanged { .. } => ErrorKind::EmbeddingModelChanged,
            Self::HnswConfigChanged { .. } => ErrorKind::HnswConfigChanged,
            Self::StorageAbiVersionChanged { .. } => ErrorKind::StorageAbiVersionChanged,
            Self::StorageSchemaVersionChanged { .. } => ErrorKind::StorageSchemaVersionChanged,
            Self::DbManifestMismatch { .. } => ErrorKind::DbManifestMismatch,
            Self::VaultRootPreflight { .. } => ErrorKind::VaultRootPreflight,
            Self::MapFull => ErrorKind::MapFull,
            Self::InvalidConfig(_) => ErrorKind::InvalidConfig,
            Self::InvalidTemporalExpression(_) => ErrorKind::InvalidTemporalExpression,
            Self::EntityNotFound => ErrorKind::EntityNotFound,
            Self::AccessGrantAlreadyExists => ErrorKind::AccessGrantAlreadyExists,
            Self::OutboundGrantAlreadyExists => ErrorKind::OutboundGrantAlreadyExists,
            Self::ConnectorKeyAlreadyExists => ErrorKind::ConnectorKeyAlreadyExists,
            Self::ChannelIdentityAlreadyExists => ErrorKind::ChannelIdentityAlreadyExists,
            Self::CounterpartyContactAlreadyExists => ErrorKind::CounterpartyContactAlreadyExists,
            Self::CompanionRecordAlreadyExists => ErrorKind::CompanionRecordAlreadyExists,
            Self::ConcurrentWrite(_) => ErrorKind::ConcurrentWrite,
            Self::ArithmeticOverflow(_) => ErrorKind::ArithmeticOverflow,
            Self::InvariantViolation(_) => ErrorKind::InvariantViolation,
            Self::InvalidKey => ErrorKind::InvalidKey,
            Self::InvalidFederationGrantBody(_) => ErrorKind::InvalidFederationGrantBody,
            Self::InvalidAuthorityLogBody(_) => ErrorKind::InvalidAuthorityLogBody,
            Self::InvalidAccessGrantBody(_) => ErrorKind::InvalidAccessGrantBody,
            Self::InvalidOutboundGrantBody(_) => ErrorKind::InvalidOutboundGrantBody,
            Self::InvalidConnectorKeyBody(_) => ErrorKind::InvalidConnectorKeyBody,
            Self::ConnectorCharterCompile { .. } => ErrorKind::ConnectorCharterCompile,
            Self::ConnectorCharterApprovalMismatch => ErrorKind::ConnectorCharterApprovalMismatch,
            Self::ConnectorCharterMissing => ErrorKind::ConnectorCharterMissing,
            Self::InvalidChannelIdentityBody(_) => ErrorKind::InvalidChannelIdentityBody,
            Self::InvalidCounterpartyContactBody(_) => ErrorKind::InvalidCounterpartyContactBody,
            Self::InvalidCommRecordBody(_) => ErrorKind::InvalidCommRecordBody,
            Self::InvalidDisclosureScope(_) => ErrorKind::InvalidDisclosureScope,
            Self::DisclosureClampViolation(_) => ErrorKind::DisclosureClampViolation,
            Self::InvalidTaskBody(_) => ErrorKind::InvalidTaskBody,
            Self::CorruptedIndex(_) => ErrorKind::CorruptedIndex,
            Self::ContextPackValidation { .. } => ErrorKind::ContextPackValidation,
            Self::IndexOverflow(_) => ErrorKind::IndexOverflow,
            Self::MissingPostingEntry => ErrorKind::MissingPostingEntry,
            Self::InvalidEntityType(_) => ErrorKind::InvalidEntityType,
            Self::InvalidFacet { .. } => ErrorKind::InvalidFacet,
            Self::InvalidFacetOfEdge { .. } => ErrorKind::InvalidFacetOfEdge,
            Self::InvalidClaimBody(_) => ErrorKind::InvalidClaimBody,
            Self::InvalidPsychProfileBody(_) => ErrorKind::InvalidPsychProfileBody,
            Self::InvalidPersonaSnapshot(_) => ErrorKind::InvalidPersonaSnapshot,
            Self::PersonaSnapshotConsentStale { .. } => ErrorKind::PersonaSnapshotConsentStale,
            Self::InvalidCodeArtifactBody(_) => ErrorKind::InvalidCodeArtifactBody,
            Self::InvalidBlobArtifactBody(_) => ErrorKind::InvalidBlobArtifactBody,
            Self::InvalidAnchor(_) => ErrorKind::InvalidAnchor,
            Self::AnnotationThreadNotFound => ErrorKind::AnnotationThreadNotFound,
            Self::InvalidEditManifest(_) => ErrorKind::InvalidEditManifest,
            Self::EditRoundtripFailed(_) => ErrorKind::EditRoundtripFailed,
            Self::EditProposalAlreadySettled { .. } => ErrorKind::EditProposalAlreadySettled,
            Self::EditProposalStale => ErrorKind::EditProposalStale,
            Self::SettleNotAuthorized(_) => ErrorKind::SettleNotAuthorized,
            Self::InvalidSkillBody(_) => ErrorKind::InvalidSkillBody,
            Self::InvalidAgentDefBody(_) => ErrorKind::InvalidAgentDefBody,
            Self::SystemAgentDisabled(_) => ErrorKind::SystemAgentDisabled,
            Self::AgentNotDispatchable(_) => ErrorKind::AgentNotDispatchable,
            Self::InvalidAgentDispatchInput(_) => ErrorKind::InvalidAgentDispatchInput,
            Self::InvalidRecoveryArtifact(_) => ErrorKind::InvalidRecoveryArtifact,
            Self::RecoveryArtifactQuarantineExhausted { .. } => {
                ErrorKind::RecoveryArtifactQuarantineExhausted
            }
            Self::InvalidCodebaseSnapshotBody(_) => ErrorKind::InvalidCodebaseSnapshotBody,
            Self::HostedMediaHashMatchKnownMatch { .. } => {
                ErrorKind::HostedMediaHashMatchKnownMatch
            }
            Self::InvalidCodeSymbolManifestBody(_) => ErrorKind::InvalidCodeSymbolManifestBody,
            Self::InvalidRepoMutationRecord(_) => ErrorKind::InvalidRepoMutationRecord,
            Self::RepoMutationFailed(_) => ErrorKind::RepoMutationFailed,
            Self::RepoMutationRecoveryDiverged { .. } => ErrorKind::RepoMutationRecoveryDiverged,
            Self::InvalidPredicate { .. } => ErrorKind::InvalidPredicate,
            Self::ReservedPredicate { .. } => ErrorKind::ReservedPredicate,
            Self::SourceNotTrustedForAuto { .. } => ErrorKind::SourceNotTrustedForAuto,
            Self::GateWriteRejected { .. } => ErrorKind::GateWriteRejected,
            Self::GateConsentStale { .. } => ErrorKind::GateConsentStale,
            Self::MaintenanceKindNotWritable(_) => ErrorKind::MaintenanceKindNotWritable,
            Self::StructuralKindBandViolation { .. } => ErrorKind::StructuralKindBandViolation,
            Self::StructuralKindTypeByteCollision(_) | Self::StructuralKindPrefixCollision(_) => {
                ErrorKind::StructuralKindCollision
            }
            Self::InvalidStructuralKindRegistration(_) => {
                ErrorKind::InvalidStructuralKindRegistration
            }
            Self::InvalidAttemptQueueRecord(_) => ErrorKind::InvalidAttemptQueueRecord,
            Self::InvalidAttemptQueueTransition { .. } => ErrorKind::InvalidAttemptQueueTransition,
            Self::EntityTypeImmutable { .. } => ErrorKind::EntityTypeImmutable,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::EdgeNotFound => ErrorKind::EdgeNotFound,
            Self::ProvenanceOnStructuralEdge { .. } => ErrorKind::ProvenanceOnStructuralEdge,
            Self::ActorClassMismatch { .. } => ErrorKind::ActorClassMismatch,
            Self::InvalidProvenanceBody(_) => ErrorKind::InvalidProvenanceBody,
            Self::InvalidModelSubstrate(_) => ErrorKind::InvalidModelSubstrate,
            Self::EmitAdjacentReceiptRequired { .. } => ErrorKind::EmitAdjacentReceiptRequired,
            Self::ClaimAlreadyClosed { .. } => ErrorKind::ClaimAlreadyClosed,
            Self::ClaimSelfSupersession => ErrorKind::ClaimSelfSupersession,
            Self::ProvenanceClaimLifecycle { .. } => ErrorKind::ProvenanceClaimLifecycle,
            Self::NotAProvenanceClaim(_) => ErrorKind::NotAProvenanceClaim,
            Self::ProvenanceClaimAlreadyClosed { .. } => ErrorKind::ProvenanceClaimAlreadyClosed,
            Self::ProvenanceClaimIdInUse => ErrorKind::ProvenanceClaimIdInUse,
            Self::ProvenanceSubjectMismatch => ErrorKind::ProvenanceSubjectMismatch,
            Self::ProvenanceSelfSupersession => ErrorKind::ProvenanceSelfSupersession,
            Self::ProvenancePrecedenceViolation { .. } => ErrorKind::ProvenancePrecedenceViolation,
            Self::EdgeIsProvenanced { .. } => ErrorKind::EdgeIsProvenanced,
            Self::CycleDetected => ErrorKind::CycleDetected,
            Self::ChildOfCardinality => ErrorKind::ChildOfCardinality,
            Self::IncompatibleAnalyzer { .. } => ErrorKind::IncompatibleAnalyzer,
            Self::Bm25FieldSchemaChanged => ErrorKind::Bm25FieldSchemaChanged,
            Self::InvalidRankProfile { .. } => ErrorKind::InvalidRankProfile,
            Self::AnalyzerAssetMissing(_) => ErrorKind::AnalyzerAssetMissing,
            Self::AnalyzerError(_) => ErrorKind::AnalyzerError,
            Self::UpstreamToolFailure { .. } => ErrorKind::UpstreamToolFailure,
            #[cfg(feature = "sync")]
            Self::CrdtDecodeError { .. } => ErrorKind::CrdtDecodeError,
            #[cfg(feature = "sync")]
            Self::WindowNotFound { .. } => ErrorKind::WindowNotFound,
            #[cfg(feature = "sync")]
            Self::WindowBusy { .. } => ErrorKind::WindowBusy,
            #[cfg(feature = "sync")]
            Self::SyncProtocolError { .. } => ErrorKind::SyncProtocolError,
            #[cfg(feature = "sync")]
            Self::SyncEngineError { .. } => ErrorKind::SyncEngineError,
            #[cfg(feature = "sync")]
            Self::MaintenanceIngestQuotaExceeded { .. } => {
                ErrorKind::MaintenanceIngestQuotaExceeded
            }
            Self::InvalidRedactionReceiptBody(_) => ErrorKind::InvalidRedactionReceiptBody,
            Self::KillSwitchDisabled => ErrorKind::KillSwitchDisabled,
            Self::OffRecordSessionAlreadyExists { .. } => ErrorKind::OffRecordSessionAlreadyExists,
            Self::OffRecordSessionNotFound { .. } => ErrorKind::OffRecordSessionNotFound,
            Self::OffRecordSessionClosing { .. } => ErrorKind::OffRecordSessionClosing,
            Self::OffRecordOverlayFull { .. } => ErrorKind::OffRecordOverlayFull,
            Self::OffRecordOverlayLeaseClosed { .. } => ErrorKind::OffRecordOverlayLeaseClosed,
            Self::OffRecordTurnNotFenced { .. } => ErrorKind::OffRecordTurnNotFenced,
            Self::OffRecordPromoteUnauthenticated { .. } => {
                ErrorKind::OffRecordPromoteUnauthenticated
            }
            Self::OffRecordFencedTurnWriteRejected { .. } => {
                ErrorKind::OffRecordFencedTurnWriteRejected
            }
            Self::OffRecordTalkOnly { .. } => ErrorKind::OffRecordTalkOnly,
            Self::OffRecordExportRefused { .. } => ErrorKind::OffRecordExportRefused,
            #[cfg(feature = "sync")]
            Self::RedactionReceiptDivergence { .. } => ErrorKind::RedactionReceiptDivergence,
            #[cfg(feature = "sync")]
            Self::ReceiptAttestationInvalid { .. } => ErrorKind::ReceiptAttestationInvalid,
            #[cfg(feature = "sync")]
            Self::ReceiptLeaseUnknown { .. } => ErrorKind::ReceiptLeaseUnknown,
            #[cfg(feature = "sync")]
            Self::ReceiptLeaseRevoked { .. } => ErrorKind::ReceiptLeaseRevoked,
            Self::IdentityTopologyRejected(_) => ErrorKind::IdentityTopologyRejected,
            Self::IdentityTopologyUnarmed(_) => ErrorKind::IdentityTopologyUnarmed,
            Self::InvalidIdentityTopologyEventBody(_) => {
                ErrorKind::InvalidIdentityTopologyEventBody
            }
            Self::ReservedEdgeKind(_) => ErrorKind::ReservedEdgeKind,
            #[cfg(feature = "sync")]
            Self::IdentityTopologyEventDivergence { .. } => {
                ErrorKind::IdentityTopologyEventDivergence
            }
        }
    }

    /// Returns whether retrying the same operation may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConcurrentWrite(_) => true,
            Self::UpstreamToolFailure { .. } => true,
            // Transient by construction: the refusal clears once the last
            // external window handle drops (ONE-1150).
            #[cfg(feature = "sync")]
            Self::WindowBusy { .. } => true,
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
