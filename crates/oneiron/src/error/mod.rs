#[cfg(feature = "sync")]
use std::error::Error as StdError;
use std::path::PathBuf;

use crate::affect::VadComponent;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_RELATIONSHIP, TypeByteZone};
use crate::temporal::TemporalExpressionParseError;

mod gate;
mod maintenance;
mod off_record;
mod relay;
mod store;
mod sync;

pub use self::gate::{GateDenial, GateDenialOutcome, GateDenialReason, GateError};
pub use self::maintenance::{CompactionPacketError, MaintenanceError};
pub use self::off_record::OffRecordError;
pub use self::relay::RelayError;
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
    /// The active relationship does not resolve to an existing RELATIONSHIP entity.
    #[error(
        "invalid active relationship {}: resolved type {found:?}, expected RELATIONSHIP ({ENTITY_TYPE_RELATIONSHIP})",
        relationship.to_hex()
    )]
    InvalidRelationship {
        relationship: EntityId,
        found: Option<u8>,
    },
    /// A public `FacetOf` (u8 17) edge write failed the ONE-1645 write-time
    /// type table: the source must be an existing CLAIM, TURN, or EVENT and
    /// the target an existing FACET. A missing endpoint row is unknowable-typed
    /// (`None`) and rejected on the same footing as a wrong type — a facet
    /// stamp's endpoints must be established facts before the stamp. The batch
    /// aborts atomically; nothing was written.
    ///
    /// Every admitted source type is disclosure-effective on at least one door:
    /// CLAIM on the local query filter (`apply_facet_filter`), and CLAIM | TURN
    /// | EVENT alike on the federation selector, which mirrors this same table
    /// on its read side. `batch::validate_facet_of_edge` holds the full
    /// two-door reading.
    #[error(
        "invalid FacetOf edge {} (type {src_type:?}) -> {} (type {tgt_type:?}): expected CLAIM/TURN/EVENT -> FACET",
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
    /// A COMPANION_REGISTER body failed the pinned STATELESS structural
    /// validation at the FEDERATION ADMISSION door. Nothing was written, and
    /// nothing was staged.
    ///
    /// FED-1380: `companion::decode_companion_record_body` reports every body
    /// fault as [`Error::InvalidClaimBody`], which `stage_foreign_vault_import`
    /// classifies TERMINAL. Returning that variant from admission would mint a
    /// permanently `Failed` receipt for a kind materialization merely
    /// quarantines — the retry-semantics flip that door deliberately avoids. So
    /// the admission arm re-labels the fault with this variant: same verdict
    /// text, same coarse [`ErrorKind::InvalidClaimBody`] for anything reading
    /// `kind()`, but a distinct variant that the staging classifier does not
    /// list, leaving the refusal RETRYABLE — no receipt, no import, and no
    /// staged bytes for a confirmation to GC.
    ///
    /// It must NEVER be added to that terminal list. As with the other
    /// pinned-body refusals there (`InvalidTaskBody`, `InvalidSkillBody`), the
    /// operator re-presenting the same malformed artifact is expected to be
    /// refused again rather than handed a receipt that outlives the row.
    #[error("invalid companion record body: {0}")]
    InvalidCompanionRecordBody(&'static str),
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
    /// A CODE_ARTIFACT entity body failed the pinned replay-key validation.
    /// Nothing was written.
    #[error("invalid CODE artifact body: {0}")]
    InvalidCodeArtifactBody(&'static str),
    /// A BLOB_ARTIFACT entity body or version record failed pinned
    /// structural validation. Nothing was written.
    #[error("invalid BLOB artifact body: {0}")]
    InvalidBlobArtifactBody(&'static str),
    /// A Git-LFS object did not match what the client declared about it: a
    /// malformed object id, or a body whose SHA-256 or length disagrees with
    /// the declared oid/size. Nothing was written.
    ///
    /// Corruption of an ALREADY STORED body is deliberately NOT this variant —
    /// that is [`Error::CorruptedIndex`], because "you sent the wrong bytes"
    /// and "this vault is holding the wrong bytes" are different facts.
    #[error("invalid LFS object: {0}")]
    InvalidLfsObject(&'static str),
    /// A NOTE entity body failed the pinned three-key ABI validation
    /// (`crate::note::NOTE_BODY_KEYS`). Nothing was written.
    #[error("invalid NOTE body: {0}")]
    InvalidNoteBody(&'static str),
    /// A MESSAGE entity body is not the canonical six-axis witness envelope
    /// `gate::witness_message` authorizes, or it arrived at a door that cannot
    /// authorize one (a public raw put, or a replicated carry of an
    /// engine-voice `system` row). Nothing was written.
    ///
    /// ONE-1686 (RT-04). Distinct from [`GateError::GateWriteRejected`]: that is a
    /// policy verdict on a well-formed envelope presented by an authenticated
    /// actor; this says the bytes are not an envelope this vault's write
    /// boundary can bind to an actor at all.
    #[error("invalid MESSAGE witness envelope: {0}")]
    InvalidWitnessMessageBody(&'static str),
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
    /// The world the ONE-1449 skill-edit gate was ruling over moved before the
    /// ruling could commit: the reserved evidence changed under the scorer, or
    /// a terminal reason read before the write door no longer held inside it.
    ///
    /// RETRYABLE, and structurally distinct from every refusal: the gate's
    /// transaction rolled back, so NO verdict row, NO lifecycle closure, NO cap
    /// spend and NO marker change was committed and nothing was learned about
    /// the proposal. The proposal is exactly as it was before the call, and a
    /// rerun over a settled ledger rules on it deterministically. A refusal, by
    /// contrast, is an ANSWER and is always durable.
    #[error("skill edit gate must be retried: {0}")]
    SkillEditGateRetry(&'static str),
    /// The deterministic SKILL content-anchor id (ONE-1741) is already occupied
    /// by an entity of another kind, so the scan-verdict subject cannot be
    /// minted or reused without adopting a squatter. Nothing was written.
    #[error("skill content anchor id is held by entity type {existing}")]
    SkillContentAnchorTypeMismatch { existing: u8 },
    /// An AGENT_DEF entity body failed pinned structural/lifecycle validation
    /// or the update-immutability gate. Nothing was written.
    #[error("invalid AGENT_DEF body: {0}")]
    InvalidAgentDefBody(&'static str),
    /// A dispatch named an AGENT_DEF row that does not exist. Nothing was
    /// enqueued.
    #[error("agent definition not found: {}", id.to_hex())]
    AgentDefinitionNotFound { id: EntityId },
    /// A dispatch named a stored AGENT_DEF row whose `enabled` field is off.
    /// Nothing was enqueued.
    #[error("agent definition disabled: {}", id.to_hex())]
    AgentDefinitionDisabled { id: EntityId },
    /// A pinned seeded-roster row id is occupied by a foreign entity, a
    /// malformed body, or a row carrying a different logical id. Seeding
    /// neither overwrote it nor selected a replacement id.
    #[error("seeded agent definition conflict at {}", id.to_hex())]
    SeededAgentDefinitionConflict { id: EntityId },
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
    /// Custody is bound, but the ONE-1829 starting-mode door is not available.
    /// The workspace onboarding journal remains resumable and incomplete.
    #[error(
        "workspace mailbox autonomy is not ready for {identity_ref:?} (requested {requested_mode})"
    )]
    WorkspaceMailboxAutonomyNotReady {
        identity_ref: EntityId,
        requested_mode: String,
    },
    /// A CounterpartyContact record failed pinned structural validation.
    /// Nothing was written.
    #[error("invalid counterparty contact body: {0}")]
    InvalidCounterpartyContactBody(&'static str),
    /// A COMM_RECORD body failed pinned structural validation. Nothing was
    /// written.
    #[error("invalid comm record body: {0}")]
    InvalidCommRecordBody(&'static str),
    /// A DIAGNOSTIC body failed the pinned closed grammar (GATE-14,
    /// ONE-1394): an unknown/missing/duplicate `DIAGNOSTIC_BODY_KEYS` key,
    /// trailing bytes, an invalid enum string, a malformed ref or content
    /// hash, non-monotonic bitemporal validity, or control data smuggled
    /// through the untrusted-detail leaf. Nothing was written.
    #[error("invalid diagnostic body: {0}")]
    InvalidDiagnosticBody(&'static str),
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
    /// The acting actor has no authority over the CLAIM it named — it did not
    /// author the claim, or it lacks the standing the operation requires over
    /// somebody else's.
    ///
    /// An authority denial, not a malformed request: the reference resolved,
    /// the body was well formed, and the operation is one the engine
    /// supports. What is missing is the actor's standing to perform it on THIS
    /// claim, which is why it classifies with the gate family rather than
    /// falling through to a request-shape error and telling a caller to fix a
    /// shape that was never wrong.
    ///
    /// Deliberately generic. It states the relationship that failed — actor
    /// versus claim — rather than one door's version of it, so the doors that
    /// share the relationship can share the error. `reason` carries the
    /// specific standing that was missing, in the voice of the door that
    /// checked it.
    #[error("actor lacks authority over this claim: {reason}")]
    ActorLacksClaimAuthority {
        /// Which standing was missing, as the checking door words it.
        reason: &'static str,
    },
    /// Registered maintenance-band entity kind (type bytes 120+, e.g.
    /// REDACTION_AUDIT) rejected on a public write path. Maintenance records
    /// are engine-authored only; this is distinct from
    /// [`Error::InvalidEntityType`], which covers genuinely unknown bytes.
    #[error("maintenance entity kind {0} is engine-authored and not writable via the public API")]
    MaintenanceKindNotWritable(u8),
    /// Pack StructuralKind registration claimed a byte outside its declared
    /// band or inside a band the runtime registry must not allocate.
    #[error(
        "structural kind band violation for type byte {type_byte}: declared={declared_zone:?}, actual={actual_zone:?}: {reason}"
    )]
    StructuralKindZoneViolation {
        type_byte: u8,
        declared_zone: TypeByteZone,
        actual_zone: TypeByteZone,
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
    /// A public surface-event correlation id is already held by an attempt row
    /// of another kind, so another subsystem owns that run. Typed rather than
    /// generic: the admission and the status read both raise it, and neither
    /// the submitter nor the operator can act on it without knowing which kind
    /// holds the id.
    #[error(
        "surface event correlation id `{correlation_id}` is already held by attempt kind `{holding_kind}`"
    )]
    SurfaceEventCorrelationKindCollision {
        correlation_id: String,
        holding_kind: String,
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
    /// A NAMED write verb (`supersede_claim` / `retract_claim` / a
    /// replacement-style `attest_edge_provenance`) addressed a claim that is
    /// no longer the head of its lifecycle chain. The claim id a verb names
    /// IS its version token (ONE-1936): there is no generation counter or
    /// ETag to compare, so a target whose `life` has moved off `active` is a
    /// STALE decision made against a view the store has since replaced.
    ///
    /// Distinct from [`Error::ClaimAlreadyClosed`], which is the mechanical
    /// "closed history never transitions again" rule: this variant is the
    /// concurrency answer, and it carries `successor_short_id` — the
    /// resolvable `short_id:content_hash` ref of the chain's terminal head —
    /// so the caller can re-get the current truth and issue a NEW decision.
    ///
    /// The engine never retargets the verb at the successor, never rewrites
    /// the caller's target ref, and never degrades to a warning. Nothing was
    /// written; the guard and the mutation it protects share one transaction,
    /// so a staged replacement rolls back with it.
    #[error(
        "write verb target {} is no longer the lifecycle head (life is {lifecycle:?}); current head is {successor_short_id}",
        target.to_hex()
    )]
    WriteVerbTargetStale {
        target: EntityId,
        lifecycle: ClaimLifecycleStatus,
        successor_short_id: String,
    },
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
    /// A `ChildOf` write named a parent that does not exist in the batch's
    /// FINAL state: absent from both LMDB and the batch's puts, or deleted by
    /// the batch without a later put. A parent CREATED anywhere in the same
    /// batch is fine — the check is on final state, not on op order.
    ///
    /// Coarse-mapped to [`ErrorKind::InvalidTaskBody`] so sync replay keeps
    /// the already-classified quarantine-and-continue policy for a structural
    /// tree rejection. The batch aborts atomically; nothing was written.
    #[error("childof parent {} does not exist", parent.to_hex())]
    ChildOfParentMissing { parent: EntityId },
    /// A TASK `ChildOf` child named a parent that is not a TASK entity. The
    /// productivity nesting matrix is TASK-to-TASK: a TASK row hung under
    /// another domain's row has no parent role to validate against, so the
    /// pair is rejected rather than admitted unchecked. `child_role` is the
    /// pinned `habit::TaskRole` byte; `parent_entity_type` is the parent's
    /// registry type byte. Nothing was written.
    #[error(
        "TASK child (role {child_role}) cannot be a child of non-TASK entity type {parent_entity_type}"
    )]
    TaskChildOfParentNotTask {
        child_role: u8,
        parent_entity_type: u8,
    },
    /// A TASK `ChildOf` pair falls outside the pinned productivity nesting
    /// matrix: `Goal -> Milestone`, `Milestone -> Task`, `Habit ->
    /// HabitCheckin`, and nothing else. Both bytes are pinned
    /// `habit::TaskRole` discriminants. Nothing was written.
    #[error("TASK role {parent_role} cannot parent TASK role {child_role}")]
    TaskChildOfNesting { parent_role: u8, child_role: u8 },
    /// An upstream tool or connector call failed outside local config
    /// validation. The code is caller-safe and pre-sanitized by the adapter.
    #[error("upstream tool failure: tool={tool}, code={code}")]
    UpstreamToolFailure { tool: &'static str, code: String },
    /// A public edge write named a kind whose topology writes are reserved
    /// to an engine door (`merged_into` / `split_into` — the ARCH-0055
    /// apply/undo door is the only writer).
    #[error("edge kind is reserved to an engine door: {0}")]
    ReservedEdgeKind(&'static str),
    /// No ARCH-0056 capture lane covers the offered context (ONE-1757), so no
    /// amendment Δ could be measured. A Δ is TELEMETRY: every caller records
    /// this and lands the decision anyway — it is never a reason to refuse an
    /// approval the decider already made.
    #[error("no amendment delta capture lane is available: {0}")]
    DeltaCaptureUnavailable(&'static str),
    /// An AUTHORITY_LOG row is append-only at its store key (ONE-1604-D1): a
    /// write carried body-divergent bytes for an existing AUTHORITY_LOG id. Local
    /// callers get this as a hard error; replicated doors classify it as a
    /// remote rejection — the payload is quarantined and local bytes are kept
    /// (never silent LWW on the authority substrate).
    #[error(
        "authority log row {} is append-only: body-divergent overwrite rejected",
        id.to_hex()
    )]
    AuthorityLogAppendOnlyViolation { id: EntityId },
    /// An AUTHORITY_LOG row's entity id does not equal the id derived from
    /// the BLAKE3 hash of its canonical signed body (ONE-1604-D1 content
    /// address). Raised at every import/replay door; replicated instances
    /// are quarantined.
    #[error(
        "authority log row {} does not match its content-derived store key",
        id.to_hex()
    )]
    AuthorityLogStoreKeyMismatch { id: EntityId },
    /// A SECRET_CUSTODY body failed structural validation (SECRET-01,
    /// ONE-1919).
    #[error("invalid secret custody body: {0}")]
    InvalidSecretCustodyBody(&'static str),
    /// A live secret name was re-registered while still held by a
    /// non-revoked record (SECRET-01).
    #[error("secret name in use: {name}")]
    SecretNameInUse { name: String },
    /// A value read was attempted on a non-`Active` custody record.
    #[error("secret custody record is not active: {name}")]
    SecretCustodyNotActive { name: String },
    /// No binding covers `(secret_ref, effector)` — the typed deny for a
    /// value read or use without a declared binding (SECRET-01; door/lease
    /// enforcement lands in SECRET-02).
    #[error("no secret binding for effector `{effector}` on secret `{secret_ref}`")]
    SecretBindingDenied {
        effector: String,
        secret_ref: String,
    },
    /// A repo-side manifest asks for more exposure than the vault floor
    /// permits for the entry's class (ARCH-0069 S2 — narrow-only).
    #[error(
        "manifest widens the vault floor for `{secret_ref}` ({class:?}): requested {requested:?} exceeds floor max {floor_max:?}"
    )]
    ManifestWidensFloor {
        secret_ref: String,
        class: crate::secret_custody::CustodyClass,
        requested: crate::secret_custody::CustodyTier,
        floor_max: crate::secret_custody::CustodyTier,
    },
    /// A requested custody tier is outside the admitted set for the
    /// record's class (SECRET-02, ONE-1920): the ONE tier-admission deny —
    /// floor band membership AND binding ceiling, stated once in
    /// `secret_lease::tier_admission`.
    #[error(
        "secret tier admission denied ({class:?}): requested {requested:?} exceeds the floor max {floor_max:?} or the binding ceiling {binding_ceiling:?} (band min {floor_min:?} is informational)"
    )]
    SecretTierDenied {
        class: crate::secret_custody::CustodyClass,
        requested: crate::secret_custody::CustodyTier,
        floor_min: crate::secret_custody::CustodyTier,
        floor_max: crate::secret_custody::CustodyTier,
        binding_ceiling: crate::secret_custody::CustodyTier,
    },
    /// A door/lease call named a secret ref with no live custody record
    /// (SECRET-02).
    #[error("no live secret custody record for ref `{name}`")]
    SecretRefNotFound { name: String },
    /// A secret-lease call named a lease id with no row (SECRET-02).
    #[error("no secret lease row for id {}", lease_id.to_hex())]
    SecretLeaseNotFound { lease_id: EntityId },
    /// A secret lease was used while `Expired`/`Revoked` (SECRET-02).
    #[error("secret lease {} is not active: {status:?}", lease_id.to_hex())]
    SecretLeaseNotActive {
        lease_id: EntityId,
        status: crate::secret_lease::SecretLeaseStatus,
    },
    /// A T2 registration named a path the record's manifest entry does not
    /// declare (SECRET-02; SECRET-03 excludes exactly the declared set).
    #[error("path `{path}` is not a manifest-declared secret path for `{secret_ref}`")]
    SecretLeasePathNotDeclared { secret_ref: String, path: String },
    /// A T2 registration named a DIFFERENT declared path under a lease that
    /// already holds a live registration (SECRET-02, SOL-1920-02): one
    /// registration row per lease — overwriting the row would orphan the
    /// first file beyond revoke/expiry. The caller mints a fresh lease for
    /// a new path.
    #[error(
        "secret lease {} already registers `{registered_path}`; requested `{requested_path}` — mint a fresh lease for a new path",
        lease_id.to_hex()
    )]
    SecretLeasePathConflict {
        lease_id: EntityId,
        registered_path: String,
        requested_path: String,
    },
    /// The declared T2 target failed the file policy (SECRET-02,
    /// SOL-1920-03): a symlink the vault never follows, a non-regular
    /// occupant, or a stray file no live registration under this lease
    /// covers — the vault never clobbers a path it did not create.
    #[error("secret lease target path `{path}` refused: {reason}")]
    SecretLeasePathRefused { path: String, reason: &'static str },
    /// The materialization receipt could not be written durable — the
    /// lease row and the value never escape a failed receipt (S3; the
    /// `#[cfg(test)]` fault hook injects this).
    #[error("secret lease materialization receipt write failed: {0}")]
    SecretLeaseReceiptWriteFailed(&'static str),
    /// A secret-lease/receipt/registration row failed structural
    /// validation (SECRET-02).
    #[error("invalid secret lease body: {0}")]
    InvalidSecretLeaseBody(&'static str),
    /// A rotation-receipt row or a stored taint-ref list failed structural
    /// validation (SECRET-04, ONE-1922).
    #[error("invalid secret rotation body: {0}")]
    InvalidSecretRotationBody(&'static str),
    /// A publish was refused because the artifact is secret-tainted by a
    /// record that has since ROTATED or been REVOKED (ARCH-0069 S7,
    /// read-time invalidation). A dial, not a wall: the resolved policy key
    /// `secret.taint.allow_stale_publish` permits the publish anyway, and
    /// the pointer row is stamped when it does.
    #[error(
        "artifact `{artifact}` is secret-tainted by a rotated or revoked record; publish refused (set secret.taint.allow_stale_publish to override)"
    )]
    TaintedArtifactStale { artifact: String },
    /// A guest tier that must run isolated has no microVM backend available
    /// (CODE-01 — the fail-closed release path; never a silent no-sandbox run).
    #[error("no microVM backend is available for guest tier `{tier}`")]
    MicroVmBackendUnavailable { tier: &'static str },
    /// A microVM backend refused or failed a boundary operation.
    #[error("microVM backend `{backend}` failed: {detail}")]
    MicroVmBackendError {
        backend: &'static str,
        detail: String,
    },
    /// The sandbox overlay could not be read, or held an entry that would let
    /// a guest write reach past the proposal channel.
    #[error("microVM overlay error: {detail}")]
    MicroVmOverlayError { detail: String },
    /// A guest paired a credential handle with a destination outside that
    /// handle's allowlist. Refused BEFORE the credential is resolved.
    #[error("credential `{credential}` is not bound to destination {scheme}://{host}")]
    MicroVmCredentialDestinationDenied {
        credential: String,
        scheme: String,
        host: String,
    },
    #[error("code emission is missing dreamer run id")]
    CodeEmissionMissingDreamerRunId,
    #[error("code review context is required")]
    CodeReviewContextRequired,
    #[error("code review does not support this operation")]
    CodeReviewUnsupportedOperation,
    #[error("code review is missing reviewer run id")]
    CodeReviewMissingReviewerRunId,
    #[error("code review reviewer run id must differ from authoring run id")]
    CodeReviewRunIdNotDistinct,
    #[error("code review is missing code artifact references")]
    CodeReviewMissingArtifactRefs,
    #[error("code review authoring run id does not match emission")]
    CodeReviewAuthoringRunIdMismatch,
    #[error("code blast-radius walk is missing touched symbols")]
    CodeBlastRadiusMissingTouchedSymbols,
    #[error("code blast-radius symbol is absent from graph: {0:?}")]
    CodeBlastRadiusUnknownSymbol(EntityId),
    /// A code-memory anchor, locator, slot name, or pull argument failed its
    /// own bounded structural validation (ONE-1608). The anchor rule this
    /// most often reports is the load-bearing one: a durable note is keyed by
    /// a live `CODE_SYMBOL` entity, and a path may never be supplied in its
    /// place.
    #[error("invalid code-memory anchor: {reason}")]
    CodeMemoryInvalidAnchor { reason: &'static str },
    /// An explicit ARCH-0050 L2 anchor transfer (`Rename` / `Copy`) was
    /// rejected before any durable write (ONE-1608): the endpoints are the
    /// same symbol, one of them does not resolve to a live `CODE_SYMBOL`, or
    /// the source symbol carries no slot value to move. Path or fingerprint
    /// resemblance NEVER substitutes for the explicit mapping, so a caller
    /// that reaches this has not identified a real rename/copy.
    #[error(
        "invalid code-memory anchor transfer {} -> {}: {reason}",
        from.to_hex(),
        to.to_hex()
    )]
    CodeMemoryInvalidAnchorTransfer {
        from: EntityId,
        to: EntityId,
        reason: &'static str,
    },
    /// A `blocks` readiness edge would close a cycle (ONE-1608): either
    /// `from == to`, or a `blocks`-only path already reaches `from` from
    /// `to`. Fail-closed — nothing is written, and a bounded-walk overflow
    /// raises [`Self::IndexOverflow`] rather than a partial acyclicity proof.
    #[error("blocks edge {} -> {} would close a readiness cycle", from.to_hex(), to.to_hex())]
    CodeMemoryBlocksCycle { from: EntityId, to: EntityId },
    /// The `blocks` door refused the write actor (ONE-1608): the actor entity
    /// did not resolve, its stored entity type does not admit the asserted
    /// [`crate::edge::EdgeActorClass`] (D13, `provenance::validate_actor_class`),
    /// or the validated class is `System`. Readiness dependencies are a
    /// Human/Agent judgement; a caller-asserted class is never trusted alone.
    #[error("blocks edge door denied the write actor: {0}")]
    CodeMemoryBlocksActorDenied(&'static str),
    /// The `blocks` door refused the host-stamped [`crate::claim::ClaimSource`]
    /// (ONE-1608): the source satisfies `requires_explicit_auto_permit()`
    /// (`imported` / `tool_output` / `generated`), so it may not mint a
    /// readiness dependency without an explicit permit.
    #[error("blocks edge door requires an explicit auto-permit for source `{source_kind}`")]
    CodeMemoryBlocksSourceUntrusted { source_kind: &'static str },
    /// An always-on L2 contract registration was rejected (ONE-1608): a
    /// `Claim` payload ref, a payload that does not resolve live, a payload
    /// whose entity type is not `NOTE`, or an anchor that is not a live
    /// `CODE_SYMBOL`.
    #[error("invalid always-on code-memory contract: {0}")]
    CodeMemoryAlwaysOnInvalid(&'static str),
    /// A bounded code-memory collection would overflow its pinned limit
    /// (ONE-1608). Transactional: the pre-existing slot / registration set is
    /// left byte-identical.
    #[error("code-memory limit exceeded for {kind}: {limit}")]
    CodeMemoryLimitExceeded { kind: &'static str, limit: usize },
    /// A git smart-HTTP route named a repository the origin will not resolve
    /// (ONE-1908). The name shape is closed, so nothing outside the serving
    /// root is ever addressable.
    #[error("invalid origin repo name: {0}")]
    GitHttpInvalidRepoName(&'static str),
    /// The named repository is not served. Phase A serves; it never implicitly
    /// creates a repository as a side effect of a request.
    #[error("origin does not serve repository `{repo}`")]
    GitHttpRepoNotFound {
        /// The requested repository name.
        repo: String,
    },
    /// The `git http-backend` invocation could not complete. Carries the
    /// backend's own diagnostic, never request or pack bytes.
    #[error("git smart-http serve failed: {reason}")]
    GitHttpServeFailed {
        /// Why the serve invocation could not complete.
        reason: String,
    },
    /// The credential door refused a push inside the quarantine window
    /// (ONE-1908). The refs never moved and the objects never became
    /// reachable. The reason names paths and detector codes only — never a
    /// matched line, a token, or any value byte.
    #[error("credential door refused the push: {reason}")]
    ReceivePackDoorRejected {
        /// The door's printable refusal.
        reason: String,
    },
    /// The journaled ref publication behind a receive-pack landing was refused:
    /// the refs moved under the decision, or the published object set is not
    /// wholly present. Either way no ref was moved by the landing.
    #[error("receive-pack landing refused: {reason}")]
    ReceivePackLandingRefused {
        /// The publication rejection class.
        reason: String,
    },
    /// A deployment-independent vault-read operation failed (ONE-1433). The
    /// typed taxonomy lives in `code_run::vault_read` and deliberately does not
    /// embed this type, which would make both errors recursive.
    #[error(transparent)]
    VaultRead(#[from] crate::code_run::vault_read::VaultReadError),
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
    /// Relay-domain failure, see [`RelayError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Relay(#[from] RelayError),
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
            Self::WorkspaceMailboxAutonomyNotReady { .. } => {
                ErrorKind::WorkspaceMailboxAutonomyNotReady
            }
            Self::InvalidCounterpartyContactBody(_) => ErrorKind::InvalidCounterpartyContactBody,
            Self::InvalidCommRecordBody(_) => ErrorKind::InvalidCommRecordBody,
            Self::InvalidDiagnosticBody(_) => ErrorKind::InvalidDiagnosticBody,
            // The structural ChildOf tree rejections are coarse-mapped onto
            // the existing TASK-body kind on purpose: remote replay already
            // classifies it quarantine-and-continue, so a new tree check adds
            // no new sync policy (ONE-1376).
            Self::InvalidTaskBody(_)
            | Self::ChildOfParentMissing { .. }
            | Self::TaskChildOfParentNotTask { .. }
            | Self::TaskChildOfNesting { .. } => ErrorKind::InvalidTaskBody,
            Self::CorruptedIndex(_) => ErrorKind::CorruptedIndex,
            Self::ContextPackValidation { .. } => ErrorKind::ContextPackValidation,
            Self::IndexOverflow(_) => ErrorKind::IndexOverflow,
            Self::InvalidEntityType(_) => ErrorKind::InvalidEntityType,
            Self::InvalidFacet { .. } => ErrorKind::InvalidFacet,
            Self::InvalidRelationship { .. } => ErrorKind::InvalidRelationship,
            Self::InvalidFacetOfEdge { .. } => ErrorKind::InvalidFacetOfEdge,
            Self::InvalidClaimBody(_) => ErrorKind::InvalidClaimBody,
            // Deliberately the SAME coarse kind a companion body fault has
            // always reported: only the variant is distinct, so the staging
            // terminal classifier can tell them apart without changing what
            // `kind()`-based callers (quarantine classification, API error
            // codes) observe.
            Self::InvalidCompanionRecordBody(_) => ErrorKind::InvalidClaimBody,
            Self::InvalidPsychProfileBody(_) => ErrorKind::InvalidPsychProfileBody,
            Self::InvalidPersonaSnapshot(_) => ErrorKind::InvalidPersonaSnapshot,
            Self::InvalidCodeArtifactBody(_) => ErrorKind::InvalidCodeArtifactBody,
            Self::InvalidBlobArtifactBody(_) => ErrorKind::InvalidBlobArtifactBody,
            Self::InvalidLfsObject(_) => ErrorKind::InvalidLfsObject,
            Self::InvalidNoteBody(_) => ErrorKind::InvalidNoteBody,
            Self::InvalidWitnessMessageBody(_) => ErrorKind::InvalidWitnessMessageBody,
            Self::InvalidAnchor(_) => ErrorKind::InvalidAnchor,
            Self::AnnotationThreadNotFound => ErrorKind::AnnotationThreadNotFound,
            Self::InvalidEditManifest(_) => ErrorKind::InvalidEditManifest,
            Self::EditRoundtripFailed(_) => ErrorKind::EditRoundtripFailed,
            Self::EditProposalAlreadySettled { .. } => ErrorKind::EditProposalAlreadySettled,
            Self::EditProposalStale => ErrorKind::EditProposalStale,
            Self::SettleNotAuthorized(_) => ErrorKind::SettleNotAuthorized,
            Self::InvalidSkillBody(_) => ErrorKind::InvalidSkillBody,
            Self::SkillEditGateRetry(_) => ErrorKind::SkillEditGateRetry,
            Self::SkillContentAnchorTypeMismatch { .. } => {
                ErrorKind::SkillContentAnchorTypeMismatch
            }
            Self::InvalidAgentDefBody(_) => ErrorKind::InvalidAgentDefBody,
            Self::AgentDefinitionNotFound { .. } => ErrorKind::AgentDefinitionNotFound,
            Self::AgentDefinitionDisabled { .. } => ErrorKind::AgentDefinitionDisabled,
            Self::SeededAgentDefinitionConflict { .. } => ErrorKind::SeededAgentDefinitionConflict,
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
            Self::MaintenanceKindNotWritable(_) => ErrorKind::MaintenanceKindNotWritable,
            Self::StructuralKindZoneViolation { .. } => ErrorKind::StructuralKindZoneViolation,
            Self::StructuralKindTypeByteCollision(_) | Self::StructuralKindPrefixCollision(_) => {
                ErrorKind::StructuralKindCollision
            }
            Self::InvalidStructuralKindRegistration(_) => {
                ErrorKind::InvalidStructuralKindRegistration
            }
            Self::InvalidAttemptQueueRecord(_) => ErrorKind::InvalidAttemptQueueRecord,
            Self::InvalidAttemptQueueTransition { .. } => ErrorKind::InvalidAttemptQueueTransition,
            Self::SurfaceEventCorrelationKindCollision { .. } => {
                ErrorKind::SurfaceEventCorrelationKindCollision
            }
            Self::EntityTypeImmutable { .. } => ErrorKind::EntityTypeImmutable,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::EdgeNotFound => ErrorKind::EdgeNotFound,
            Self::ProvenanceOnStructuralEdge { .. } => ErrorKind::ProvenanceOnStructuralEdge,
            Self::ActorLacksClaimAuthority { .. } => ErrorKind::ActorLacksClaimAuthority,
            Self::ActorClassMismatch { .. } => ErrorKind::ActorClassMismatch,
            Self::InvalidProvenanceBody(_) => ErrorKind::InvalidProvenanceBody,
            Self::InvalidModelSubstrate(_) => ErrorKind::InvalidModelSubstrate,
            Self::EmitAdjacentReceiptRequired { .. } => ErrorKind::EmitAdjacentReceiptRequired,
            Self::ClaimAlreadyClosed { .. } => ErrorKind::ClaimAlreadyClosed,
            Self::WriteVerbTargetStale { .. } => ErrorKind::WriteVerbTargetStale,
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
            Self::UpstreamToolFailure { .. } => ErrorKind::UpstreamToolFailure,
            Self::DeltaCaptureUnavailable(_) => ErrorKind::DeltaCaptureUnavailable,
            Self::ReservedEdgeKind(_) => ErrorKind::ReservedEdgeKind,
            Self::AuthorityLogAppendOnlyViolation { .. } => {
                ErrorKind::AuthorityLogAppendOnlyViolation
            }
            Self::AuthorityLogStoreKeyMismatch { .. } => ErrorKind::AuthorityLogStoreKeyMismatch,
            Self::InvalidSecretCustodyBody(_) => ErrorKind::InvalidSecretCustodyBody,
            Self::SecretNameInUse { .. } => ErrorKind::SecretNameInUse,
            Self::SecretCustodyNotActive { .. } => ErrorKind::SecretCustodyNotActive,
            Self::SecretBindingDenied { .. } => ErrorKind::SecretBindingDenied,
            Self::ManifestWidensFloor { .. } => ErrorKind::ManifestWidensFloor,
            Self::SecretTierDenied { .. } => ErrorKind::SecretTierDenied,
            Self::SecretRefNotFound { .. } => ErrorKind::SecretRefNotFound,
            Self::SecretLeaseNotFound { .. } => ErrorKind::SecretLeaseNotFound,
            Self::SecretLeaseNotActive { .. } => ErrorKind::SecretLeaseNotActive,
            Self::SecretLeasePathNotDeclared { .. } => ErrorKind::SecretLeasePathNotDeclared,
            Self::SecretLeasePathConflict { .. } => ErrorKind::SecretLeasePathConflict,
            Self::SecretLeasePathRefused { .. } => ErrorKind::SecretLeasePathRefused,
            Self::SecretLeaseReceiptWriteFailed(_) => ErrorKind::SecretLeaseReceiptWriteFailed,
            Self::InvalidSecretRotationBody(_) => ErrorKind::InvalidSecretRotationBody,
            Self::TaintedArtifactStale { .. } => ErrorKind::TaintedArtifactStale,
            Self::InvalidSecretLeaseBody(_) => ErrorKind::InvalidSecretLeaseBody,
            Self::MicroVmBackendUnavailable { .. } => ErrorKind::MicroVmBackendUnavailable,
            Self::MicroVmBackendError { .. } => ErrorKind::MicroVmBackendError,
            Self::MicroVmOverlayError { .. } => ErrorKind::MicroVmOverlayError,
            Self::MicroVmCredentialDestinationDenied { .. } => {
                ErrorKind::MicroVmCredentialDestinationDenied
            }
            Self::CodeEmissionMissingDreamerRunId => ErrorKind::CodeEmissionMissingDreamerRunId,
            Self::CodeReviewContextRequired => ErrorKind::CodeReviewContextRequired,
            Self::CodeReviewUnsupportedOperation => ErrorKind::CodeReviewUnsupportedOperation,
            Self::CodeReviewMissingReviewerRunId => ErrorKind::CodeReviewMissingReviewerRunId,
            Self::CodeReviewRunIdNotDistinct => ErrorKind::CodeReviewRunIdNotDistinct,
            Self::CodeReviewMissingArtifactRefs => ErrorKind::CodeReviewMissingArtifactRefs,
            Self::CodeReviewAuthoringRunIdMismatch => ErrorKind::CodeReviewAuthoringRunIdMismatch,
            Self::CodeBlastRadiusMissingTouchedSymbols => {
                ErrorKind::CodeBlastRadiusMissingTouchedSymbols
            }
            Self::CodeBlastRadiusUnknownSymbol(_) => ErrorKind::CodeBlastRadiusUnknownSymbol,
            Self::CodeMemoryInvalidAnchor { .. } => ErrorKind::CodeMemoryInvalidAnchor,
            Self::CodeMemoryInvalidAnchorTransfer { .. } => {
                ErrorKind::CodeMemoryInvalidAnchorTransfer
            }
            Self::CodeMemoryBlocksCycle { .. } => ErrorKind::CodeMemoryBlocksCycle,
            Self::CodeMemoryBlocksActorDenied(_) => ErrorKind::CodeMemoryBlocksActorDenied,
            Self::CodeMemoryBlocksSourceUntrusted { .. } => {
                ErrorKind::CodeMemoryBlocksSourceUntrusted
            }
            Self::CodeMemoryAlwaysOnInvalid(_) => ErrorKind::CodeMemoryAlwaysOnInvalid,
            Self::CodeMemoryLimitExceeded { .. } => ErrorKind::CodeMemoryLimitExceeded,
            Self::GitHttpInvalidRepoName(_) => ErrorKind::GitHttpInvalidRepoName,
            Self::GitHttpRepoNotFound { .. } => ErrorKind::GitHttpRepoNotFound,
            Self::GitHttpServeFailed { .. } => ErrorKind::GitHttpServeFailed,
            Self::ReceivePackDoorRejected { .. } => ErrorKind::ReceivePackDoorRejected,
            Self::ReceivePackLandingRefused { .. } => ErrorKind::ReceivePackLandingRefused,
            Self::VaultRead(_) => ErrorKind::VaultRead,
            Self::Gate(inner) => inner.kind(),
            Self::Maintenance(inner) => inner.kind(),
            Self::OffRecord(inner) => inner.kind(),
            Self::Relay(inner) => inner.kind(),
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
            Self::SkillEditGateRetry(_) => true,
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
