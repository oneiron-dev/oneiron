#[cfg(feature = "sync")]
use std::error::Error as StdError;
use std::path::PathBuf;

use crate::affect::VadComponent;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::temporal::TemporalExpressionParseError;

mod claim;
mod gate;
mod maintenance;
mod off_record;
mod registry;
mod relay;
mod secret;
mod store;
mod sync;

pub use self::claim::ClaimError;
pub use self::gate::{GateDenial, GateDenialOutcome, GateDenialReason, GateError};
pub use self::maintenance::{CompactionPacketError, MaintenanceError};
pub use self::off_record::OffRecordError;
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
    /// Claim-domain failure, see [`ClaimError`].
    /// Transparent, so Display and `source()` are the leaf's.
    #[error(transparent)]
    Claim(#[from] ClaimError),
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
            Self::InvalidTaskBody(_) => ErrorKind::InvalidTaskBody,
            Self::CorruptedIndex(_) => ErrorKind::CorruptedIndex,
            Self::ContextPackValidation { .. } => ErrorKind::ContextPackValidation,
            Self::IndexOverflow(_) => ErrorKind::IndexOverflow,
            Self::InvalidEntityType(_) => ErrorKind::InvalidEntityType,
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
            Self::InvalidAttemptQueueRecord(_) => ErrorKind::InvalidAttemptQueueRecord,
            Self::InvalidAttemptQueueTransition { .. } => ErrorKind::InvalidAttemptQueueTransition,
            Self::InvalidTimeRange { .. } => ErrorKind::InvalidTimeRange,
            Self::EdgeNotFound => ErrorKind::EdgeNotFound,
            Self::UpstreamToolFailure { .. } => ErrorKind::UpstreamToolFailure,
            Self::DeltaCaptureUnavailable(_) => ErrorKind::DeltaCaptureUnavailable,
            Self::AuthorityLogAppendOnlyViolation { .. } => {
                ErrorKind::AuthorityLogAppendOnlyViolation
            }
            Self::AuthorityLogStoreKeyMismatch { .. } => ErrorKind::AuthorityLogStoreKeyMismatch,
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
            Self::Claim(inner) => inner.kind(),
            Self::Gate(inner) => inner.kind(),
            Self::Maintenance(inner) => inner.kind(),
            Self::OffRecord(inner) => inner.kind(),
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
