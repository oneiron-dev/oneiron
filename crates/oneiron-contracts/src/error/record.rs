//! Record-domain errors: body validation and identity-collision refusals for
//! the stored record families — grants, connector keys, channel identities,
//! companion records, notes, tasks and the authority log.
//!
//! Reached from the root as `Error::Record(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use crate::entity_id::EntityId;

use super::ErrorKind;

/// Record-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// A courtesy request requires a disconnected or dissolved pact.
    #[error("cooperative deletion request requires a disconnected or dissolved pact")]
    CooperativeDeletionRequiresTerminalPact,
    /// Malformed or unauthenticated courtesy request.
    #[error("invalid cooperative deletion request")]
    InvalidCooperativeDeletionRequest,
    /// A project or its derived home-room payload failed write admission.
    #[error("invalid project body: {0}")]
    InvalidProjectBody(&'static str),
    #[error("invalid project home room: {0}")]
    InvalidProjectRoomBody(&'static str),
    /// A project parent or the signer of its depth fact has not materialized yet.
    #[error("project dependency is not materialized")]
    ProjectDependencyPending,
    /// A different body at a held project revision's content-derived id.
    #[error("project revision {} is held with another body", id.to_hex())]
    ProjectRevisionCollision { id: EntityId },
    /// Project revisions are engine-written; no public door writes one.
    #[error("project revisions are written by the engine only")]
    ProjectRevisionWrite,
    /// An effect's person target came from a mention that is not settled
    /// yet (OF-123 act-now guard): its identity ask is open, or it still
    /// names more than one person.
    #[error(
        "which person \"{name}\" names is not settled; settle it with self.identity.settle first"
    )]
    IdentityUnsettled { name: String },
    /// A project's signed history passed its budget; it serves its last
    /// verified frontier and takes no new authority until the owner acts.
    #[error("project {} history over budget: {held} revisions, limit {max}", project.to_hex())]
    ProjectHistoryOverBudget {
        project: EntityId,
        held: u64,
        max: u64,
    },
    /// The project's signed history has no single head this door can build on.
    #[error("project {} authority unresolved: {reason}", project.to_hex())]
    ProjectAuthorityUnresolved {
        project: EntityId,
        reason: &'static str,
    },
    #[error("message stream recovery refused: {0}")]
    MessageStreamRecoveryFailed(String),
    #[error("invalid conversation body: {0}")]
    InvalidConversationBody(&'static str),
    #[error("invalid conversation operation: {0}")]
    ConversationState(&'static str),
    #[error("conversation actor is not authorized")]
    ConversationDenied,
    /// A live shared-ancestor rule narrowed the default leader-chat admission.
    #[error("leader chat refused by rule claim {}", rule.to_hex())]
    LeaderChatRule { rule: EntityId },

    #[error("DAG parent is outside the conversation")]
    DagParentOutsideConversation,
    #[error("cannot advance HEAD off the current trunk")]
    HeadAdvanceOffTrunk,
    #[error("invalid conversation DAG: {0}")]
    InvalidConversationDag(&'static str),
    #[error("invalid scope summary: {0}")]
    InvalidScopeSummary(&'static str),
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
    /// A FEDERATION_GRANT (type 124) body failed structural validation.
    #[error("invalid federation grant body: {0}")]
    InvalidFederationGrantBody(&'static str),
    #[error("invalid authority log body: {0}")]
    InvalidAuthorityLogBody(&'static str),
    /// A pairing link's scope the vault refuses: a facet limit on the vault
    /// owner, or a write facet outside the link's facets.
    #[error("invalid pairing scope: {0}")]
    InvalidPairingScope(&'static str),
    /// Context-pack assembly found a cross-record anomaly before surfacing output.
    #[error("context pack validation failed for entity {}: {reason}", id.to_hex())]
    ContextPackValidation { id: EntityId, reason: &'static str },
    /// A COMPANION_REGISTER body failed the pinned STATELESS structural
    /// validation at the FEDERATION ADMISSION door. Nothing was written, and
    /// nothing was staged.
    ///
    /// Retired companion identity carriers are refused before import staging.
    /// This typed variant is retryable rather than a terminal staged receipt:
    /// repeated presentation must never confirm a row storage cannot admit.
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
    /// A NOTE entity body failed the pinned three-key ABI validation
    /// (`crate::note::NOTE_BODY_KEYS`). Nothing was written.
    #[error("invalid NOTE body: {0}")]
    InvalidNoteBody(&'static str),
    /// A MESSAGE entity body is not the canonical six-axis witness envelope
    /// `gate::witness_message` authorizes, or it arrived at a door that cannot
    /// authorize one (a public raw put, or a replicated carry of an
    /// engine-voice `system` row). Nothing was written.
    ///
    /// ONE-1686 (RT-04). Distinct from [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected): that is a
    /// policy verdict on a well-formed envelope presented by an authenticated
    /// actor; this says the bytes are not an envelope this vault's write
    /// boundary can bind to an actor at all.
    #[error("invalid MESSAGE witness envelope: {0}")]
    InvalidWitnessMessageBody(&'static str),
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
    /// An incoming suppression ASSET claims the reserved domain but does not
    /// decode or bind to its deterministic entity ID.
    #[error("invalid outbound suppression receipt body: {0}")]
    InvalidSuppressionReceiptBody(&'static str),
    /// An incoming write tries to change an already committed suppression
    /// ASSET. Its stored bytes remain authoritative.
    #[error("outbound suppression receipt is immutable")]
    SuppressionReceiptDivergence,
    /// A TASK record failed pinned role-field validation. Nothing was written.
    #[error("invalid TASK body: {0}")]
    InvalidTaskBody(&'static str),
    /// A replicated ask fact names a group or person row that has not
    /// materialized yet. Its proof is checked once that row arrives.
    #[error("ask fact dependency is not materialized")]
    AskDependencyPending,
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
    /// A replicated AUTHORITY_LOG row the vault cannot apply yet (H72): no
    /// folded row admitted its signer, or no owner key signed or cosigned it.
    /// The row is held and never stored; replicated doors classify it as
    /// dependency-pending.
    #[error(
        "authority log row {} is held: its signer is not enrolled here, or no owner key signed it",
        id.to_hex()
    )]
    AuthorityLogSignerPending { id: EntityId },
    /// Storing this AUTHORITY_LOG row would take its signer, or the log's
    /// handoffs, past the pinned fold bound (H72). Nothing was written; a
    /// slip issuer's slip ops, and the rows it signs that only restrict
    /// authority, are never refused this way.
    #[error(
        "authority log at its bound for signer {signer}; row {} not stored",
        id.to_hex()
    )]
    AuthorityLogFull { id: EntityId, signer: String },
    #[error("MESSAGE stream already active: {}", message.to_hex())]
    StreamAlreadyActive { message: EntityId },
    #[error("MESSAGE stream handle is not active: {}", message.to_hex())]
    StreamNotActive { message: EntityId },
    #[error("MESSAGE stream {resource} limit: {limit}")]
    StreamLimit {
        resource: &'static str,
        limit: usize,
    },
}

impl RecordError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::CooperativeDeletionRequiresTerminalPact => {
                ErrorKind::CooperativeDeletionRequiresTerminalPact
            }
            Self::InvalidCooperativeDeletionRequest => ErrorKind::InvalidCooperativeDeletionRequest,
            Self::InvalidProjectBody(_) => ErrorKind::InvalidProjectBody,
            Self::InvalidProjectRoomBody(_) => ErrorKind::InvalidProjectRoomBody,
            Self::ProjectDependencyPending => ErrorKind::ProjectDependencyPending,
            Self::ProjectRevisionCollision { .. } => ErrorKind::ProjectRevisionCollision,
            Self::ProjectRevisionWrite => ErrorKind::ProjectRevisionWrite,
            Self::IdentityUnsettled { .. } => ErrorKind::IdentityUnsettled,
            Self::ProjectHistoryOverBudget { .. } => ErrorKind::ProjectHistoryOverBudget,
            Self::ProjectAuthorityUnresolved { .. } => ErrorKind::ProjectAuthorityUnresolved,
            Self::InvalidConversationBody(_) => ErrorKind::InvalidConversationBody,
            Self::ConversationState(_) => ErrorKind::ConversationState,
            Self::ConversationDenied | Self::LeaderChatRule { .. } => ErrorKind::ConversationDenied,
            Self::MessageStreamRecoveryFailed(_) => ErrorKind::MessageStreamRecoveryFailed,
            Self::DagParentOutsideConversation => ErrorKind::DagParentOutsideConversation,
            Self::HeadAdvanceOffTrunk => ErrorKind::HeadAdvanceOffTrunk,
            Self::InvalidConversationDag(_) => ErrorKind::InvalidConversationDag,
            Self::InvalidScopeSummary(_) => ErrorKind::InvalidScopeSummary,
            Self::InvalidPairingScope(_) => ErrorKind::InvalidPairingScope,
            Self::StreamAlreadyActive { .. } => ErrorKind::StreamAlreadyActive,
            Self::StreamNotActive { .. } => ErrorKind::StreamNotActive,
            Self::StreamLimit { .. } => ErrorKind::StreamLimit,
            Self::AccessGrantAlreadyExists => ErrorKind::AccessGrantAlreadyExists,
            Self::OutboundGrantAlreadyExists => ErrorKind::OutboundGrantAlreadyExists,
            Self::ConnectorKeyAlreadyExists => ErrorKind::ConnectorKeyAlreadyExists,
            Self::ChannelIdentityAlreadyExists => ErrorKind::ChannelIdentityAlreadyExists,
            Self::CounterpartyContactAlreadyExists => ErrorKind::CounterpartyContactAlreadyExists,
            Self::CompanionRecordAlreadyExists => ErrorKind::CompanionRecordAlreadyExists,
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
            Self::InvalidSuppressionReceiptBody(_) => ErrorKind::InvalidSuppressionReceiptBody,
            Self::SuppressionReceiptDivergence => ErrorKind::SuppressionReceiptDivergence,
            Self::InvalidTaskBody(_) => ErrorKind::InvalidTaskBody,
            Self::AskDependencyPending => ErrorKind::AskDependencyPending,
            Self::ContextPackValidation { .. } => ErrorKind::ContextPackValidation,
            // Deliberately the SAME coarse kind a companion body fault has
            // always reported: only the variant is distinct, so the staging
            // terminal classifier can tell them apart without changing what
            // `kind()`-based callers (quarantine classification, API error
            // codes) observe.
            Self::InvalidCompanionRecordBody(_) => ErrorKind::InvalidClaimBody,
            Self::InvalidPsychProfileBody(_) => ErrorKind::InvalidPsychProfileBody,
            Self::InvalidPersonaSnapshot(_) => ErrorKind::InvalidPersonaSnapshot,
            Self::InvalidNoteBody(_) => ErrorKind::InvalidNoteBody,
            Self::InvalidWitnessMessageBody(_) => ErrorKind::InvalidWitnessMessageBody,
            Self::AuthorityLogAppendOnlyViolation { .. } => {
                ErrorKind::AuthorityLogAppendOnlyViolation
            }
            Self::AuthorityLogStoreKeyMismatch { .. } => ErrorKind::AuthorityLogStoreKeyMismatch,
            Self::AuthorityLogSignerPending { .. } => ErrorKind::AuthorityLogSignerPending,
            Self::AuthorityLogFull { .. } => ErrorKind::AuthorityLogFull,
        }
    }
}
