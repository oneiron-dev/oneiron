//! Artifact-domain errors: code and blob artifacts, anchors, edit proposals,
//! skills, agent definitions, recovery artifacts and the attempt queue.
//!
//! Reached from the root as `Error::Artifact(..)`, a transparent wrapper:
//! Display and `source()` are the leaf's, so every message string is what it
//! was when these variants sat flat on `Error`.

use std::path::PathBuf;

use crate::entity_id::EntityId;

use super::ErrorKind;

/// Artifact-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactError {
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
    /// that is [`Error::CorruptedIndex`](crate::error::Error::CorruptedIndex), because "you sent the wrong bytes"
    /// and "this vault is holding the wrong bytes" are different facts.
    #[error("invalid LFS object: {0}")]
    InvalidLfsObject(&'static str),
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
    /// No ARCH-0056 capture lane covers the offered context (ONE-1757), so no
    /// amendment Δ could be measured. A Δ is TELEMETRY: every caller records
    /// this and lands the decision anyway — it is never a reason to refuse an
    /// approval the decider already made.
    #[error("no amendment delta capture lane is available: {0}")]
    DeltaCaptureUnavailable(&'static str),
}

impl ArtifactError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidCodeArtifactBody(_) => ErrorKind::InvalidCodeArtifactBody,
            Self::InvalidBlobArtifactBody(_) => ErrorKind::InvalidBlobArtifactBody,
            Self::InvalidLfsObject(_) => ErrorKind::InvalidLfsObject,
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
            Self::InvalidAttemptQueueRecord(_) => ErrorKind::InvalidAttemptQueueRecord,
            Self::InvalidAttemptQueueTransition { .. } => ErrorKind::InvalidAttemptQueueTransition,
            Self::DeltaCaptureUnavailable(_) => ErrorKind::DeltaCaptureUnavailable,
        }
    }
}
