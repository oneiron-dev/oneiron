//! Code-domain errors: codebase snapshots and symbol manifests, repo
//! mutations, the micro-VM backend, code review and blast radius, code memory,
//! the git smart-HTTP doors and deployment-independent vault reads.
//!
//! Reached from the root as `Error::Code(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use crate::entity_id::{EntityId, bytes_to_hex_lower};

use super::ErrorKind;

/// Code-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodeError {
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
    /// raises [`Error::IndexOverflow`](crate::error::Error::IndexOverflow)
    /// rather than a partial acyclicity proof.
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
}

impl CodeError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidCodebaseSnapshotBody(_) => ErrorKind::InvalidCodebaseSnapshotBody,
            Self::HostedMediaHashMatchKnownMatch { .. } => {
                ErrorKind::HostedMediaHashMatchKnownMatch
            }
            Self::InvalidCodeSymbolManifestBody(_) => ErrorKind::InvalidCodeSymbolManifestBody,
            Self::InvalidRepoMutationRecord(_) => ErrorKind::InvalidRepoMutationRecord,
            Self::RepoMutationFailed(_) => ErrorKind::RepoMutationFailed,
            Self::RepoMutationRecoveryDiverged { .. } => ErrorKind::RepoMutationRecoveryDiverged,
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
        }
    }
}
