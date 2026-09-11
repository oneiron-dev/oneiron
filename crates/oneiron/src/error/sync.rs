//! Sync-domain errors: the CRDT window/protocol/engine failures behind
//! `feature = "sync"`, plus the replay-receipt and identity-topology refusals
//! that ride the same doors and are reachable without the feature.
//!
//! Reached from the root as `Error::Sync(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

#[cfg(feature = "sync")]
use std::error::Error as StdError;
#[cfg(feature = "sync")]
use std::fmt;

#[cfg(feature = "sync")]
use crate::entity_id::EntityId;

use super::ErrorKind;

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
    GrantExpired,
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
            Self::GrantExpired => "sync selector grant expired",
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

/// Sync-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
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
    /// A REDACTION_AUDIT blob arriving through a sync replay door
    /// failed structural validation against the pinned contracts.ts
    /// `redactionAuditReceipt` field set (request_id, scope, reason,
    /// requested_at, soft_complete_at, hard_purge_complete_at,
    /// sweep_queued_at?, sweep_complete_at?, affected_revision_ids,
    /// verification — opaque identifiers + timestamps only). Fail-closed:
    /// nothing was written; the replay doors quarantine the blob (`x:`
    /// family, ONE-1134).
    #[error("invalid redaction audit receipt body: {0}")]
    InvalidRedactionReceiptBody(&'static str),
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
    /// An ARCH-0055 r7 proposal amendment left the reviewed proposal's scope
    /// (ONE-1747): a different op kind, a subject the proposal never named,
    /// or a body that does not decode as an op at all. An amendment narrows
    /// what the decider reviewed — it is never a capability to substitute
    /// one operation for another. Fail-closed: nothing is applied and the
    /// park stays open.
    #[error("identity proposal amendment is out of scope: {0}")]
    IdentityProposalAmendmentOutOfScope(&'static str),
}

impl SyncError {
    /// Constructs a typed sync protocol validation failure.
    #[cfg(feature = "sync")]
    #[must_use]
    pub(crate) fn sync_protocol(context: SyncProtocolValidation) -> Self {
        Self::SyncProtocolError { context }
    }

    /// Constructs a typed sync engine failure while preserving its source.
    #[cfg(feature = "sync")]
    pub(crate) fn sync_engine<E>(context: SyncEngineContext, source: E) -> Self
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
    pub(crate) fn sync_engine_rollback<Operation, Rollback>(
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

    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
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
            Self::IdentityProposalAmendmentOutOfScope(_) => {
                ErrorKind::IdentityProposalAmendmentOutOfScope
            }
            Self::InvalidIdentityTopologyEventBody(_) => {
                ErrorKind::InvalidIdentityTopologyEventBody
            }
            #[cfg(feature = "sync")]
            Self::IdentityTopologyEventDivergence { .. } => {
                ErrorKind::IdentityTopologyEventDivergence
            }
        }
    }
}
