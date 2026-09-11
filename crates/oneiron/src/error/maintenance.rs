//! Maintenance-domain errors: the compaction handoff refusal with its
//! per-axis taxonomy, and the vault-cleanup doors.
//!
//! Reached from the root as `Error::Maintenance(..)`, a transparent wrapper:
//! Display and `source()` are the leaf's, so every message string is what it
//! was when these variants sat flat on `Error`.

use std::fmt;

use crate::entity_id::EntityId;

use super::ErrorKind;

/// Per-axis reason the compaction handoff door refused a
/// [`crate::compaction::CompactionPacket`] (DREAM-008, ONE-1250).
///
/// Each variant is ONE validation axis, so a caller (and a fixture) can
/// match the exact refusal instead of reading a message. Admission is
/// fail-closed on every axis: nothing is written, nothing is partially
/// admitted, and a packet that trips any axis never yields a
/// [`crate::compaction::ValidatedCompactionPacket`].
///
/// [`Self::SessionMembershipNotRecorded`] is deliberately DISTINCT from
/// [`Self::TurnFromOtherSession`]: a turn witnessed before membership
/// recording landed carries no membership fact at all, which is an unknown
/// answer, not a wrong one. It fails closed rather than passing silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompactionPacketError {
    /// The packet's `schema_version` is not
    /// [`crate::compaction::COMPACTION_PACKET_SCHEMA_VERSION`]. There is no
    /// silent migration: an older or newer wire shape is refused outright.
    SchemaMismatch { expected: u16, got: u16 },
    /// The packet carries no turn ids. A handoff that compacts nothing has
    /// no subject and is never admitted.
    EmptyTurnIds,
    /// A referenced turn id does not resolve to any stored entity.
    UnknownTurn { turn: EntityId },
    /// A referenced turn id resolves, but its stored type byte is not
    /// [`crate::registry::ENTITY_TYPE_TURN`].
    TurnNotTurnEntity { turn: EntityId, entity_type: u8 },
    /// A referenced turn resolves as a TURN but carries no recorded
    /// session membership, so its sitting cannot be proven.
    SessionMembershipNotRecorded { turn: EntityId },
    /// A referenced turn's recorded membership names a different session
    /// than the packet's `session_ref`.
    TurnFromOtherSession { turn: EntityId, recorded: EntityId },
    /// The packet's `session_ref` does not resolve to a stored SESSION.
    UnknownSession { session: EntityId },
    /// The packet's snapshot ref is structurally unusable (zero content
    /// hash or zero byte length).
    SnapshotMalformed(&'static str),
    /// The packet's snapshot ref differs from the expected ref the caller
    /// supplied. The engine never resolves a foreign snapshot store, so
    /// this axis is reachable only through that caller-supplied ref.
    SnapshotMismatch { field: &'static str },
    /// The packet's payload-kind byte is outside the closed
    /// [`crate::compaction::CompactionPayloadKind`] set.
    PayloadKindUnknown { byte: u8 },
    /// The payload fields violate the shape pinned for the packet's kind.
    PayloadShapeViolation(&'static str),
}

impl fmt::Display for CompactionPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, got } => {
                write!(f, "schema version mismatch: expected {expected}, got {got}")
            }
            Self::EmptyTurnIds => f.write_str("packet carries no turn ids"),
            Self::UnknownTurn { turn } => {
                write!(f, "turn {} does not resolve", turn.to_hex())
            }
            Self::TurnNotTurnEntity { turn, entity_type } => write!(
                f,
                "entity {} is type {entity_type}, not a TURN",
                turn.to_hex()
            ),
            Self::SessionMembershipNotRecorded { turn } => write!(
                f,
                "turn {} has no recorded session membership",
                turn.to_hex()
            ),
            Self::TurnFromOtherSession { turn, recorded } => write!(
                f,
                "turn {} belongs to session {}",
                turn.to_hex(),
                recorded.to_hex()
            ),
            Self::UnknownSession { session } => {
                write!(f, "session {} does not resolve", session.to_hex())
            }
            Self::SnapshotMalformed(detail) => write!(f, "malformed snapshot ref: {detail}"),
            Self::SnapshotMismatch { field } => {
                write!(f, "snapshot ref {field} does not match the expected ref")
            }
            Self::PayloadKindUnknown { byte } => write!(f, "unknown payload kind byte {byte}"),
            Self::PayloadShapeViolation(detail) => {
                write!(f, "payload shape violation: {detail}")
            }
        }
    }
}

/// Maintenance-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MaintenanceError {
    /// A compaction handoff packet was refused at the admission door
    /// (DREAM-008, ONE-1250). Fail-closed on every axis: the carried
    /// [`CompactionPacketError`] names the exact axis, and no
    /// [`crate::compaction::ValidatedCompactionPacket`] is minted.
    #[error("compaction packet rejected: {0}")]
    CompactionPacketRejected(CompactionPacketError),
    /// [`crate::Vault::restore_archived`] was called on an entity that
    /// carries no `archived_by_cleanup` marker (ONE-1931).
    ///
    /// The restore door is scoped to cleanup archives ALONE, and this is the
    /// refusal that keeps it there: a `user_delete` shell, a hard-purged id
    /// and a live row all land here, so the door can never become a general
    /// un-delete for tombstones the owner or a regulator asked for.
    #[error("restore refused: {entity} carries no archived_by_cleanup marker")]
    VaultCleanupRestoreNotArchived {
        /// Lowercase hex entity id.
        entity: String,
    },
    /// A cleanup-archive marker exists for the entity but its bytes are not
    /// an `archived_by_cleanup` tombstone value (ONE-1931).
    ///
    /// Fail-closed, matching the tombstone decode law it borrows: a marker
    /// the engine cannot read as an archive is never treated as one, so a
    /// corrupt row refuses the restore instead of reviving a shell on a guess.
    #[error("cleanup archive marker for {entity} is not readable as an archive: {reason}")]
    VaultCleanupArchiveMarkerUndecodable {
        /// Lowercase hex entity id.
        entity: String,
        /// Why the marker could not be read as an archive.
        reason: &'static str,
    },
    /// No cleanup proposal exists under the given id (ONE-1931). An accept or
    /// reject of an already-resolved proposal lands here rather than silently
    /// doing nothing.
    #[error("vault cleanup proposal {proposal} not found")]
    VaultCleanupProposalNotFound {
        /// Lowercase hex proposal id.
        proposal: String,
    },
    /// The vault-cleanup cron was registered on a wake it does not run on
    /// (ONE-1931). ARCH-0073 puts the cleanup pass on the TIMER wake (Macro
    /// scope); registering it on a compaction/session-end/event wake would
    /// make an interactive turn pay for a maintenance scan.
    #[error("vault cleanup registers on the timer wake only, not {trigger}")]
    VaultCleanupWakeTriggerRejected {
        /// The refused trigger's name.
        trigger: &'static str,
    },
}

impl From<CompactionPacketError> for MaintenanceError {
    fn from(value: CompactionPacketError) -> Self {
        Self::CompactionPacketRejected(value)
    }
}

impl MaintenanceError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::CompactionPacketRejected(_) => ErrorKind::CompactionPacketRejected,
            Self::VaultCleanupRestoreNotArchived { .. } => {
                ErrorKind::VaultCleanupRestoreNotArchived
            }
            Self::VaultCleanupArchiveMarkerUndecodable { .. } => {
                ErrorKind::VaultCleanupArchiveMarkerUndecodable
            }
            Self::VaultCleanupProposalNotFound { .. } => ErrorKind::VaultCleanupProposalNotFound,
            Self::VaultCleanupWakeTriggerRejected { .. } => {
                ErrorKind::VaultCleanupWakeTriggerRejected
            }
        }
    }
}
