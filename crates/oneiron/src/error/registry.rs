//! Registry-domain errors: structural-kind registration, entity-type and
//! edge-kind refusals raised by the registry and the edge doors.
//!
//! Reached from the root as `Error::Registry(..)`, a transparent wrapper:
//! Display and `source()` are the leaf's, so every message string is what it
//! was when these variants sat flat on `Error`.

use crate::entity_id::EntityId;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_RELATIONSHIP, TypeByteZone};

use super::ErrorKind;

/// Registry-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
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
    /// Registered maintenance-band entity kind (type bytes 120+, e.g.
    /// REDACTION_AUDIT) rejected on a public write path. Maintenance records
    /// are engine-authored only; this is distinct from
    /// [`Error::InvalidEntityType`](crate::error::Error::InvalidEntityType), which covers genuinely unknown bytes.
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
    /// A public edge write named a kind whose topology writes are reserved
    /// to an engine door (`merged_into` / `split_into` — the ARCH-0055
    /// apply/undo door is the only writer).
    #[error("edge kind is reserved to an engine door: {0}")]
    ReservedEdgeKind(&'static str),
}

impl RegistryError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            // The structural ChildOf tree rejections are coarse-mapped onto
            // the existing TASK-body kind on purpose: remote replay already
            // classifies it quarantine-and-continue, so a new tree check adds
            // no new sync policy (ONE-1376).
            Self::ChildOfParentMissing { .. }
            | Self::TaskChildOfParentNotTask { .. }
            | Self::TaskChildOfNesting { .. } => ErrorKind::InvalidTaskBody,
            Self::InvalidFacet { .. } => ErrorKind::InvalidFacet,
            Self::InvalidRelationship { .. } => ErrorKind::InvalidRelationship,
            Self::InvalidFacetOfEdge { .. } => ErrorKind::InvalidFacetOfEdge,
            Self::MaintenanceKindNotWritable(_) => ErrorKind::MaintenanceKindNotWritable,
            Self::StructuralKindZoneViolation { .. } => ErrorKind::StructuralKindZoneViolation,
            Self::StructuralKindTypeByteCollision(_) | Self::StructuralKindPrefixCollision(_) => {
                ErrorKind::StructuralKindCollision
            }
            Self::InvalidStructuralKindRegistration(_) => {
                ErrorKind::InvalidStructuralKindRegistration
            }
            Self::SurfaceEventCorrelationKindCollision { .. } => {
                ErrorKind::SurfaceEventCorrelationKindCollision
            }
            Self::EntityTypeImmutable { .. } => ErrorKind::EntityTypeImmutable,
            Self::CycleDetected => ErrorKind::CycleDetected,
            Self::ChildOfCardinality => ErrorKind::ChildOfCardinality,
            Self::ReservedEdgeKind(_) => ErrorKind::ReservedEdgeKind,
        }
    }
}
