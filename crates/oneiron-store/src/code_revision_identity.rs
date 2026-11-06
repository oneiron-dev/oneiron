//! Deterministic aggregation-session, tested-revision and provenance identifiers.

use crate::code_snapshot::ids::entity_id_from_hash_material;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The aggregation SESSION one queue's tested chain shares.
///
/// # Errors
/// An id derivation failure.
pub fn queue_aggregation_session(store: &str, init_work: &str) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-aggregation-session:v1",
        &[store.as_bytes(), init_work.as_bytes()],
    )
}

/// The deterministic id of one tested revision: the queue's store and
/// checked init, the target, the exact checked commit and tree and the plan.
///
/// # Errors
/// An id derivation failure.
pub fn queue_revision_id(
    store: &str,
    init_work: &str,
    target: &str,
    commit: &str,
    tree: &str,
    plan_digest: &str,
) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-tested-revision:v1",
        &[
            store.as_bytes(),
            init_work.as_bytes(),
            target.as_bytes(),
            commit.as_bytes(),
            tree.as_bytes(),
            plan_digest.as_bytes(),
        ],
    )
}

/// The aggregate provenance claim's id for `revision`.
///
/// # Errors
/// An id derivation failure.
pub fn queue_provenance_id(revision: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:queue-revision-provenance:v1",
        &[revision.as_bytes()],
    )
}
