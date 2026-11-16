//! Deterministic aggregation-session, tested-revision and provenance identifiers.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::fingerprint::purposes;

/// The aggregation SESSION one queue's tested chain shares.
///
/// # Errors
/// An id derivation failure.
pub fn queue_aggregation_session(store: &str, init_work: &str) -> Result<EntityId> {
    EntityId::derive_legacy_material(
        purposes::code::QUEUE_AGGREGATION_SESSION,
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
    EntityId::derive_legacy_material(
        purposes::code::QUEUE_TESTED_REVISION,
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
    EntityId::derive_legacy_material(
        purposes::code::QUEUE_REVISION_PROVENANCE,
        &[revision.as_bytes()],
    )
}
