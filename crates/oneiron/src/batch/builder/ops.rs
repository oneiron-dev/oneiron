//! Batch op vocabulary and shared op constructors.

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::temporal::TimeRange;

pub(crate) use oneiron_store::batch_op::BatchOp;

/// Builds the sync-replay put op — the SINGLE place where the replicated
/// door's two admit flags are set (`allow_maintenance` AND
/// `allow_reserved_predicate`). [`BatchBuilder::put_replicated`] delegates
/// here; no other constructor may open both bands at once.
///
/// A trusted door still validates structure: the flags only skip the
/// public-band rejections (`MaintenanceKindNotWritable` /
/// `ReservedPredicate`). `apply_put` still runs the registry type-byte gate,
/// the full D17/D18 CLAIM body validation, and registered maintenance body
/// validation on every typed maintenance kind that defines one. Policy
/// manifests and AccessGrants are authority-bearing control-plane inputs and
/// are not admitted through this unverified replicated door.
///
/// Compiled for sync production replay and for the test fixtures, which are
/// the only reason this constructor exists in a featureless test build.
///
/// [`BatchBuilder::put_replicated`]: super::BatchBuilder::put_replicated
pub(super) fn replicated_put_op(
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> BatchOp {
    BatchOp::Put {
        id: *id,
        entity_type,
        occurred,
        learned_at,
        data: data.to_vec(),
        allow_maintenance: true,
        allow_reserved_predicate: true,
        hub_sync_imported: false,
    }
}

pub(super) fn capture_invalid_vector_component(
    validation_error: &mut Option<Error>,
    vector: &[f32],
) {
    if validation_error.is_none()
        && let Some(error) = Error::invalid_vector_component(vector)
    {
        *validation_error = Some(error);
    }
}
