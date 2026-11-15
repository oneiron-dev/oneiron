//! Moved from `crates/oneiron/src/compaction/check_material.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::body_descriptor::BodyRef;
use crate::store::body_descriptor::BodyState;
use crate::store::body_descriptor::OwnedBody;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where a conversation summary's check material is, and what it is (FIX
/// 5040): its occurrence, which is the sealed request's job id, and its
/// body, which is the BLAKE3 digest and byte length of its encoding, held
/// inline in its row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionCheckMaterialRef {
    pub occurrence: EntityId,
    pub body: BodyRef,
}

/// The body that `reference` names, owned by `summary`.
pub fn bound_body(summary: EntityId, reference: &CompactionCheckMaterialRef) -> OwnedBody {
    OwnedBody {
        owner: summary,
        occurrence: reference.occurrence,
        mark_occurrence: reference.occurrence,
        state: BodyState::Complete {
            body: reference.body.clone(),
        },
        result: None,
        // A compaction's check material is no code run's output.
        code_run_output: None,
    }
}
