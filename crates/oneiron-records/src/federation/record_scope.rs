//! Moved from `crates/oneiron/src/federation/record_scope.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[cfg(feature = "sync")]
pub(crate) use crate::federation::record_scope::birth_placement::carries_birth_placement;
use oneiron_authority::federation::Scope;
use oneiron_authority::federation::ScopeAxis;
use oneiron_authority::federation::ScopeId;
use oneiron_authority::federation::Sensitivity;
use oneiron_authority::federation::SensitivityCeiling;
use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::batch::row_put::RowPut;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub fn singleton<T: Ord>(v: T) -> ScopeAxis<T> {
    ScopeAxis::Some(BTreeSet::from([v]))
}

pub fn default_stamp(kind: u8, facet: EntityId) -> Scope {
    Scope {
        worlds: singleton(ScopeId(
            oneiron_store::write_envelope::claim_body::base_world_id(),
        )),
        facets: singleton(ScopeId(facet)),
        bands: singleton(kind),
        audience: singleton(ScopeId(
            oneiron_store::write_envelope::claim_body::default_project_id(),
        )),
        // The record itself is not a capability. The operation is bound at evaluation.
        verbs: ScopeAxis::Bottom,
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Sensitive),
    }
}
#[cfg(feature = "sync")]
pub mod birth_placement;
