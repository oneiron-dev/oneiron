//! Provenance vocabulary defined below the claim layer.
pub use crate::write_envelope::provenance::edge_ref::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeRef, PREDICATE_EDGE_PROVENANCE,
    REASONING_EFFORT_MAX_BYTES, SupersessionStatus,
};
pub(super) use crate::write_envelope::provenance::edge_ref::{
    KEY_ACTOR_CLASS, KEY_BODY_SNAPSHOT_REF, KEY_REASONING_EFFORT, KEY_SOURCE_REVISION_REF,
    KEY_SUBSTRATE_REF, KEY_SUPERSESSION_STATUS, KEY_VALID_FROM,
};
pub(crate) use crate::write_envelope::provenance::edge_ref::{
    KEY_ACTOR_ENTITY_REF, KEY_CONFIDENCE, KEY_VALID_TO,
};
