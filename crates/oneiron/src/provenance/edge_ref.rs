//! Provenance vocabulary defined below the claim layer.
pub use crate::write_envelope::provenance::edge_ref::{PREDICATE_EDGE_PROVENANCE, EDGE_REF_LEN, EDGE_PROVENANCE_BODY_KEYS, REASONING_EFFORT_MAX_BYTES, EdgeRef, SupersessionStatus};
pub(crate) use crate::write_envelope::provenance::edge_ref::{KEY_ACTOR_ENTITY_REF, KEY_CONFIDENCE, KEY_VALID_TO};
pub(super) use crate::write_envelope::provenance::edge_ref::{KEY_SOURCE_REVISION_REF, KEY_BODY_SNAPSHOT_REF, KEY_SUPERSESSION_STATUS, KEY_VALID_FROM, KEY_SUBSTRATE_REF, KEY_REASONING_EFFORT, KEY_ACTOR_CLASS};
