//! Edge provenance and derivation record vocabulary and codecs.

pub mod actor_substrate;
pub mod codec;
pub mod edge_ref;
pub mod edge_lifecycle;
pub(crate) mod entity_ref_wire;
pub mod made_by;
pub mod text_commit;

pub use codec::EdgeProvenanceClaimBody;
pub use edge_ref::{PREDICATE_EDGE_PROVENANCE, EDGE_REF_LEN, EDGE_PROVENANCE_BODY_KEYS, REASONING_EFFORT_MAX_BYTES, EdgeRef, SupersessionStatus};
pub(crate) use edge_ref::{KEY_ACTOR_ENTITY_REF, KEY_CONFIDENCE, KEY_VALID_TO, KEY_SOURCE_REVISION_REF, KEY_BODY_SNAPSHOT_REF, KEY_SUPERSESSION_STATUS, KEY_VALID_FROM, KEY_SUBSTRATE_REF, KEY_REASONING_EFFORT, KEY_ACTOR_CLASS};
pub mod actor_stamp;
pub use actor_stamp::ActorStamp;
