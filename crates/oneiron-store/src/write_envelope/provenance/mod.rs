//! Edge provenance and derivation record vocabulary and codecs.

pub mod actor_substrate;
pub mod codec;
pub mod edge_lifecycle;
pub mod edge_ref;
pub mod entity_ref_wire;
pub mod made_by;
pub mod text_commit;

pub use codec::EdgeProvenanceClaimBody;
pub use edge_ref::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeRef, PREDICATE_EDGE_PROVENANCE,
    REASONING_EFFORT_MAX_BYTES, SupersessionStatus,
};
pub use edge_ref::{
    KEY_ACTOR_CLASS, KEY_ACTOR_ENTITY_REF, KEY_BODY_SNAPSHOT_REF, KEY_CONFIDENCE,
    KEY_REASONING_EFFORT, KEY_SOURCE_REVISION_REF, KEY_SUBSTRATE_REF, KEY_SUPERSESSION_STATUS,
    KEY_VALID_FROM, KEY_VALID_TO,
};
pub mod actor_stamp;
pub use actor_stamp::ActorStamp;
