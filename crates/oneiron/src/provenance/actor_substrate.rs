//! Provenance vocabulary defined below the claim layer.
pub use crate::write_envelope::provenance::actor_substrate::{
    MODEL_SUBSTRATE_FIELD_MAX_BYTES, validate_actor_class,
};
pub(super) use crate::write_envelope::provenance::actor_substrate::{
    actor_class_from_u8, encode_model_entity_body, validate_model_substrate_field,
};
pub(crate) use crate::write_envelope::provenance::actor_substrate::{
    decode_model_entity_body, resolve_persisted_actor_class,
};
