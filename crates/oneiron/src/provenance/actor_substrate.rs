//! Provenance vocabulary defined below the claim layer.
pub use crate::write_envelope::provenance::actor_substrate::{validate_actor_class, MODEL_SUBSTRATE_FIELD_MAX_BYTES};
pub(super) use crate::write_envelope::provenance::actor_substrate::{actor_class_from_u8, validate_model_substrate_field, encode_model_entity_body};
pub(crate) use crate::write_envelope::provenance::actor_substrate::{resolve_persisted_actor_class, decode_model_entity_body};
