//! Affect trigger values and codecs are defined in core write vocabulary.

pub use crate::write_envelope::affect_trigger::{AFFECT_TRIGGER_PREDICATE, VadDelta, AffectTriggerValue, affect_trigger_value, decode_affect_trigger_value, decode_affect_trigger_claim, affect_trigger_claim_candidate};
pub(crate) use crate::write_envelope::affect_trigger::{validate_affect_trigger_claim_structure, decode_entity_ref};
pub(super) use crate::write_envelope::affect_trigger::{reject_duplicate, decode_vad_delta, vad_delta_value};
