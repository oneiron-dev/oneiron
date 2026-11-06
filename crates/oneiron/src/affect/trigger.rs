//! Affect trigger values and codecs are defined in core write vocabulary.

pub use crate::write_envelope::affect_trigger::{
    AFFECT_TRIGGER_PREDICATE, AffectTriggerValue, VadDelta, affect_trigger_claim_candidate,
    affect_trigger_value, decode_affect_trigger_claim, decode_affect_trigger_value,
};
pub(crate) use crate::write_envelope::affect_trigger::{
    decode_entity_ref, validate_affect_trigger_claim_structure,
};
pub(super) use crate::write_envelope::affect_trigger::{
    decode_vad_delta, reject_duplicate, vad_delta_value,
};
