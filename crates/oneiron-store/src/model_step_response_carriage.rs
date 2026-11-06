//! How a checkpoint carries a terminal `dreamer.step` claim whose response
//! rests inline in its `entities` row: the claim's body, and a stub with the
//! step value taken. The model step layer (`llm::step`) writes these claims
//! and retires their responses; the store's response body scan carries them.
use crate::model_step_record::DREAMER_STEP_PREDICATE;
use rmpv::Value;

use crate::write_envelope::claim_body::decode_claim_body;
use crate::write_envelope::claim_body::encode_claim_body;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;

pub const KEY_RESPONSE: &str = "response";

/// Whether a `dreamer.step` claim value holds its response inline.
pub fn holds_response(value: &Value) -> bool {
    matches!(value, Value::Map(entries)
        if entries.iter().any(|(key, _)| key.as_str() == Some(KEY_RESPONSE)))
}
