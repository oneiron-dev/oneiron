//! Core half of `store::model_step_response_carriage`: its store-layer items live in `oneiron_store::model_step_response_carriage` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::model_step_response_carriage::*;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::store::{ResponseCarriage, ResponseScan};
use crate::write_envelope::claim_body::{decode_claim_body, encode_claim_body};
use oneiron_store::model_step_record::DREAMER_STEP_PREDICATE;
use rmpv::Value;

/// What a checkpoint carries of the `entities` row `value` when it is a
/// terminal `dreamer.step` claim whose response rests in it: the claim's
/// body; the stub keeps its header and the claim with its step value taken,
/// and a retired instance keeps its header alone. No response for any other
/// row. A body naming the `dreamer.step` predicate that does not decode, or
/// whose stub does not encode, is carried whole past its header as an opaque
/// response (FIX 6227): a header-only shell names none.
pub(crate) fn step_claim_carriage(value: &[u8]) -> ResponseScan {
    let Some(body) = value.get(ENTITY_METADATA_HEADER_LEN..) else {
        return ResponseScan::NotResponse;
    };
    // Most claims are not a step's: their bodies are never decoded here.
    let predicate = DREAMER_STEP_PREDICATE.as_bytes();
    if !body
        .windows(predicate.len())
        .any(|window| window == predicate)
    {
        return ResponseScan::NotResponse;
    }
    let Ok(mut claim) = decode_claim_body(body, true) else {
        return ResponseScan::opaque_claim(value);
    };
    if claim.predicate != DREAMER_STEP_PREDICATE || !holds_response(&claim.value) {
        return ResponseScan::NotResponse;
    }
    claim.value = Value::Nil;
    let Ok(encoded) = encode_claim_body(&claim) else {
        return ResponseScan::opaque_claim(value);
    };
    let mut stub = value[..ENTITY_METADATA_HEADER_LEN].to_vec();
    stub.extend(encoded);
    ResponseScan::Decoded(ResponseCarriage {
        keep: ENTITY_METADATA_HEADER_LEN,
        stub,
        retired: ENTITY_METADATA_HEADER_LEN,
    })
}
