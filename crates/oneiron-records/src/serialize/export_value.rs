//! Moved from `crates/oneiron/src/serialize/export_value.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;

/// How deep text decoded inside text is read before its original bytes are
/// kept, as deep as the document pass reads. A value's own structure spends
/// none of it (FIX 10097).
pub const TEXT_DEPTH: usize = 128;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault export: {reason}"))
}

pub fn reference_field(key: &str, bytes: &[u8], entity_type: u8, depth: usize) -> bool {
    if entity_type != oneiron_base::registry::ENTITY_TYPE_CLAIM {
        return false;
    }
    if depth > 1 && key != oneiron_store::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY {
        return false;
    }
    match key {
        "subj" => oneiron_store::write_envelope::claim_body::ClaimSubject::decode(bytes).is_ok(),
        "actor_entity_ref" => <[u8; 16]>::try_from(bytes)
            .ok()
            .is_some_and(|id| oneiron_contracts::entity_id::EntityId::from_bytes(id).is_ok()),
        _ => false,
    }
}
