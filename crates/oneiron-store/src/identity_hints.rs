//! Per-kind declared identity fields (human-facing identity hints).

use oneiron_contracts::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};

/// Declared hints for kinds with human-facing identities. None is unique.
pub fn identity_fields_for_kind(kind: u8) -> &'static [&'static str] {
    match kind {
        ENTITY_TYPE_PERSON => &["name", "aliases", "phonetic", "contact_handle"],
        ENTITY_TYPE_ORG | ENTITY_TYPE_PLACE => &["name", "aliases", "phonetic"],
        _ => &[],
    }
}
