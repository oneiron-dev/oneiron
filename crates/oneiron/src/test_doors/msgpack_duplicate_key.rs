//! Doors for tests/msgpack_duplicate_key_refusal.rs (PLAN-UC-08 PR 1b). Compiled only under
//! --cfg oneiron_test_support; never API.

/// Whether `raw` decodes as a vault-cleanup proposal through the test door.
pub fn cleanup_proposal_decodes(raw: &[u8]) -> bool {
    crate::vault_cleanup::cleanup_proposal_decodes_for_test(raw)
}

/// How many ids `raw` names as a vault-cleanup proposal through the test door.
pub fn cleanup_proposal_named_id_count(raw: &[u8]) -> usize {
    crate::vault_cleanup::cleanup_proposal_named_id_count_for_test(raw)
}

/// The vault-cleanup proposal schema version through the test door.
pub fn cleanup_proposal_schema_version() -> u64 {
    crate::vault_cleanup::cleanup_proposal_schema_version_for_test()
}

/// Whether `raw` decodes as a skill-reliability outcome row through the test door.
pub fn outcome_row_decodes(raw: &[u8]) -> bool {
    crate::skill_reliability::outcome_row_decodes_for_test(raw)
}

/// The skill-reliability outcome-row schema version through the test door.
pub fn outcome_row_schema_version() -> u64 {
    crate::skill_reliability::outcome_row_schema_version_for_test()
}
