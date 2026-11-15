//! Doors for tests/msgpack_trailing_refusal.rs (PLAN-UC-08 PR 1). Compiled only under
//! --cfg oneiron_test_support; never API.

use crate::error::Result;

/// Decodes one dreamer-consolidation value through the test door.
pub fn consolidation_value_decode(raw: &[u8]) -> Result<rmpv::Value> {
    crate::dreamer_consolidation::consolidation_value_decode_for_test(raw)
}

/// Decodes one skill-reliability outcome value through the test door.
pub fn outcome_value_decode(raw: &[u8]) -> Result<rmpv::Value> {
    crate::skill_reliability::outcome_value_decode_for_test(raw)
}

/// Decodes one vault-cleanup receipt row through the test door.
pub fn receipt_row_decode(raw: &[u8]) -> Result<Vec<(rmpv::Value, rmpv::Value)>> {
    crate::vault_cleanup::receipt_row_decode_for_test(raw)
}

/// Sample edit-distance miner row bytes for the trailing-bytes test.
pub fn miner_row_sample() -> Vec<u8> {
    crate::edit_distance::miner::miner_mint_mark_sample_for_test()
}

/// Whether `raw` decodes as the edit-distance miner row.
pub fn miner_row_decode(raw: &[u8]) -> bool {
    crate::edit_distance::miner::miner_mint_mark_decode_for_test(raw)
}
