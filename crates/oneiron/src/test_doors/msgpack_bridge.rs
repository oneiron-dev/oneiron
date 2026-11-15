//! Doors for tests/msgpack_bridge_guard.rs (PLAN-UC-08 PR 6a). Compiled only under
//! --cfg oneiron_test_support; never API.

use rmpv::Value;

/// The JSON a claim class's schema checks for a claim value, when JSON holds the
/// value exactly; else none.
pub fn claim_value_json(value: &Value) -> Option<serde_json::Value> {
    crate::store::claim_descriptors::json_value(value)
}

/// The JSON form of a vault-shape manifest body, when writing it back gives
/// exactly the body; else none.
pub fn manifest_json(body: &[u8]) -> Option<serde_json::Value> {
    crate::vault_shape::manifest_json_for_test(body)
}
