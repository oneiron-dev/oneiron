mod decode_manifest;
mod decode_map_util;
mod decode_policy_tables;
mod decode_trust_budget;

// Re-exposes the `breaker` module under the pre-split `super::breaker` path
// one moved body still spells; `use` bindings are module plumbing.
use super::breaker;

pub(super) use self::decode_manifest::decode_policy_manifest;
// Test-only name the gate test seam reaches through `use self::decode::*`
// (gate/mod.rs); gating the re-export keeps the non-test build warning-free.
#[cfg(test)]
pub(super) use self::decode_policy_tables::parse_delegated_grants;
