mod decode_manifest;
mod decode_map_util;
mod decode_policy_tables;
mod decode_trust_budget;
mod policy_scope_migration;

pub(super) use self::decode_manifest::decode_policy_manifest;
// Test-only name the gate test seam reaches through `use self::decode::*`
// (gate/mod.rs); gating the re-export keeps the non-test build warning-free.
#[cfg(test)]
pub(super) use self::decode_policy_tables::parse_delegated_grants;

pub(crate) use self::policy_scope_migration::normalize_policy_manifest_scope;
