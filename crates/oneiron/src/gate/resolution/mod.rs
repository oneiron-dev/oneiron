mod accessors;
mod evaluation;
mod frontier_hash;
mod manifest_fold;
mod manifest_types;

pub(super) use self::frontier_hash::{hash_bool, hash_bytes, hash_opt_str, hash_str};
pub(super) use self::manifest_fold::check_claim_source_trust;
pub(crate) use self::manifest_fold::{
    resolve_gate_decision_retention, resolve_policy_manifest, retention_edit_target,
};
pub(super) use self::manifest_types::CommOptOutPosture;
pub(crate) use self::manifest_types::{
    GateDecisionRetentionPolicy, GateRetentionContext, GateRetentionOverrideCeiling,
    GateRetentionPrecedence, GateRetentionRow, GateRetentionScope, PolicyManifestResolution,
};
