//! Manifest envelope plus DecodedPolicyManifest assembly.

use std::io::Cursor;

use rmpv::Value;

use crate::gate::breaker::{GATE_BREAKER_POLICY_KEY, GateBreakerThresholds};
use crate::gate::ceiling::{
    ActorCeiling, DelegationGrantRecord, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack,
    PolicySignature, SourceTrustCeiling,
};
use crate::gate::constants::{
    POLICY_ACTOR_CEILINGS_KEY, POLICY_AUTO_CHECKER_KEY, POLICY_BUDGET_POLICY_KEY,
    POLICY_COMM_OPT_OUT_POSTURE_KEY, POLICY_DEFAULTS_KEY, POLICY_DELEGATED_GRANTS_KEY,
    POLICY_LEGAL_FLOOR_ROWS_KEY, POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY,
    POLICY_OWNER_POLICY_DOCUMENT_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY, POLICY_OWNER_POLICY_PATTERNS_KEY,
    POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY, POLICY_PACK_VERSION_KEY, POLICY_RULES_KEY,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY,
    POLICY_SIGNATURE_KEY, POLICY_SIGNATURES_KEY, POLICY_SOURCE_TRUST_KEY,
};
use crate::gate::grants::PolicyScopedGrant;
use crate::gate::resolution::CommOptOutPosture;
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};

use super::decode_map_util::{
    MapValue, parse_signature_value, parse_signatures, required_string, required_value,
    single_map_value, version_gt,
};
use super::decode_policy_tables::{
    parse_actor_ceilings, parse_axes, parse_delegated_grants, parse_owner_policy_patterns,
    parse_owner_policy_rows, parse_rules, parse_scoped_grants,
};
use super::decode_trust_budget::{
    parse_budget_exhaustion_policy, parse_budget_policy, parse_comm_opt_out_posture,
    parse_source_trust,
};

pub(in crate::gate) struct DecodedPolicyManifest {
    pub(in crate::gate) pack: PolicyPack,
    pub(in crate::gate) actor_ceilings: Vec<ActorCeiling>,
    pub(in crate::gate) delegated_grants: Vec<DelegationGrantRecord>,
    pub(in crate::gate) source_trust: SourceTrustCeiling,
    pub(in crate::gate) scoped_grants: Vec<PolicyScopedGrant>,
    pub(in crate::gate) owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    pub(in crate::gate) owner_policy_rows_dropped: bool,
    pub(in crate::gate) owner_policy_enabled: bool,
    pub(in crate::gate) owner_policy_document: Option<String>,
    pub(in crate::gate) owner_policy_output_contract: Option<String>,
    pub(in crate::gate) owner_policy_patterns: Vec<PolicyOwnerPatternRow>,
    pub(in crate::gate) owner_policy_patterns_dropped: bool,
    pub(in crate::gate) signatures: Vec<PolicySignature>,
    pub(in crate::gate) on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    pub(in crate::gate) comm_opt_out_posture: Option<CommOptOutPosture>,
    /// The opaque host checker ref (ONE-1296), absent unless the manifest
    /// names one.
    pub(in crate::gate) auto_checker: Option<String>,
    pub(in crate::gate) budget_policy: BudgetPolicyTable,
    /// ONE-1453: this manifest's burst-breaker candidate. `None` covers both
    /// an absent key and a malformed override — a malformed override
    /// contributes NO candidate to the cross-manifest fold and never makes the
    /// manifest itself malformed.
    pub(in crate::gate) actor_burst_breaker: Option<GateBreakerThresholds>,
    pub(in crate::gate) unsupported_schema: bool,
    pub(in crate::gate) engine_version_floor: bool,
    pub(in crate::gate) unknown_axis_seen: bool,
}

pub(in crate::gate) fn decode_policy_manifest(data: &[u8]) -> Option<DecodedPolicyManifest> {
    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != data.len() as u64 {
        return None;
    }
    let Value::Map(entries) = value else {
        return None;
    };
    for (key, _) in &entries {
        let key = key.as_str()?;
        if !matches!(
            key,
            POLICY_SCHEMA_VERSION_KEY
                | POLICY_PACK_ID_KEY
                | POLICY_PACK_VERSION_KEY
                | POLICY_MIN_ENGINE_VERSION_KEY
                | POLICY_DEFAULTS_KEY
                | POLICY_RULES_KEY
                | POLICY_ACTOR_CEILINGS_KEY
                | POLICY_DELEGATED_GRANTS_KEY
                | POLICY_SOURCE_TRUST_KEY
                | POLICY_SCOPED_GRANTS_KEY
                | POLICY_OWNER_POLICY_ROWS_KEY
                | POLICY_OWNER_POLICY_ENABLED_KEY
                | POLICY_OWNER_POLICY_DOCUMENT_KEY
                | POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY
                | POLICY_OWNER_POLICY_PATTERNS_KEY
                // Retired, accepted and ignored so manifests written before
                // the engine floor was removed still decode. See the const.
                | POLICY_LEGAL_FLOOR_ROWS_KEY
                | POLICY_SIGNATURE_KEY
                | POLICY_SIGNATURES_KEY
                | POLICY_ON_BUDGET_EXHAUSTED_KEY
                | POLICY_COMM_OPT_OUT_POSTURE_KEY
                | POLICY_AUTO_CHECKER_KEY
                | POLICY_BUDGET_POLICY_KEY
                | GATE_BREAKER_POLICY_KEY
        ) {
            return None;
        }
    }

    let unsupported_schema = match single_map_value(&entries, POLICY_SCHEMA_VERSION_KEY) {
        MapValue::Missing => true,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => value.as_str()? != POLICY_SCHEMA_VERSION,
    };
    let pack_id = required_string(&entries, POLICY_PACK_ID_KEY)?;
    let pack_version = required_string(&entries, POLICY_PACK_VERSION_KEY)?;
    let min_engine_version = required_string(&entries, POLICY_MIN_ENGINE_VERSION_KEY)?;
    let engine_version_floor = version_gt(&min_engine_version, env!("CARGO_PKG_VERSION"))?;
    let defaults = parse_axes(required_value(&entries, POLICY_DEFAULTS_KEY)?)?;
    let rules = parse_rules(required_value(&entries, POLICY_RULES_KEY)?)?;
    let actor_ceilings =
        parse_actor_ceilings(required_value(&entries, POLICY_ACTOR_CEILINGS_KEY)?)?;

    let delegated_grants = match single_map_value(&entries, POLICY_DELEGATED_GRANTS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_delegated_grants(value)?,
    };
    let source_trust = match single_map_value(&entries, POLICY_SOURCE_TRUST_KEY) {
        MapValue::Missing => SourceTrustCeiling::default(),
        MapValue::Duplicate => SourceTrustCeiling::malformed(),
        MapValue::Present(value) => {
            parse_source_trust(value).unwrap_or_else(SourceTrustCeiling::malformed)
        }
    };
    let scoped_grants = match single_map_value(&entries, POLICY_SCOPED_GRANTS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_scoped_grants(value)?,
    };
    let owner_policy_enabled = match single_map_value(&entries, POLICY_OWNER_POLICY_ENABLED_KEY) {
        MapValue::Missing => false,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Boolean(value)) => *value,
        MapValue::Present(_) => return None,
    };
    let (owner_policy_rows, owner_policy_rows_dropped) =
        match single_map_value(&entries, POLICY_OWNER_POLICY_ROWS_KEY) {
            MapValue::Missing => (Vec::new(), false),
            MapValue::Duplicate => (Vec::new(), true),
            MapValue::Present(value) => match parse_owner_policy_rows(value) {
                Some(rows) => (rows, false),
                None => (Vec::new(), true),
            },
        };
    let owner_policy_document = match single_map_value(&entries, POLICY_OWNER_POLICY_DOCUMENT_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(nonblank_bounded_string(
            value,
            OWNER_POLICY_DOCUMENT_MAX_LEN,
        )?),
    };
    let owner_policy_output_contract =
        match single_map_value(&entries, POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(nonblank_bounded_string(
                value,
                OWNER_POLICY_OUTPUT_CONTRACT_MAX_LEN,
            )?),
        };
    let (owner_policy_patterns, owner_policy_patterns_dropped) =
        match single_map_value(&entries, POLICY_OWNER_POLICY_PATTERNS_KEY) {
            MapValue::Missing => (Vec::new(), false),
            MapValue::Duplicate => (Vec::new(), true),
            MapValue::Present(value) => match parse_owner_policy_patterns(value) {
                Some(rows) => (rows, false),
                None => (Vec::new(), true),
            },
        };
    let mut signatures = match single_map_value(&entries, POLICY_SIGNATURE_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => vec![parse_signature_value(value)?],
    };
    match single_map_value(&entries, POLICY_SIGNATURES_KEY) {
        MapValue::Missing => {}
        MapValue::Duplicate => return None,
        MapValue::Present(value) => signatures.extend(parse_signatures(value)?),
    }
    let on_budget_exhausted = match single_map_value(&entries, POLICY_ON_BUDGET_EXHAUSTED_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_budget_exhaustion_policy(value)?),
    };
    // Parsed exactly like its `on_budget_exhausted` sibling, and failing the
    // same way: an unrecognized token drops the WHOLE manifest, which sets
    // `malformed_manifest_seen` and fails the gate closed. A posture nobody can
    // read must never resolve to the permissive pole by silent default.
    let comm_opt_out_posture = match single_map_value(&entries, POLICY_COMM_OPT_OUT_POSTURE_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_comm_opt_out_posture(value)?),
    };
    // ONE-1296: the checker ref is a SELECTOR the host resolves, so decode
    // asks only that it be one non-blank, bounded string. A duplicate row is
    // the same ambiguity `on_budget_exhausted` refuses, and a blank or
    // oversized value is a misconfigured knob rather than "no checker" — both
    // reject the whole manifest, which fails the gate closed.
    let auto_checker = match single_map_value(&entries, POLICY_AUTO_CHECKER_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(nonblank_bounded_string(value, AUTO_CHECKER_REF_MAX_LEN)?),
    };
    let budget_policy = match single_map_value(&entries, POLICY_BUDGET_POLICY_KEY) {
        MapValue::Missing => BudgetPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_budget_policy(value)?,
    };
    let actor_burst_breaker = super::breaker::decode_gate_breaker_override(&entries);

    let unknown_axis_seen =
        defaults.unknown_axis_seen || rules.iter().any(|rule| rule.axes.unknown_axis_seen);

    Some(DecodedPolicyManifest {
        pack: PolicyPack {
            _pack_id: pack_id,
            _pack_version: pack_version,
            _min_engine_version: min_engine_version,
            defaults,
            rules,
        },
        actor_ceilings,
        delegated_grants,
        source_trust,
        scoped_grants,
        owner_policy_rows,
        owner_policy_rows_dropped,
        owner_policy_enabled,
        owner_policy_document,
        owner_policy_output_contract,
        owner_policy_patterns,
        owner_policy_patterns_dropped,
        signatures,
        on_budget_exhausted,
        comm_opt_out_posture,
        auto_checker,
        budget_policy,
        actor_burst_breaker,
        unsupported_schema,
        engine_version_floor,
        unknown_axis_seen,
    })
}

/// Longest owner policy document a manifest may carry, mirroring the bound the
/// hosted plane's registration enforces. Spelled here rather than imported:
/// `gate` sits under `policy_model`, and
/// `policy_model::tests::owner_and_hosted_document_bounds_agree` pins the two
/// numbers together.
pub(super) const OWNER_POLICY_DOCUMENT_MAX_LEN: usize = 65_536;

/// Longest output-contract NAME a manifest may carry. It is a preset spelling
/// (`binary`, `category_json`, …) that `policy_model` looks up, so the bound
/// only has to keep a manifest from carrying a blob where a keyword belongs.
pub(super) const OWNER_POLICY_OUTPUT_CONTRACT_MAX_LEN: usize = 64;

/// Longest auto-checker REF a manifest may carry (ONE-1296). Same reasoning
/// as the output contract above: the value is a selector the host resolves,
/// so the bound only keeps a manifest from carrying a blob where a name
/// belongs.
pub(super) const AUTO_CHECKER_REF_MAX_LEN: usize = 256;

pub(super) fn nonblank_bounded_string(value: &Value, max_len: usize) -> Option<String> {
    let value = value.as_str()?;
    if value.trim().is_empty() || value.len() > max_len {
        return None;
    }
    Some(value.to_owned())
}
