//! Manifest envelope plus DecodedPolicyManifest assembly.

use std::io::Cursor;

use rmpv::Value;

use crate::gate::PackInstallPolicy;
use crate::gate::ceiling::{
    ActorCeiling, DelegationGrantRecord, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack,
    PolicySignature, SourceTrustCeiling,
};
use crate::gate::constants::{
    POLICY_ACTOR_CEILINGS_KEY, POLICY_AUTO_CHECKER_KEY, POLICY_BUDGET_POLICY_KEY,
    POLICY_COMM_OPT_OUT_POSTURE_KEY, POLICY_DEFAULTS_KEY, POLICY_DELEGATED_GRANTS_KEY,
    POLICY_HOSTED_TTS_KEY, POLICY_LEGAL_FLOOR_ROWS_KEY, POLICY_MIN_ENGINE_VERSION_KEY,
    POLICY_ON_BUDGET_EXHAUSTED_KEY, POLICY_OWNER_POLICY_DOCUMENT_KEY,
    POLICY_OWNER_POLICY_ENABLED_KEY, POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY,
    POLICY_OWNER_POLICY_PATTERNS_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY,
    POLICY_PACK_VERSION_KEY, POLICY_PPTX_COMMENT_LIMITS_KEY, POLICY_RULES_KEY,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY,
    POLICY_SHEET_ANSWER_LIMITS_KEY, POLICY_SHEET_ANSWER_PRECEDENCE_KEY, POLICY_SIGNATURE_KEY,
    POLICY_SIGNATURES_KEY, POLICY_SOURCE_TRUST_KEY, POLICY_WEAVE_CORRECTION_POLICY_KEY,
};
use crate::gate::grants::PolicyScopedGrant;
use crate::gate::hosted_tts_policy::HostedTtsPolicy;
use crate::gate::pack_install_policy::KEY as PACK_INSTALL_POLICY_KEY;

use crate::gate::resolution::CommOptOutPosture;
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};
use crate::voice_identity::ref_limits::VoiceRefLimitPolicy;

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
    pub(in crate::gate) single_valued_predicates: std::collections::BTreeSet<String>,
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
    pub(in crate::gate) pack_install_policy: Option<PackInstallPolicy>,
    pub(in crate::gate) pptx_comment_limits:
        Option<crate::edit_roundtrip::pptx::PptxOperationalLimits>,
    pub(in crate::gate) hosted_tts: HostedTtsPolicy,

    pub(in crate::gate) diagnostic_bounds: Option<crate::self_heal::tripwires::TripwireBounds>,
    pub(in crate::gate) proposal_check_threshold: Option<u64>,
    pub(in crate::gate) voice_ref_limits: Option<VoiceRefLimitPolicy>,
    pub(in crate::gate) sheet_answer_limits: Vec<crate::gate::resolution::SheetAnswerLimitRow>,
    pub(in crate::gate) sheet_answer_precedence:
        Option<crate::gate::resolution::SheetAnswerPrecedence>,
    pub(in crate::gate) weave_correction_policy: Option<crate::gate::WeaveCorrectionPolicy>,
    pub(in crate::gate) retry_source_policy:
        Vec<crate::gate::retry_source_policy::RetrySourcePolicyRow>,
    pub(in crate::gate) compilation_policy: Option<crate::edit_distance::miner::CompilationPolicy>,
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
                | "single_valued_predicates"
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
                | PACK_INSTALL_POLICY_KEY
                | POLICY_PPTX_COMMENT_LIMITS_KEY
                | POLICY_HOSTED_TTS_KEY

                | "diagnostic_bounds"
                | "proposal_check_threshold"
                | "voice_ref_limits"
                | POLICY_SHEET_ANSWER_LIMITS_KEY
                | POLICY_SHEET_ANSWER_PRECEDENCE_KEY
                | POLICY_WEAVE_CORRECTION_POLICY_KEY
                | "retry_source_policy"
                | "compilation_policy"
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
    let single_valued_predicates = match single_map_value(&entries, "single_valued_predicates") {
        MapValue::Missing => std::collections::BTreeSet::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_single_valued_predicates(value)?,
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
    let pack_install_policy = match single_map_value(&entries, PACK_INSTALL_POLICY_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(PackInstallPolicy::decode(value.clone())?),
    };
    let budget_policy = match single_map_value(&entries, POLICY_BUDGET_POLICY_KEY) {
        MapValue::Missing => BudgetPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_budget_policy(value)?,
    };
    let pptx_comment_limits = match single_map_value(&entries, POLICY_PPTX_COMMENT_LIMITS_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::edit_roundtrip::pptx::PptxOperationalLimits::from_policy_row(value)?)
        }
    };
    let hosted_tts = match single_map_value(&entries, POLICY_HOSTED_TTS_KEY) {
        MapValue::Missing => HostedTtsPolicy::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => HostedTtsPolicy::parse(value)?,
    };
    let diagnostic_bounds = match single_map_value(&entries, "diagnostic_bounds") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::self_heal::tripwires::TripwireBounds::decode(value)?)
        }
    };

    let proposal_check_threshold = match single_map_value(&entries, "proposal_check_threshold") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(value.as_u64().filter(|value| *value > 0)?),
    };

    let voice_ref_limits = match single_map_value(&entries, "voice_ref_limits") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(VoiceRefLimitPolicy::decode(value)?),
    };

    let sheet_answer_limits = match single_map_value(&entries, POLICY_SHEET_ANSWER_LIMITS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_sheet_answer_limits(value)?,
    };

    let sheet_answer_precedence = match single_map_value(
        &entries,
        POLICY_SHEET_ANSWER_PRECEDENCE_KEY,
    ) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Map(row)) => {
            if row.len() != 1 {
                return None;
            }
            match single_map_value(row, "mode") {
                MapValue::Present(value) if value.as_str() == Some("nested_narrowing_holder_capped_at_vault") =>
                    Some(crate::gate::resolution::SheetAnswerPrecedence::NestedNarrowingHolderCappedAtVault),
                _ => return None,
            }
        }
        _ => return None,
    };
    let weave_correction_policy =
        match single_map_value(&entries, POLICY_WEAVE_CORRECTION_POLICY_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(crate::gate::WeaveCorrectionPolicy::parse(value)?),
        };
    let retry_source_policy = match single_map_value(&entries, "retry_source_policy") {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) => rows
            .iter()
            .map(crate::gate::retry_source_policy::RetrySourcePolicyRow::parse)
            .collect::<Option<Vec<_>>>()?,
        MapValue::Present(_) => return None,
    };
    let compilation_policy = match single_map_value(&entries, "compilation_policy") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::edit_distance::miner::CompilationPolicy::decode(
            value,
        )?),
    };

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
        single_valued_predicates,
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
        pack_install_policy,
        pptx_comment_limits,
        hosted_tts,

        diagnostic_bounds,
        proposal_check_threshold,
        voice_ref_limits,
        sheet_answer_limits,
        sheet_answer_precedence,
        weave_correction_policy,
        retry_source_policy,
        compilation_policy,
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

fn parse_single_valued_predicates(value: &Value) -> Option<std::collections::BTreeSet<String>> {
    let Value::Array(values) = value else {
        return None;
    };
    let mut predicates = std::collections::BTreeSet::new();
    for value in values {
        let predicate = value.as_str()?;
        crate::claim::validate_predicate(predicate, false).ok()?;
        if !predicates.insert(predicate.to_owned()) {
            return None;
        }
    }
    Some(predicates)
}

/// Exact row decoder; a malformed or unknown field rejects the manifest.
fn parse_sheet_answer_limits(
    value: &Value,
) -> Option<Vec<crate::gate::resolution::SheetAnswerLimitRow>> {
    use crate::gate::resolution::SheetAnswerLimitRow;
    let Value::Array(rows) = value else {
        return None;
    };
    if rows.len() > 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(rows.len());
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let Value::Map(fields) = row else {
            return None;
        };
        if fields
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), Some("artifact_ref" | "sheet" | "max_count")))
        {
            return None;
        }
        let artifact_ref = match single_map_value(fields, "artifact_ref") {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                let id = value.as_str()?;
                let parsed = crate::entity_id::EntityId::from_hex(id).ok()?;
                // Accepted rows must match the canonical lookup key; rejecting
                // mixed case prevents a silent widening at both write doors.
                if parsed.to_hex() != id {
                    return None;
                }
                Some(id.to_owned())
            }
        };
        let sheet = match single_map_value(fields, "sheet") {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                artifact_ref.as_ref()?;
                let name = value.as_str()?;
                if name.trim().is_empty() || name.len() > 255 {
                    return None;
                }
                Some(name.to_owned())
            }
        };
        let max_count = match single_map_value(fields, "max_count") {
            MapValue::Present(value) => value.as_u64().filter(|n| *n > 0)?,
            _ => return None,
        };
        if !seen.insert((artifact_ref.clone(), sheet.clone())) {
            return None;
        }
        out.push(SheetAnswerLimitRow {
            artifact_ref,
            sheet,
            max_count,
        });
    }
    Some(out)
}

#[cfg(test)]
mod sheet_answer_limit_tests {
    use super::*;
    use crate::gate::resolution::{PolicyManifestResolution, SheetAnswerLimitRow};

    #[test]
    fn default_and_nested_manifest_rows_restrict_holder_at_vault() {
        let shipped = crate::gate::default_manifest::default_policy_manifest();
        let default = decode_policy_manifest(&shipped).expect("shipped manifest decodes");
        assert_eq!(default.sheet_answer_limits[0].max_count, 4096);
        assert_eq!(
            default.sheet_answer_precedence,
            Some(
                crate::gate::resolution::SheetAnswerPrecedence::NestedNarrowingHolderCappedAtVault
            )
        );
        let artifact = "11111111111111111111111111111111";
        let rows = Value::Array(vec![
            Value::Map(vec![(Value::from("max_count"), Value::from(256u64))]),
            Value::Map(vec![
                (Value::from("artifact_ref"), Value::from(artifact)),
                (Value::from("max_count"), Value::from(128u64)),
            ]),
            Value::Map(vec![
                (Value::from("artifact_ref"), Value::from(artifact)),
                (Value::from("sheet"), Value::from("Private")),
                (Value::from("max_count"), Value::from(32u64)),
            ]),
        ]);
        let parsed = parse_sheet_answer_limits(&rows).expect("nested rows parse");
        let mut policy = PolicyManifestResolution::default();
        policy.sheet_answer_default_max_count = Some(default.sheet_answer_limits[0].max_count);
        policy.sheet_answer_precedence = default.sheet_answer_precedence;
        policy.sheet_answer_limits = parsed;
        let mut raised = PolicyManifestResolution::default();
        raised.sheet_answer_default_max_count = policy.sheet_answer_default_max_count;
        raised.sheet_answer_precedence = policy.sheet_answer_precedence;
        raised.sheet_answer_limits.push(SheetAnswerLimitRow {
            artifact_ref: None,
            sheet: None,
            max_count: 8192,
        });
        assert_eq!(
            raised.sheet_answer_limit(artifact, "Public", Some(8192)),
            Some(8192)
        );
        assert_eq!(
            raised.sheet_answer_limit(artifact, "Public", Some(9000)),
            Some(8192)
        );
        assert_eq!(
            policy.sheet_answer_limit(artifact, "Private", None),
            Some(32)
        );
        assert_eq!(
            policy.sheet_answer_limit(artifact, "Public", Some(64)),
            Some(64)
        );
        assert_eq!(
            policy.sheet_answer_limit("22222222222222222222222222222222", "Private", Some(1000)),
            Some(256)
        );
        assert_eq!(policy.sheet_answer_limit(artifact, "Public", Some(0)), None);
        let mut narrowed = policy;
        narrowed.sheet_answer_limits.push(SheetAnswerLimitRow {
            artifact_ref: Some(artifact.into()),
            sheet: Some("Private".into()),
            max_count: 8,
        });
        assert_eq!(
            narrowed.sheet_answer_limit(artifact, "Private", Some(4096)),
            Some(8)
        );
        let letters = "abababababababababababababababab";
        let upper = letters.to_ascii_uppercase();
        assert!(
            parse_sheet_answer_limits(&Value::Array(vec![Value::Map(vec![
                (Value::from("artifact_ref"), Value::from(upper.as_str())),
                (Value::from("max_count"), Value::from(1u64)),
            ])]))
            .is_none(),
            "accepted uppercase IDs would silently miss canonical lookups"
        );
        let valid = parse_sheet_answer_limits(&Value::Array(vec![Value::Map(vec![
            (Value::from("artifact_ref"), Value::from(letters)),
            (Value::from("max_count"), Value::from(1u64)),
        ])]))
        .expect("canonical artifact ref");
        narrowed.sheet_answer_limits.extend(valid);
        assert_eq!(
            narrowed.sheet_answer_limit(letters, "Public", None),
            Some(1)
        );
        // Unknown or duplicate row keys fail the manifest rather than falling
        // back to the shipped limit, which could inadvertently widen it.
        assert!(
            parse_sheet_answer_limits(&Value::Array(vec![Value::Map(vec![
                (Value::from("max_count"), Value::from(1u64)),
                (Value::from("unknown"), Value::from(1u64)),
            ])]))
            .is_none()
        );
    }
}
