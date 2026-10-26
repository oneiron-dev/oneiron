//! Manifest envelope plus DecodedPolicyManifest assembly.

use std::io::Cursor;

use rmpv::Value;

use super::decode_docedit_resource::parse_docedit_resource_policy;
use super::experiment_selection::parse_experiment_selection;
use crate::autoreason_campaign::selection::SelectionPolicyRow;
use crate::gate::PackInstallPolicy;
use crate::gate::SkillEditGoalPolicy;
use crate::gate::ceiling::{
    ActorCeiling, DelegationGrantRecord, PolicyOwnerPatternRow, PolicyOwnerPolicyRow,
    PolicyOwnerPrecedence, PolicyPack, PolicySignature, SourceTrustCeiling,
};
use crate::gate::class_policy::{ActPolicyTable, WaitPolicyTable};
use crate::gate::constants::{
    ATTRIBUTION_HOLDER_ACTOR_KEY, ATTRIBUTION_HOLDER_MAX_BYTES_KEY,
    ATTRIBUTION_HOLDER_REASON_BYTES_KEY, ATTRIBUTION_PRECEDENCE_KEY,
    ATTRIBUTION_REASON_MAX_BYTES_KEY, ATTRIBUTION_RECEIPTS_PER_PASS_KEY, POLICY_ACT_POLICY_KEY,
    POLICY_ACTOR_CEILINGS_KEY, POLICY_ASK_POLICY_KEY, POLICY_ATTRIBUTION_LIMITS_KEY,
    POLICY_AUTO_CHECKER_KEY, POLICY_BUDGET_POLICY_KEY, POLICY_CONNECTOR_ADMISSION_KEY,
    POLICY_CONNECTOR_CLASS_CARRY_KEY, POLICY_CONNECTOR_CLASS_PRECEDENCE_KEY,
    POLICY_CONNECTOR_CLASS_ROLE_KEY, POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY,
    POLICY_CONSULT_FANOUT_CONTROLS_KEY, POLICY_CONSULT_FANOUT_PRECEDENCE_KEY,
    POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY, POLICY_CREDENTIAL_LIFETIMES_KEY, POLICY_DEFAULTS_KEY,
    POLICY_DELEGATED_GRANTS_KEY, POLICY_DOCEDIT_RESOURCE_KEY, POLICY_DOCX_ARCHIVE_LIMITS_KEY,
    POLICY_DREAMER_FAILURE_PRECEDENCE_KEY, POLICY_DREAMER_FAILURE_RULES_KEY,
    POLICY_GATE_DECISION_RETENTION_KEY, POLICY_HOSTED_TTS_KEY, POLICY_LEGAL_FLOOR_ROWS_KEY,
    POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY,
    POLICY_OWNER_POLICY_DOCUMENT_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY, POLICY_OWNER_POLICY_PATTERNS_KEY,
    POLICY_OWNER_POLICY_PRECEDENCE_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY,
    POLICY_PACK_VERSION_KEY, POLICY_PERSONA_CORE_PREFIXES_KEY, POLICY_PPTX_COMMENT_LIMITS_KEY,
    POLICY_PROJECT_COLLABORATION_KEY, POLICY_PROJECT_CONVERSION_KEY,
    POLICY_RETIRED_COMM_OPT_OUT_POSTURE_KEY, POLICY_RETIRED_PROPOSAL_CHECK_THRESHOLD_KEY,
    POLICY_RULES_KEY, POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY,
    POLICY_SHARED_ACT_POLICIES_KEY, POLICY_SHEET_ANSWER_LIMITS_KEY,
    POLICY_SHEET_ANSWER_PRECEDENCE_KEY, POLICY_SIGNATURE_KEY, POLICY_SIGNATURES_KEY,
    POLICY_SKILL_EDIT_GOAL_KEY, POLICY_SLIDE_REVIEW_KEY, POLICY_SOURCE_TRUST_KEY,
    POLICY_SYNC_WORLD_CEILING_KEY, POLICY_SYNC_WORLD_DEFAULT_KEY, POLICY_TEACHER_PROBE_KEY,
    POLICY_WAIT_POLICY_KEY, POLICY_WEAVE_CORRECTION_POLICY_KEY,
};
use crate::gate::docedit_resource::DoceditResourcePolicy;
use crate::gate::fanout_policy::{
    FanoutControls, FanoutPrecedence, FanoutScopedRow, parse_controls, parse_precedence,
    parse_scoped_rows,
};
use crate::gate::grants::PolicyScopedGrant;
use crate::gate::hosted_tts_policy::HostedTtsPolicy;
use crate::gate::operational_policy::{
    LINEAR_MIRROR_KEY, LINEAR_SYNC_KEY, LinearMirrorPolicy, LinearSyncBudget, PRECEDENCE_KEY,
    PolicyPrecedence, WAVE_HANDOFF_KEY, WaveHandoffPolicy,
};
use crate::gate::pack_install_policy::KEY as PACK_INSTALL_POLICY_KEY;
use crate::gate::policy_values::{PolicyValueRow, parse_policy_values};
use crate::gate::project_conversion::{ProjectConversionPolicy, parse_project_conversion};
use crate::gate::resolution::{
    AttributionLimits, ConnectorClassPrecedence, CredentialLifetimePolicy,
    CredentialLifetimePrecedence, GateDecisionRetentionPolicy, ProjectCollaborationPolicy,
    ResidenceOperationBudgetRow, TeacherProbeRow,
};
use crate::gate::retrieval_retention::{
    RETRIEVAL_RETENTION_ROWS_KEY, RetrievalRetentionRows, parse_retrieval_retention_rows,
};
use crate::llm::{
    BudgetExhaustionPolicy, BudgetPolicyTable, DreamerFailurePrecedence, DreamerFailureRule,
    parse_failure_rules,
};
use crate::voice_identity::ref_limits::VoiceRefLimitPolicy;

use super::decode_class_policy::{parse_act_policy, parse_wait_policy};
use super::decode_map_util::{
    MapValue, parse_signature_value, parse_signatures, required_string, required_value,
    single_map_value, version_gt,
};
use super::decode_policy_tables::{
    parse_actor_ceilings, parse_axes, parse_delegated_grants, parse_owner_policy_patterns,
    parse_owner_policy_rows, parse_rules, parse_scoped_grants, parse_shared_act_policies,
};
use super::decode_trust_budget::{
    parse_budget_exhaustion_policy, parse_budget_policy, parse_gate_decision_retention,
    parse_source_trust,
};
use super::parse_residence_operation_budgets;

mod parse;

pub(in crate::gate) use self::parse::decode_policy_manifest;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::gate) enum ConnectorClassRole {
    #[default]
    Vault,
    Holder,
}

#[derive(Clone)]
pub(in crate::gate) struct DecodedPolicyManifest {
    pub(in crate::gate) pack: PolicyPack,
    pub(in crate::gate) policy_values: Vec<PolicyValueRow>,
    pub(in crate::gate) actor_ceilings: Vec<ActorCeiling>,
    pub(in crate::gate) delegated_grants: Vec<DelegationGrantRecord>,
    pub(in crate::gate) source_trust: SourceTrustCeiling,
    pub(in crate::gate) single_valued_predicates: std::collections::BTreeSet<String>,
    pub(in crate::gate) scoped_grants: Vec<PolicyScopedGrant>,
    pub(in crate::gate) skill_edit_goal: Option<SkillEditGoalPolicy>,
    pub(in crate::gate) federation_grant_rows: Vec<crate::federation::grant_policy::GrantPolicyRow>,
    pub(in crate::gate) room_policy_rows: Vec<crate::gate::room_policy::RoomPolicyRow>,
    pub(in crate::gate) shared_act_policies:
        Option<std::collections::BTreeMap<String, crate::federation::SharedActPolicy>>,
    pub(in crate::gate) catastrophe_floor: Option<crate::consent::CatastropheFloor>,
    pub(in crate::gate) owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    pub(in crate::gate) owner_policy_precedence: PolicyOwnerPrecedence,
    pub(in crate::gate) owner_policy_rows_dropped: bool,
    pub(in crate::gate) owner_policy_enabled: bool,
    pub(in crate::gate) owner_policy_document: Option<String>,
    pub(in crate::gate) owner_policy_output_contract: Option<String>,
    pub(in crate::gate) owner_policy_patterns: Vec<PolicyOwnerPatternRow>,
    pub(in crate::gate) owner_policy_patterns_dropped: bool,
    pub(in crate::gate) signatures: Vec<PolicySignature>,
    pub(in crate::gate) on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    pub(in crate::gate) project_depth_default: Option<u64>,
    pub(in crate::gate) project_depth_max: Option<u64>,
    pub(in crate::gate) native_mail_policy: Vec<crate::gate::mail_policy::MailPolicy>,
    pub(in crate::gate) project_collaboration: Option<ProjectCollaborationPolicy>,
    /// The opaque host checker ref (ONE-1296), absent unless the manifest
    /// names one.
    pub(in crate::gate) auto_checker: Option<String>,
    pub(in crate::gate) budget_policy: BudgetPolicyTable,
    pub(in crate::gate) connector_admission:
        Option<crate::gate::connector_admission::ConnectorAdmissionPolicy>,
    pub(in crate::gate) voice_serving: Option<crate::gate::voice_serving::VoiceServingRows>,
    pub(in crate::gate) weave_report_policy: Vec<crate::gate::weave_policy::Row>,
    pub(in crate::gate) weave_report_policy_empty: bool,
    pub(in crate::gate) weave_report_precedence: crate::gate::weave_policy::Precedence,
    pub(in crate::gate) gate_decision_retention: Option<GateDecisionRetentionPolicy>,
    pub(in crate::gate) wait_policy: WaitPolicyTable,
    pub(in crate::gate) act_policy: ActPolicyTable,
    pub(in crate::gate) pack_install_policy: Option<PackInstallPolicy>,
    pub(in crate::gate) project_conversion: Option<ProjectConversionPolicy>,
    pub(in crate::gate) room_thread: Option<crate::gate::RoomThreadManifest>,
    pub(in crate::gate) pptx_comment_limits:
        Option<crate::edit_roundtrip::pptx::PptxOperationalLimits>,
    pub(in crate::gate) booking_conversion_rows: Vec<crate::booking::BookingConversionPolicyRow>,
    pub(in crate::gate) dreamer_failure_rules: Vec<DreamerFailureRule>,
    pub(in crate::gate) dreamer_failure_precedence: Option<DreamerFailurePrecedence>,
    pub(in crate::gate) hosted_tts: HostedTtsPolicy,
    pub(in crate::gate) connector_class_carry: Option<std::collections::BTreeSet<(String, String)>>,
    pub(in crate::gate) connector_class_role: ConnectorClassRole,
    pub(in crate::gate) connector_class_precedence: Option<ConnectorClassPrecedence>,

    pub(in crate::gate) slide_review_policy: crate::llm::decision::SlideReviewPolicy,
    pub(in crate::gate) docedit_resource_policy: Option<DoceditResourcePolicy>,
    pub(in crate::gate) docx_archive_limits: Option<crate::gate::docx_budget::DocxArchivePolicy>,

    pub(in crate::gate) diagnostic_bounds:
        Option<crate::self_heal::tripwires::ManifestTripwireBounds>,
    pub(in crate::gate) failure_signal_policy: Vec<crate::failure_signals::policy::Row>,
    pub(in crate::gate) residence_operation_budgets: Option<ResidenceOperationBudgetRow>,
    pub(in crate::gate) livequery_tracker_limits:
        Option<crate::gate::tracker_limits::PolicyTrackerLimits>,
    pub(in crate::gate) retrieval_retention: Option<RetrievalRetentionRows>,
    pub(in crate::gate) goal_limits: Option<crate::workspace_roster::GoalLimits>,
    pub(in crate::gate) voice_ref_limits: Option<VoiceRefLimitPolicy>,
    pub(in crate::gate) sheet_answer_limits: Vec<crate::gate::resolution::SheetAnswerLimitRow>,
    pub(in crate::gate) sheet_answer_precedence:
        Option<crate::gate::resolution::SheetAnswerPrecedence>,
    pub(in crate::gate) linear_mirror: Option<LinearMirrorPolicy>,
    pub(in crate::gate) linear_sync: Option<LinearSyncBudget>,
    pub(in crate::gate) wave_handoff: Option<WaveHandoffPolicy>,
    pub(in crate::gate) operational_precedence: Option<PolicyPrecedence>,
    pub(in crate::gate) skill_tradeoff_rows:
        Vec<crate::gate::skill_tradeoff_policy::SkillTradeoffPolicyRow>,
    pub(in crate::gate) weave_correction_policy: Option<crate::gate::WeaveCorrectionPolicy>,
    pub(in crate::gate) attribution_limits: Option<AttributionLimits>,
    pub(in crate::gate) ask_policy: Option<crate::gate::ask_policy::AskOperationalPolicy>,
    pub(in crate::gate) retry_source_policy:
        Vec<crate::gate::retry_source_policy::RetrySourcePolicyRow>,
    pub(in crate::gate) compilation_policy: Option<crate::edit_distance::miner::CompilationPolicy>,
    pub(in crate::gate) teacher_probe: Option<TeacherProbeRow>,
    pub(in crate::gate) experiment_selection: Vec<SelectionPolicyRow>,
    pub(in crate::gate) carry_forward_confidence:
        Option<crate::gate::carry_forward_policy::CarryForwardPolicy>,
    pub(in crate::gate) judge_calibration:
        Option<crate::skill_optimize::policy::JudgeCalibrationPolicy>,
    pub(in crate::gate) credential_lifetimes: Option<CredentialLifetimePolicy>,
    pub(in crate::gate) sync_world_ceiling: Option<std::collections::BTreeSet<crate::EntityId>>,
    pub(in crate::gate) sync_world_default: Option<bool>,
    pub(in crate::gate) persona_core_prefixes: std::collections::BTreeSet<String>,
    pub(in crate::gate) consult_fanout_approval_threshold: Option<u32>,
    pub(in crate::gate) consult_fanout_controls: Option<FanoutControls>,
    pub(in crate::gate) consult_fanout_precedence: Option<FanoutPrecedence>,
    pub(in crate::gate) consult_fanout_scope_rows: Vec<FanoutScopedRow>,
    pub(in crate::gate) unsupported_schema: bool,
    pub(in crate::gate) engine_version_floor: bool,
    pub(in crate::gate) unknown_axis_seen: bool,
}

/// A policy carrier is either a complete ordinary pack or one immutable
/// project-scoped signed contribution. Signed rows never inherit a pack's
/// local-only trusted marker or its unrelated gate defaults.
#[expect(
    clippy::large_enum_variant,
    reason = "per-row decode value, kept once per body by the store's manifest memo"
)]
pub(in crate::gate) enum DecodedManifestCarrier {
    Pack(DecodedPolicyManifest),
    ProjectDepth(crate::gate::project_depth::ProjectDepthContribution),
}

pub(in crate::gate) fn decode_manifest_carrier(data: &[u8]) -> Option<DecodedManifestCarrier> {
    if crate::gate::project_depth::is_project_depth_contribution(data) {
        return crate::gate::project_depth::decode_contribution(data)
            .ok()
            .map(DecodedManifestCarrier::ProjectDepth);
    }
    decode_policy_manifest(data).map(DecodedManifestCarrier::Pack)
}

/// A malformed notification row must not silently suppress a promised
/// holder push. Validation shares the manifest's closed-key admission.
fn validate_owner_policy_notify(entries: &[(Value, Value)]) -> Option<()> {
    match single_map_value(
        entries,
        super::super::constants::POLICY_OWNER_POLICY_NOTIFY_KEY,
    ) {
        MapValue::Missing => {}
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) => {
            let mut scopes = std::collections::BTreeSet::new();
            for row in rows {
                let Value::Map(fields) = row else { return None };
                if fields.len() != 3
                    || fields.iter().any(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            Some("scope" | "delivery" | "digest_interval_seconds")
                        )
                    })
                {
                    return None;
                }
                let scope = single_map_value(fields, "scope");
                let delivery = single_map_value(fields, "delivery");
                let (
                    MapValue::Present(Value::String(scope)),
                    MapValue::Present(Value::String(delivery)),
                ) = (scope, delivery)
                else {
                    return None;
                };
                let (Some(scope), Some(delivery)) = (scope.as_str(), delivery.as_str()) else {
                    return None;
                };
                if !matches!(scope, "vault" | "override")
                    || !matches!(delivery, "push_other_holders" | "log_only")
                    || !matches!(single_map_value(fields, "digest_interval_seconds"),
                        MapValue::Present(value) if value.as_u64().is_some_and(|secs| (1..=31_536_000).contains(&secs)))
                    || !scopes.insert(scope)
                {
                    return None;
                }
            }
            if scopes.len() != 2 {
                return None;
            }
        }
        MapValue::Present(_) => return None,
    }
    Some(())
}

/// Invalid policy must not fall back to the permissive scope selection.
fn decode_owner_policy_precedence(entries: &[(Value, Value)]) -> Option<PolicyOwnerPrecedence> {
    let precedence = match single_map_value(entries, POLICY_OWNER_POLICY_PRECEDENCE_KEY) {
        MapValue::Missing => PolicyOwnerPrecedence::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Map(fields)) => {
            if fields.len() != 2
                || fields
                    .iter()
                    .any(|(key, _)| !matches!(key.as_str(), Some("composition" | "vault_cap")))
            {
                return None;
            }
            if !matches!(
                single_map_value(fields, "vault_cap"),
                MapValue::Present(Value::Boolean(true))
            ) {
                return None;
            }
            match single_map_value(fields, "composition") {
                MapValue::Present(Value::String(value)) => match value.as_str()? {
                    "nested_narrowing" => PolicyOwnerPrecedence::NestedNarrowing,
                    "most_specific_vault_capped" => PolicyOwnerPrecedence::MostSpecificVaultCapped,
                    _ => return None,
                },
                _ => return None,
            }
        }
        MapValue::Present(_) => return None,
    };
    Some(precedence)
}

/// A policy-manifest row. Numeric knobs are positive; unknown/duplicate keys
/// refuse the row instead of silently widening its meaning. Holder entries
/// are narrow-only relative to the vault limit and to other packs.
fn parse_attribution_limits(value: &Value) -> Option<AttributionLimits> {
    let Value::Map(entries) = value else {
        return None;
    };
    for (key, _) in entries {
        if !matches!(
            key.as_str()?,
            ATTRIBUTION_REASON_MAX_BYTES_KEY
                | ATTRIBUTION_RECEIPTS_PER_PASS_KEY
                | ATTRIBUTION_HOLDER_REASON_BYTES_KEY
                | ATTRIBUTION_PRECEDENCE_KEY
        ) {
            return None;
        }
    }
    if required_string(entries, ATTRIBUTION_PRECEDENCE_KEY)?.as_str() != "nested_narrowing" {
        return None;
    }
    let mut limits = AttributionLimits::default();
    for (key, target) in [
        (
            ATTRIBUTION_REASON_MAX_BYTES_KEY,
            &mut limits.reason_max_bytes,
        ),
        (
            ATTRIBUTION_RECEIPTS_PER_PASS_KEY,
            &mut limits.receipts_per_pass,
        ),
    ] {
        match single_map_value(entries, key) {
            MapValue::Missing => {}
            MapValue::Duplicate => return None,
            MapValue::Present(value) => *target = value.as_u64().filter(|v| *v > 0)?,
        }
    }
    match single_map_value(entries, ATTRIBUTION_HOLDER_REASON_BYTES_KEY) {
        MapValue::Missing => {}
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) => {
            for row in rows {
                let Value::Map(fields) = row else { return None };
                if fields.len() != 2 {
                    return None;
                }
                let actor = required_string(fields, ATTRIBUTION_HOLDER_ACTOR_KEY)?;
                let holder = crate::EntityId::from_hex(&actor).ok()?;
                if holder.to_hex() != actor {
                    return None;
                }
                let bytes = required_value(fields, ATTRIBUTION_HOLDER_MAX_BYTES_KEY)?
                    .as_u64()
                    .filter(|v| *v > 0)?;
                if limits.holder_reason_bytes.insert(holder, bytes).is_some() {
                    return None;
                }
            }
        }
        MapValue::Present(_) => return None,
    }
    Some(limits)
}

/// Longest owner policy document a manifest may carry, mirroring the bound the
/// hosted plane's registration enforces. Spelled here rather than imported,
/// because `gate` sits under `policy_model`; keep it equal to
/// `policy_model::POLICY_DOCUMENT_MAX_LEN`.
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

/// A teacher-probe floor is a POLICY_MANIFEST row, never a per-run CLI knob.
/// Holder overrides must be at least as strict as their containing vault row.
fn parse_teacher_probe_row(value: &Value) -> Option<TeacherProbeRow> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut probe_id = None;
    let mut minimum = None;
    let mut holders = None;
    for (key, value) in entries {
        match key.as_str()? {
            "probe_id" if probe_id.is_none() => probe_id = Some(value.as_str()?),
            "min_f1_millionths" if minimum.is_none() => {
                minimum = Some(u32::try_from(value.as_u64()?).ok()?);
            }
            "holders" if holders.is_none() => {
                let Value::Array(rows) = value else {
                    return None;
                };
                let mut parsed = std::collections::BTreeMap::new();
                for row in rows {
                    let Value::Map(fields) = row else {
                        return None;
                    };
                    let holder = required_string(fields, "holder_ref")?;
                    if !crate::llm::manifest::valid_teacher_probe_holder_ref(&holder) {
                        return None;
                    }
                    let floor =
                        u32::try_from(required_value(fields, "min_f1_millionths")?.as_u64()?)
                            .ok()?;
                    if fields.len() != 2 || parsed.insert(holder, floor).is_some() {
                        return None;
                    }
                }
                holders = Some(parsed);
            }
            _ => return None,
        }
    }
    let minimum = minimum.filter(|floor| (1..=1_000_000).contains(floor))?;
    let holders = holders.unwrap_or_default();
    if probe_id != Some(crate::llm::manifest::TEACHER_PROBE_ID)
        || holders
            .values()
            .any(|floor| *floor < minimum || *floor > 1_000_000)
    {
        return None;
    }
    Some(TeacherProbeRow {
        min_f1_millionths: minimum,
        holders,
    })
}

/// The project-depth creation default and vault ceiling rows. Each is
/// optional and owner-editable to any depth (rule 5: an engine walk count is
/// never policy validity), but a duplicate, a non-integer, or a default above
/// the ceiling rejects the manifest.
fn parse_project_depth_rows(entries: &[(Value, Value)]) -> Option<(Option<u64>, Option<u64>)> {
    let row = |key: &str| match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => value.as_u64().map(Some),
    };
    let default = row("project_depth_default")?;
    let max = row("project_depth_max")?;
    if default.zip(max).is_some_and(|(start, max)| start > max) {
        return None;
    }
    Some((default, max))
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
