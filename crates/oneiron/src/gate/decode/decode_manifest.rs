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
    POLICY_CONNECTOR_CLASS_ROLE_KEY, POLICY_CREDENTIAL_LIFETIMES_KEY, POLICY_DEFAULTS_KEY,
    POLICY_DELEGATED_GRANTS_KEY, POLICY_DOCEDIT_RESOURCE_KEY, POLICY_DOCX_ARCHIVE_LIMITS_KEY,
    POLICY_DREAMER_FAILURE_PRECEDENCE_KEY, POLICY_DREAMER_FAILURE_RULES_KEY,
    POLICY_GATE_DECISION_RETENTION_KEY, POLICY_HOSTED_TTS_KEY, POLICY_LEGAL_FLOOR_ROWS_KEY,
    POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY,
    POLICY_OWNER_POLICY_DOCUMENT_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY, POLICY_OWNER_POLICY_PATTERNS_KEY,
    POLICY_OWNER_POLICY_PRECEDENCE_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY,
    POLICY_PACK_VERSION_KEY, POLICY_PPTX_COMMENT_LIMITS_KEY,
    POLICY_RETIRED_COMM_OPT_OUT_POSTURE_KEY, POLICY_RETIRED_PROPOSAL_CHECK_THRESHOLD_KEY,
    POLICY_RULES_KEY, POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY,
    POLICY_SHEET_ANSWER_LIMITS_KEY, POLICY_SHEET_ANSWER_PRECEDENCE_KEY, POLICY_SIGNATURE_KEY,
    POLICY_SIGNATURES_KEY, POLICY_SKILL_EDIT_GOAL_KEY, POLICY_SLIDE_REVIEW_KEY,
    POLICY_SOURCE_TRUST_KEY, POLICY_TEACHER_PROBE_KEY, POLICY_WAIT_POLICY_KEY,
    POLICY_WEAVE_CORRECTION_POLICY_KEY,
};
use crate::gate::docedit_resource::DoceditResourcePolicy;
use crate::gate::grants::PolicyScopedGrant;
use crate::gate::hosted_tts_policy::HostedTtsPolicy;
use crate::gate::operational_policy::{
    LINEAR_MIRROR_KEY, LINEAR_SYNC_KEY, LinearMirrorPolicy, LinearSyncBudget, PRECEDENCE_KEY,
    PolicyPrecedence, WAVE_HANDOFF_KEY, WaveHandoffPolicy,
};
use crate::gate::pack_install_policy::KEY as PACK_INSTALL_POLICY_KEY;
use crate::gate::policy_values::{PolicyValueRow, parse_policy_values};
use crate::gate::resolution::{
    AttributionLimits, ConnectorClassPrecedence, CredentialLifetimePolicy,
    CredentialLifetimePrecedence, GateDecisionRetentionPolicy, TeacherProbeRow,
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
    parse_owner_policy_rows, parse_rules, parse_scoped_grants,
};
use super::decode_trust_budget::{
    parse_budget_exhaustion_policy, parse_budget_policy, parse_gate_decision_retention,
    parse_source_trust,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::gate) enum ConnectorClassRole {
    #[default]
    Vault,
    Holder,
}

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

    pub(in crate::gate) diagnostic_bounds: Option<crate::self_heal::tripwires::TripwireBounds>,
    pub(in crate::gate) failure_signal_policy: Vec<crate::failure_signals::policy::Row>,
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
    pub(in crate::gate) unsupported_schema: bool,
    pub(in crate::gate) engine_version_floor: bool,
    pub(in crate::gate) unknown_axis_seen: bool,
}

// One decode per manifest row, mirroring default_policy_manifest: splitting it would scatter one manifest.
#[allow(clippy::too_many_lines)]
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
                | POLICY_CREDENTIAL_LIFETIMES_KEY
                | POLICY_RULES_KEY
                | POLICY_ACTOR_CEILINGS_KEY
                | POLICY_DELEGATED_GRANTS_KEY
                | POLICY_SOURCE_TRUST_KEY
                | "single_valued_predicates"
                | POLICY_SCOPED_GRANTS_KEY
                | POLICY_SKILL_EDIT_GOAL_KEY
                | crate::federation::grant_policy::ROWS_KEY
                | crate::gate::room_policy::KEY
                | POLICY_OWNER_POLICY_ROWS_KEY
                | POLICY_OWNER_POLICY_PRECEDENCE_KEY
                | super::super::constants::POLICY_OWNER_POLICY_NOTIFY_KEY
                | POLICY_OWNER_POLICY_ENABLED_KEY
                | POLICY_OWNER_POLICY_DOCUMENT_KEY
                | POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY
                | POLICY_OWNER_POLICY_PATTERNS_KEY
                // Retired, accepted and ignored so manifests written before
                // the engine floor was removed still decode. See the const.
                | POLICY_LEGAL_FLOOR_ROWS_KEY
                | POLICY_RETIRED_COMM_OPT_OUT_POSTURE_KEY
                | POLICY_RETIRED_PROPOSAL_CHECK_THRESHOLD_KEY
                | POLICY_SIGNATURE_KEY
                | POLICY_SIGNATURES_KEY
                | POLICY_ON_BUDGET_EXHAUSTED_KEY
                | POLICY_AUTO_CHECKER_KEY
                | POLICY_BUDGET_POLICY_KEY
                | POLICY_CONNECTOR_ADMISSION_KEY
                | crate::gate::voice_serving::KEY
                | POLICY_GATE_DECISION_RETENTION_KEY
                | POLICY_WAIT_POLICY_KEY
                | POLICY_ACT_POLICY_KEY
                | PACK_INSTALL_POLICY_KEY
                | "room_thread"
                | POLICY_PPTX_COMMENT_LIMITS_KEY
                | "booking_conversion"
                | POLICY_DREAMER_FAILURE_RULES_KEY
                | POLICY_DREAMER_FAILURE_PRECEDENCE_KEY
                | POLICY_HOSTED_TTS_KEY
                | POLICY_CONNECTOR_CLASS_CARRY_KEY
                | POLICY_CONNECTOR_CLASS_ROLE_KEY
                | POLICY_CONNECTOR_CLASS_PRECEDENCE_KEY

                | POLICY_SLIDE_REVIEW_KEY
                | POLICY_DOCEDIT_RESOURCE_KEY
                | POLICY_DOCX_ARCHIVE_LIMITS_KEY

                | "diagnostic_bounds"
                | "policy_values"
                | crate::failure_signals::policy::POLICY_KEY
                | "livequery_tracker_limits"
                | crate::gate::weave_policy::KEY
                | crate::gate::weave_policy::PRECEDENCE_KEY
                | RETRIEVAL_RETENTION_ROWS_KEY
                | "goal_limits"
                | "voice_ref_limits"
                | POLICY_SHEET_ANSWER_LIMITS_KEY
                | POLICY_SHEET_ANSWER_PRECEDENCE_KEY
                | LINEAR_MIRROR_KEY
                | LINEAR_SYNC_KEY
                | WAVE_HANDOFF_KEY
                | PRECEDENCE_KEY
                | POLICY_WEAVE_CORRECTION_POLICY_KEY
                | POLICY_ATTRIBUTION_LIMITS_KEY
                | POLICY_ASK_POLICY_KEY
                | "retry_source_policy"
                | "compilation_policy"
                | POLICY_TEACHER_PROBE_KEY
                | "experiment_selection"
                | crate::gate::carry_forward_policy::KEY
                | crate::skill_optimize::policy::MANIFEST_KEY
        ) {
            return None;
        }
    }

    validate_owner_policy_notify(&entries)?;

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
    let credential_lifetimes = match single_map_value(&entries, POLICY_CREDENTIAL_LIFETIMES_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Map(rows)) => {
            if rows.len() != 3
                || rows.iter().any(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        Some("oauth_exchange_secs" | "initial_owner_secs" | "precedence")
                    )
                })
            {
                return None;
            }
            let duration = |name| match single_map_value(rows, name) {
                MapValue::Present(value) => value.as_u64().filter(|secs| *secs > 0),
                MapValue::Missing | MapValue::Duplicate => None,
            };
            let precedence = match single_map_value(rows, "precedence") {
                MapValue::Present(Value::String(value))
                    if value.as_str() == Some("vault_ceiling_holder_narrows") =>
                {
                    CredentialLifetimePrecedence::VaultCeilingHolderNarrows
                }
                _ => return None,
            };
            Some(CredentialLifetimePolicy {
                oauth_exchange_secs: duration("oauth_exchange_secs")?,
                initial_owner_secs: duration("initial_owner_secs")?,
                precedence,
            })
        }
        MapValue::Present(_) => return None,
    };
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
    let skill_edit_goal = match single_map_value(&entries, POLICY_SKILL_EDIT_GOAL_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(SkillEditGoalPolicy::decode(value.clone())?),
    };
    let scoped_grants = match single_map_value(&entries, POLICY_SCOPED_GRANTS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_scoped_grants(value)?,
    };
    let federation_grant_rows =
        match single_map_value(&entries, crate::federation::grant_policy::ROWS_KEY) {
            MapValue::Missing => Vec::new(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => crate::federation::grant_policy::parse_rows(value)?,
        };
    let owner_policy_enabled = match single_map_value(&entries, POLICY_OWNER_POLICY_ENABLED_KEY) {
        MapValue::Missing => false,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Boolean(value)) => *value,
        MapValue::Present(_) => return None,
    };
    let room_policy_rows = match single_map_value(&entries, crate::gate::room_policy::KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => crate::gate::room_policy::parse_rows(value)?,
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
    let owner_policy_precedence = decode_owner_policy_precedence(&entries)?;
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
    let connector_admission = match single_map_value(&entries, POLICY_CONNECTOR_ADMISSION_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::gate::connector_admission::ConnectorAdmissionPolicy::decode(value)?)
        }
    };
    let voice_serving = match single_map_value(&entries, crate::gate::voice_serving::KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::gate::voice_serving::VoiceServingRows::decode(value)?)
        }
    };
    let gate_decision_retention =
        match single_map_value(&entries, POLICY_GATE_DECISION_RETENTION_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(parse_gate_decision_retention(value)?),
        };
    // Invalid wait/act rows reject the entire manifest, not just the axis.
    let wait_policy = match single_map_value(&entries, POLICY_WAIT_POLICY_KEY) {
        MapValue::Missing => WaitPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_wait_policy(value)?,
    };
    let act_policy = match single_map_value(&entries, POLICY_ACT_POLICY_KEY) {
        MapValue::Missing => ActPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_act_policy(value)?,
    };
    let room_thread = match single_map_value(&entries, "room_thread") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::gate::RoomThreadManifest::decode(value)?),
    };
    let pptx_comment_limits = match single_map_value(&entries, POLICY_PPTX_COMMENT_LIMITS_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::edit_roundtrip::pptx::PptxOperationalLimits::from_policy_row(value)?)
        }
    };
    let docx_archive_limits = match single_map_value(&entries, POLICY_DOCX_ARCHIVE_LIMITS_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::gate::docx_budget::parse(value)?),
    };
    let booking_conversion_rows = match single_map_value(&entries, "booking_conversion") {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) if rows.len() <= 128 => rows
            .iter()
            .map(|row| {
                let json: serde_json::Value = rmpv::ext::from_value(row.clone()).ok()?;
                let parsed: crate::booking::BookingConversionPolicyRow =
                    serde_json::from_value(json).ok()?;
                parsed.validate().ok()?;
                Some(parsed)
            })
            .collect::<Option<Vec<_>>>()?,
        MapValue::Present(_) => return None,
    };
    let dreamer_failure_rules = match single_map_value(&entries, POLICY_DREAMER_FAILURE_RULES_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_failure_rules(value)?,
    };
    let dreamer_failure_precedence =
        match single_map_value(&entries, POLICY_DREAMER_FAILURE_PRECEDENCE_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(DreamerFailurePrecedence::parse(value.as_str()?)?),
        };
    let hosted_tts = match single_map_value(&entries, POLICY_HOSTED_TTS_KEY) {
        MapValue::Missing => HostedTtsPolicy::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => HostedTtsPolicy::parse(value)?,
    };
    let connector_class_carry = match single_map_value(&entries, POLICY_CONNECTOR_CLASS_CARRY_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) => {
            let mut result = std::collections::BTreeSet::new();
            for row in rows {
                let Value::Array(pair) = row else {
                    return None;
                };
                let [Value::String(from), Value::String(to)] = pair.as_slice() else {
                    return None;
                };
                let (Some(from), Some(to)) = (from.as_str(), to.as_str()) else {
                    return None;
                };
                // Typed class names, not an engine-fixed precedence or pair list.
                if !matches!(from, "public" | "personal" | "secret" | "header")
                    || !matches!(to, "public" | "personal" | "secret" | "header")
                    || from == to
                    || !result.insert((from.to_owned(), to.to_owned()))
                {
                    return None;
                }
            }
            Some(result)
        }
        MapValue::Present(_) => return None,
    };
    let connector_class_role = match single_map_value(&entries, POLICY_CONNECTOR_CLASS_ROLE_KEY) {
        MapValue::Missing | MapValue::Present(Value::Nil) => ConnectorClassRole::Vault,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::String(role)) => match role.as_str()? {
            "vault" => ConnectorClassRole::Vault,
            "holder" => ConnectorClassRole::Holder,
            _ => return None,
        },
        MapValue::Present(_) => return None,
    };
    let connector_class_precedence =
        match single_map_value(&entries, POLICY_CONNECTOR_CLASS_PRECEDENCE_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(ConnectorClassPrecedence::parse(value.as_str()?)?),
        };
    let livequery_tracker_limits = match single_map_value(&entries, "livequery_tracker_limits") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::gate::tracker_limits::PolicyTrackerLimits::decode(
            value,
        )?),
    };
    let slide_review_policy = match single_map_value(&entries, POLICY_SLIDE_REVIEW_KEY) {
        MapValue::Missing => crate::llm::decision::SlideReviewPolicy::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => crate::llm::decision::SlideReviewPolicy::decode(value)?,
    };
    let docedit_resource_policy = match single_map_value(&entries, POLICY_DOCEDIT_RESOURCE_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_docedit_resource_policy(value)?),
    };
    let diagnostic_bounds = match single_map_value(&entries, "diagnostic_bounds") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => {
            Some(crate::self_heal::tripwires::TripwireBounds::decode(value)?)
        }
    };

    let failure_signal_policy =
        match single_map_value(&entries, crate::failure_signals::policy::POLICY_KEY) {
            MapValue::Missing => Vec::new(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => crate::failure_signals::policy::decode(value)?,
        };

    let policy_values = match single_map_value(&entries, "policy_values") {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_policy_values(value)?,
    };

    let weave_report_precedence =
        match single_map_value(&entries, crate::gate::weave_policy::PRECEDENCE_KEY) {
            MapValue::Missing => crate::gate::weave_policy::Precedence::default(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                crate::gate::weave_policy::Precedence::parse(value.as_str()?)?
            }
        };
    let (weave_report_policy, weave_report_policy_empty) =
        match single_map_value(&entries, crate::gate::weave_policy::KEY) {
            MapValue::Missing => (Vec::new(), false),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                let rows = crate::gate::weave_policy::parse(value)?;
                let empty = rows.is_empty();
                (rows, empty)
            }
        };
    let retrieval_retention = match single_map_value(&entries, RETRIEVAL_RETENTION_ROWS_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_retrieval_retention_rows(value)?),
    };
    let goal_limits = match single_map_value(&entries, "goal_limits") {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::workspace_roster::GoalLimits::decode(value)?),
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
    let linear_mirror = match single_map_value(&entries, LINEAR_MIRROR_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(LinearMirrorPolicy::decode(value)?),
    };
    let linear_sync = match single_map_value(&entries, LINEAR_SYNC_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(LinearSyncBudget::decode(value)?),
    };
    let wave_handoff = match single_map_value(&entries, WAVE_HANDOFF_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(WaveHandoffPolicy::decode(value)?),
    };
    let operational_precedence = match single_map_value(&entries, PRECEDENCE_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(PolicyPrecedence::decode(value)?),
    };
    let weave_correction_policy =
        match single_map_value(&entries, POLICY_WEAVE_CORRECTION_POLICY_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(crate::gate::WeaveCorrectionPolicy::parse(value)?),
        };
    let attribution_limits = match single_map_value(&entries, POLICY_ATTRIBUTION_LIMITS_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_attribution_limits(value)?),
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

    let ask_policy = match single_map_value(&entries, POLICY_ASK_POLICY_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(crate::gate::ask_policy::AskOperationalPolicy::decode(
            value,
        )?),
    };
    let experiment_selection = match single_map_value(&entries, "experiment_selection") {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_experiment_selection(value)?,
    };

    let teacher_probe = match single_map_value(&entries, POLICY_TEACHER_PROBE_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_teacher_probe_row(value)?),
    };

    let carry_forward_confidence =
        match single_map_value(&entries, crate::gate::carry_forward_policy::KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                Some(crate::gate::carry_forward_policy::CarryForwardPolicy::parse(value)?)
            }
        };
    let judge_calibration =
        match single_map_value(&entries, crate::skill_optimize::policy::MANIFEST_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => {
                Some(crate::skill_optimize::policy::JudgeCalibrationPolicy::decode(value)?)
            }
        };

    let unknown_axis_seen =
        defaults.unknown_axis_seen || rules.iter().any(|rule| rule.axes.unknown_axis_seen);

    Some(DecodedPolicyManifest {
        policy_values,
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
        skill_edit_goal,
        federation_grant_rows,
        room_policy_rows,
        single_valued_predicates,
        owner_policy_rows,
        owner_policy_precedence,
        owner_policy_rows_dropped,
        owner_policy_enabled,
        owner_policy_document,
        owner_policy_output_contract,
        owner_policy_patterns,
        owner_policy_patterns_dropped,
        signatures,
        on_budget_exhausted,
        auto_checker,
        budget_policy,
        connector_admission,
        voice_serving,
        weave_report_policy,
        weave_report_policy_empty,
        weave_report_precedence,
        gate_decision_retention,
        wait_policy,
        act_policy,
        pack_install_policy,
        room_thread,
        pptx_comment_limits,
        booking_conversion_rows,
        dreamer_failure_rules,
        dreamer_failure_precedence,
        hosted_tts,
        connector_class_carry,
        connector_class_role,
        connector_class_precedence,
        slide_review_policy,
        docedit_resource_policy,
        docx_archive_limits,
        diagnostic_bounds,
        failure_signal_policy,
        livequery_tracker_limits,
        retrieval_retention,
        goal_limits,
        voice_ref_limits,
        sheet_answer_limits,
        sheet_answer_precedence,
        linear_mirror,
        linear_sync,
        wave_handoff,
        operational_precedence,
        weave_correction_policy,
        attribution_limits,
        ask_policy,
        retry_source_policy,
        compilation_policy,
        teacher_probe,
        experiment_selection,
        carry_forward_confidence,
        judge_calibration,
        credential_lifetimes,
        unsupported_schema,
        engine_version_floor,
        unknown_axis_seen,
    })
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
