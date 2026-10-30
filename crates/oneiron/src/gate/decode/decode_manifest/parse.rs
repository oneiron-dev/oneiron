//! The whole policy-manifest body decode; `decode_manifest` re-exports it.

use super::*;

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
                | POLICY_SHARED_ACT_POLICIES_KEY
                | crate::consent::CATASTROPHE_FLOOR_ROW_KEY
                | POLICY_OWNER_POLICY_ROWS_KEY
                | POLICY_OWNER_POLICY_PRECEDENCE_KEY
                | super::super::super::constants::POLICY_OWNER_POLICY_NOTIFY_KEY
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
                | crate::gate::mail_policy::MANIFEST_KEY
                | POLICY_PROJECT_COLLABORATION_KEY
                | POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY
                | POLICY_CONSULT_FANOUT_CONTROLS_KEY
                | POLICY_CONSULT_FANOUT_PRECEDENCE_KEY
                | POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY
                | POLICY_AUTO_CHECKER_KEY
                | POLICY_BUDGET_POLICY_KEY
                | POLICY_CONNECTOR_ADMISSION_KEY
                | crate::gate::voice_serving::KEY
                | POLICY_GATE_DECISION_RETENTION_KEY
                | POLICY_WAIT_POLICY_KEY
                | POLICY_ACT_POLICY_KEY
                | PACK_INSTALL_POLICY_KEY
                | POLICY_PROJECT_CONVERSION_KEY
                | "room_thread"
                | POLICY_PPTX_COMMENT_LIMITS_KEY
                | "booking_conversion"
                | crate::booking::anti_abuse::BOOKING_ANTI_ABUSE_RULES_KEY
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
                | "project_depth_default"
                | "project_depth_max"
                | "policy_values"
                | crate::failure_signals::policy::POLICY_KEY
                | "livequery_tracker_limits"
                | crate::gate::policy_manifest_doors::CLAIM_AGING_PROFILES_KEY
                | crate::gate::policy_manifest_doors::RETRIEVAL_WEIGHTS_KEY
                | crate::gate::weave_policy::KEY
                | crate::gate::weave_policy::PRECEDENCE_KEY
                | super::super::POLICY_RESIDENCE_OPERATION_BUDGETS_KEY
                | RETRIEVAL_RETENTION_ROWS_KEY
                | "goal_limits"
                | "voice_ref_limits"
                | POLICY_SHEET_ANSWER_LIMITS_KEY
                | POLICY_SHEET_ANSWER_PRECEDENCE_KEY
                | LINEAR_MIRROR_KEY
                | LINEAR_SYNC_KEY
                | WAVE_HANDOFF_KEY
                | PRECEDENCE_KEY
                | crate::gate::skill_tradeoff_policy::KEY
                | POLICY_WEAVE_CORRECTION_POLICY_KEY
                | POLICY_ATTRIBUTION_LIMITS_KEY
                | POLICY_ASK_POLICY_KEY
                | "retry_source_policy"
                | "compilation_policy"
                | POLICY_TEACHER_PROBE_KEY
                | "experiment_selection"
                | crate::gate::carry_forward_policy::KEY
                | crate::skill_optimize::policy::MANIFEST_KEY
                | POLICY_SYNC_WORLD_CEILING_KEY
                | POLICY_SYNC_WORLD_DEFAULT_KEY
                | POLICY_PERSONA_CORE_PREFIXES_KEY
        ) {
            return None;
        }
    }

    crate::gate::policy_manifest_doors::decode_claim_aging_profiles(&entries).ok()?;
    crate::gate::policy_manifest_doors::decode_retrieval_weights(&entries).ok()?;
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
    let shared_act_policies = match single_map_value(&entries, POLICY_SHARED_ACT_POLICIES_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_shared_act_policies(value)?),
    };
    let catastrophe_floor =
        match single_map_value(&entries, crate::consent::CATASTROPHE_FLOOR_ROW_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(crate::consent::CatastropheFloor::decode_row(value)?),
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
    let native_mail_policy =
        match single_map_value(&entries, crate::gate::mail_policy::MANIFEST_KEY) {
            MapValue::Missing => Vec::new(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => crate::gate::mail_policy::decode_rows(value)?,
        };
    let project_collaboration = match single_map_value(&entries, POLICY_PROJECT_COLLABORATION_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(super::super::project_collaboration::parse(value)?),
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
    let project_conversion = match single_map_value(&entries, POLICY_PROJECT_CONVERSION_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_project_conversion(value)?),
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
        MapValue::Present(value) => Some(
            crate::self_heal::tripwires::ManifestTripwireBounds::decode(value)?,
        ),
    };

    let (project_depth_default, project_depth_max) = parse_project_depth_rows(&entries)?;
    let residence_operation_budgets = match single_map_value(
        &entries,
        super::super::POLICY_RESIDENCE_OPERATION_BUDGETS_KEY,
    ) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_residence_operation_budgets(value)?),
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

    let skill_tradeoff_rows =
        match single_map_value(&entries, crate::gate::skill_tradeoff_policy::KEY) {
            MapValue::Missing => Vec::new(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => crate::gate::skill_tradeoff_policy::parse_rows(value)?,
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

    let sync_world_ceiling = match single_map_value(&entries, POLICY_SYNC_WORLD_CEILING_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(worlds)) => {
            let mut ids = std::collections::BTreeSet::new();
            for value in worlds {
                let Value::Binary(bytes) = value else {
                    return None;
                };
                let id = crate::EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()?;
                if !ids.insert(id) {
                    return None;
                }
            }
            Some(ids)
        }
        MapValue::Present(_) => return None,
    };

    let persona_core_prefixes = match single_map_value(&entries, POLICY_PERSONA_CORE_PREFIXES_KEY) {
        MapValue::Missing => std::collections::BTreeSet::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(prefixes)) => {
            let mut declared = std::collections::BTreeSet::new();
            for value in prefixes {
                let prefix = value.as_str()?;
                if !crate::claim::is_predicate_prefix(prefix) || !declared.insert(prefix.to_owned())
                {
                    return None;
                }
            }
            declared
        }
        MapValue::Present(_) => return None,
    };

    let sync_world_default = match single_map_value(&entries, POLICY_SYNC_WORLD_DEFAULT_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(Value::String(mode)) if mode.as_str() == Some("opened") => Some(false),
        MapValue::Present(Value::String(mode)) if mode.as_str() == Some("all") => Some(true),
        MapValue::Present(_) => return None,
    };

    let consult_fanout_approval_threshold =
        match single_map_value(&entries, POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(u32::try_from(value.as_u64()?).ok()?),
        };

    let consult_fanout_controls =
        match single_map_value(&entries, POLICY_CONSULT_FANOUT_CONTROLS_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(parse_controls(value)?),
        };
    let consult_fanout_precedence =
        match single_map_value(&entries, POLICY_CONSULT_FANOUT_PRECEDENCE_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(parse_precedence(value)?),
        };
    let consult_fanout_scope_rows =
        match single_map_value(&entries, POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY) {
            MapValue::Missing => Vec::new(),
            MapValue::Duplicate => return None,
            MapValue::Present(value) => parse_scoped_rows(value)?,
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
        shared_act_policies,
        catastrophe_floor,
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
        native_mail_policy,
        project_collaboration,
        auto_checker,
        project_depth_default,
        project_depth_max,
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
        project_conversion,
        room_thread,
        pptx_comment_limits,
        booking_conversion_rows,
        booking_anti_abuse_rows: crate::booking::anti_abuse::decode_manifest_rule_field(&entries)?,
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
        residence_operation_budgets,
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
        skill_tradeoff_rows,
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
        sync_world_ceiling,
        sync_world_default,
        persona_core_prefixes,
        consult_fanout_approval_threshold,
        consult_fanout_controls,
        consult_fanout_precedence,
        consult_fanout_scope_rows,
        unsupported_schema,
        engine_version_floor,
        unknown_axis_seen,
    })
}
