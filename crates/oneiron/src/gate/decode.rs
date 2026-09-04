use std::io::Cursor;

use rmpv::Value;

use crate::claim::{ClaimSource, sensitivity_band_from_value};
use crate::entity_id::EntityId;
use crate::llm::{
    BudgetExhaustionPolicy, BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable, CallPurpose,
};

use super::ceiling::{
    ActorCeiling, DelegationGrantRecord, OwnerRowAction, PolicyApprovalCeiling, PolicyAxes,
    PolicyCriticality, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack, PolicyRule,
    PolicySensitivity, PolicySignature, SourceTrustCeiling, SourceTrustRow,
};
use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, AXIS_CRITICALITY_KEY, AXIS_SENSITIVITY_KEY,
    BUDGET_POLICY_ACTOR_KEY, BUDGET_POLICY_CAP_KEY, BUDGET_POLICY_FLOOR_KEY,
    BUDGET_POLICY_PURPOSE_KEY, GRANT_BUDGET_KEY, GRANT_EFFECTOR_KEY, GRANT_RECEIPT_REQUIRED_KEY,
    GRANT_SCOPE_KEY, POLICY_ACTOR_CEILINGS_KEY, POLICY_BUDGET_POLICY_KEY,
    POLICY_COMM_OPT_OUT_POSTURE_KEY, POLICY_DEFAULTS_KEY, POLICY_DELEGATED_GRANTS_KEY,
    POLICY_LEGAL_FLOOR_ROWS_KEY, POLICY_MIN_ENGINE_VERSION_KEY, POLICY_ON_BUDGET_EXHAUSTED_KEY,
    POLICY_OWNER_POLICY_DOCUMENT_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY, POLICY_OWNER_POLICY_PATTERNS_KEY,
    POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PACK_ID_KEY, POLICY_PACK_VERSION_KEY,
    POLICY_PATTERN_CATEGORY_KEY, POLICY_PATTERN_ID_KEY, POLICY_PATTERN_PATTERN_KEY,
    POLICY_PATTERN_ROLE_KEY, POLICY_ROW_ACTION_KEY, POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY,
    POLICY_ROW_TEXT_KEY, POLICY_ROW_WORLD_REF_KEY, POLICY_RULES_KEY, POLICY_SCHEMA_VERSION,
    POLICY_SCHEMA_VERSION_KEY, POLICY_SCOPED_GRANTS_KEY, POLICY_SIGNATURE_KEY,
    POLICY_SIGNATURES_KEY, POLICY_SOURCE_TRUST_KEY, RULE_AXES_KEY, RULE_EXACT_KEY, RULE_PREFIX_KEY,
    SIGNATURE_ALG_KEY, SIGNATURE_KEY_ID_KEY, SIGNATURE_SIG_KEY, SIGNATURE_SIGNATURE_KEY,
    SOURCE_TRUST_AUTO_KEY, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY, SOURCE_TRUST_RECEIPTED_KEY,
    SOURCE_TRUST_WARNED_KEY,
};
use super::grants::PolicyScopedGrant;
use super::resolution::CommOptOutPosture;

pub(super) struct DecodedPolicyManifest {
    pub(super) pack: PolicyPack,
    pub(super) actor_ceilings: Vec<ActorCeiling>,
    pub(super) delegated_grants: Vec<DelegationGrantRecord>,
    pub(super) source_trust: SourceTrustCeiling,
    pub(super) scoped_grants: Vec<PolicyScopedGrant>,
    pub(super) owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    pub(super) owner_policy_rows_dropped: bool,
    pub(super) owner_policy_enabled: bool,
    pub(super) owner_policy_document: Option<String>,
    pub(super) owner_policy_output_contract: Option<String>,
    pub(super) owner_policy_patterns: Vec<PolicyOwnerPatternRow>,
    pub(super) owner_policy_patterns_dropped: bool,
    pub(super) signatures: Vec<PolicySignature>,
    pub(super) on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    pub(super) comm_opt_out_posture: Option<CommOptOutPosture>,
    pub(super) budget_policy: BudgetPolicyTable,
    pub(super) unsupported_schema: bool,
    pub(super) engine_version_floor: bool,
    pub(super) unknown_axis_seen: bool,
}

pub(super) fn decode_policy_manifest(data: &[u8]) -> Option<DecodedPolicyManifest> {
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
                | POLICY_BUDGET_POLICY_KEY
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
    let budget_policy = match single_map_value(&entries, POLICY_BUDGET_POLICY_KEY) {
        MapValue::Missing => BudgetPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_budget_policy(value)?,
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
        budget_policy,
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
const OWNER_POLICY_DOCUMENT_MAX_LEN: usize = 65_536;

/// Longest output-contract NAME a manifest may carry. It is a preset spelling
/// (`binary`, `category_json`, …) that `policy_model` looks up, so the bound
/// only has to keep a manifest from carrying a blob where a keyword belongs.
const OWNER_POLICY_OUTPUT_CONTRACT_MAX_LEN: usize = 64;

fn nonblank_bounded_string(value: &Value, max_len: usize) -> Option<String> {
    let value = value.as_str()?;
    if value.trim().is_empty() || value.len() > max_len {
        return None;
    }
    Some(value.to_owned())
}

/// Parses the `owner_policy_patterns` array. Every entry must be a row map
/// carrying only the four recognized keys — an unknown key rejects the whole
/// table, exactly as [`parse_owner_policy_rows`] does, so a misspelled `role`
/// can never fall through to the permissive default and quietly change what a
/// rule is allowed to do.
fn parse_owner_policy_patterns(value: &Value) -> Option<Vec<PolicyOwnerPatternRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                POLICY_PATTERN_ID_KEY
                | POLICY_PATTERN_PATTERN_KEY
                | POLICY_PATTERN_CATEGORY_KEY
                | POLICY_PATTERN_ROLE_KEY => {}
                _ => return None,
            }
        }
        parsed.push(PolicyOwnerPatternRow {
            id: required_nonempty_string(entries, POLICY_PATTERN_ID_KEY)?,
            pattern: required_nonempty_string(entries, POLICY_PATTERN_PATTERN_KEY)?,
            category: required_nonempty_string(entries, POLICY_PATTERN_CATEGORY_KEY)?,
            role: optional_string(entries, POLICY_PATTERN_ROLE_KEY)?,
        });
    }
    Some(parsed)
}

fn parse_rules(value: &Value) -> Option<Vec<PolicyRule>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let prefix = required_string(entries, RULE_PREFIX_KEY)?;
        if prefix.is_empty() {
            return None;
        }
        let exact = optional_bool(entries, RULE_EXACT_KEY)?;
        let axes = parse_axes(required_value(entries, RULE_AXES_KEY)?)?;
        rules.push(PolicyRule {
            prefix,
            exact,
            axes,
        });
    }
    Some(rules)
}

fn parse_axes(value: &Value) -> Option<PolicyAxes> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut axes = PolicyAxes::default();
    let mut criticality_seen = false;
    let mut sensitivity_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            AXIS_CRITICALITY_KEY => {
                if criticality_seen {
                    return None;
                }
                criticality_seen = true;
                axes.criticality = Some(PolicyCriticality::parse(value)?);
            }
            AXIS_SENSITIVITY_KEY => {
                if sensitivity_seen {
                    return None;
                }
                sensitivity_seen = true;
                axes.sensitivity = Some(PolicySensitivity::parse(value)?);
            }
            _ => axes.unknown_axis_seen = true,
        }
    }

    Some(axes)
}

fn parse_actor_ceilings(value: &Value) -> Option<Vec<ActorCeiling>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut actor_ceilings = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = required_string(entries, ACTOR_CLASS_KEY)?;
        if actor_class.is_empty() {
            return None;
        }
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let ceiling = PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?;
        actor_ceilings.push(ActorCeiling {
            actor_class,
            actor_ref,
            ceiling,
        });
    }
    Some(actor_ceilings)
}

pub(super) fn parse_delegated_grants(value: &Value) -> Option<Vec<DelegationGrantRecord>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut out = Vec::new();
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let op = match (
            single_map_value(entries, "op"),
            single_map_value(entries, "kind"),
        ) {
            (MapValue::Present(v), MapValue::Missing)
            | (MapValue::Missing, MapValue::Present(v)) => v.as_str()?,
            _ => return None,
        };
        let grant_ref = required_nonempty_string(entries, "grant_ref")?;
        for (key, _) in entries {
            let key = key.as_str()?;
            let allowed = match op {
                "revoke_grant" => matches!(key, "op" | "kind" | "grant_ref"),
                "grant" => matches!(
                    key,
                    "op" | "kind"
                        | "grant_ref"
                        | ACTOR_CLASS_KEY
                        | ACTOR_REF_KEY
                        | "parent_grant_ref"
                        | ACTOR_CEILING_KEY
                ),
                _ => false,
            };
            if !allowed {
                return None;
            }
        }
        match op {
            "revoke_grant" => out.push(DelegationGrantRecord::RevokeGrant { grant_ref }),
            "grant" => out.push(DelegationGrantRecord::Grant {
                grant_ref,
                actor_class: required_nonempty_string(entries, ACTOR_CLASS_KEY)?,
                actor_ref: optional_string(entries, ACTOR_REF_KEY)?,
                parent_grant_ref: optional_string(entries, "parent_grant_ref")?,
                ceiling: PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?,
            }),
            _ => return None,
        }
    }
    Some(out)
}

fn parse_source_trust(value: &Value) -> Option<SourceTrustCeiling> {
    let Value::Map(source_rows) = value else {
        return None;
    };
    let mut ceiling = SourceTrustCeiling::default();
    for (source_key, row_value) in source_rows {
        let source = source_key.as_str().and_then(ClaimSource::parse)?;
        let row = parse_source_trust_row(row_value)?;
        ceiling.set_row(source, row);
    }
    Some(ceiling)
}

fn parse_source_trust_row(value: &Value) -> Option<SourceTrustRow> {
    match value {
        // The shorthand row shapes carry no actor binding, so they stay
        // class-wide exactly as before.
        Value::Boolean(false) => Some(SourceTrustRow {
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
            actor_ref: None,
        }),
        Value::Integer(_) | Value::String(_) => Some(SourceTrustRow {
            max_auto_sensitivity: sensitivity_band_from_value(value),
            receipted: false,
            warned: false,
            actor_ref: None,
        }),
        Value::Map(entries) => {
            let mut max_auto_sensitivity = None;
            let mut auto_disabled = false;
            let mut receipted = false;
            let mut warned = false;
            let mut actor_ref = None;

            for (key, value) in entries {
                match key.as_str()? {
                    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY => {
                        max_auto_sensitivity = Some(sensitivity_band_from_value(value)?);
                    }
                    SOURCE_TRUST_AUTO_KEY => match value {
                        Value::Boolean(false) => auto_disabled = true,
                        Value::Boolean(true) => {}
                        _ => return None,
                    },
                    SOURCE_TRUST_RECEIPTED_KEY => {
                        receipted = value.as_bool()?;
                    }
                    SOURCE_TRUST_WARNED_KEY => {
                        warned = value.as_bool()?;
                    }
                    // An actor binding must decode to a real entity id or the
                    // whole row is malformed: a permit aimed at an unreadable
                    // ref would otherwise silently widen back to class-wide.
                    ACTOR_REF_KEY => {
                        actor_ref = Some(EntityId::from_hex(value.as_str()?).ok()?);
                    }
                    _ => {}
                }
            }

            Some(SourceTrustRow {
                max_auto_sensitivity: if auto_disabled {
                    None
                } else {
                    Some(max_auto_sensitivity?)
                },
                receipted,
                warned,
                actor_ref,
            })
        }
        _ => None,
    }
}

fn parse_budget_exhaustion_policy(value: &Value) -> Option<BudgetExhaustionPolicy> {
    if let Some(policy) = value.as_str().and_then(parse_budget_exhaustion_policy_kind) {
        return Some(policy);
    }

    let Value::Map(entries) = value else {
        return None;
    };

    match single_map_value(entries, "kind") {
        MapValue::Present(kind) => match kind.as_str()? {
            "suspend" => Some(BudgetExhaustionPolicy::Suspend),
            "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
            "overdraft" => {
                let cap = required_value(entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
            _ => None,
        },
        MapValue::Missing => match single_map_value(entries, "overdraft") {
            MapValue::Missing | MapValue::Duplicate => None,
            MapValue::Present(overdraft) => {
                let Value::Map(overdraft_entries) = overdraft else {
                    return None;
                };
                let cap = required_value(overdraft_entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
        },
        MapValue::Duplicate => None,
    }
}

/// Exact inverse of [`CommOptOutPosture::as_str`]. A plain token and nothing
/// else: the posture is a two-valued dial, not a shape with sub-keys.
fn parse_comm_opt_out_posture(value: &Value) -> Option<CommOptOutPosture> {
    match value.as_str()? {
        "escalate" => Some(CommOptOutPosture::Escalate),
        "allow_with_receipt" => Some(CommOptOutPosture::AllowWithReceipt),
        _ => None,
    }
}

fn parse_budget_exhaustion_policy_kind(kind: &str) -> Option<BudgetExhaustionPolicy> {
    match kind {
        "suspend" => Some(BudgetExhaustionPolicy::Suspend),
        "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
        _ => None,
    }
}

/// Parses the ordered `budget_policy` row array. Every entry must be a valid
/// row map; any malformed entry rejects the whole table so
/// `decode_policy_manifest` drops the manifest rather than silently widening
/// the policy by ignoring rows.
fn parse_budget_policy(value: &Value) -> Option<BudgetPolicyTable> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        parsed.push(parse_budget_policy_row(entries)?);
    }
    Some(BudgetPolicyTable::from_rows(parsed))
}

/// One row is valid only with exactly one of `purpose`/`actor`, at least one
/// of `floor`/`cap`, unsigned 64-bit units (`0` is valid: `cap: 0` denies the
/// row deliberately, `floor: 0` is an explicit no-op reservation), no
/// duplicated key, and no unknown key — unknown keys are never ignored.
fn parse_budget_policy_row(entries: &[(Value, Value)]) -> Option<BudgetPolicyRow> {
    let mut purpose = None;
    let mut actor = None;
    let mut floor_units = None;
    let mut cap_units = None;
    let mut purpose_seen = false;
    let mut actor_seen = false;
    let mut floor_seen = false;
    let mut cap_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            BUDGET_POLICY_PURPOSE_KEY => {
                if purpose_seen {
                    return None;
                }
                purpose_seen = true;
                purpose = Some(parse_budget_purpose(value)?);
            }
            BUDGET_POLICY_ACTOR_KEY => {
                if actor_seen {
                    return None;
                }
                actor_seen = true;
                actor = Some(parse_budget_actor(value)?);
            }
            BUDGET_POLICY_FLOOR_KEY => {
                if floor_seen {
                    return None;
                }
                floor_seen = true;
                floor_units = Some(value.as_u64()?);
            }
            BUDGET_POLICY_CAP_KEY => {
                if cap_seen {
                    return None;
                }
                cap_seen = true;
                cap_units = Some(value.as_u64()?);
            }
            _ => return None,
        }
    }

    let selector = match (purpose, actor) {
        (Some(purpose), None) => BudgetPolicySelector::Purpose(purpose),
        (None, Some(actor)) => BudgetPolicySelector::Actor(actor),
        _ => return None,
    };
    if !floor_seen && !cap_seen {
        return None;
    }
    Some(BudgetPolicyRow::new(selector, floor_units, cap_units))
}

/// Built-in names map to their pinned `CallPurpose` variants; any other
/// non-empty string is an exact-name `Other`. An `Other` name that happens
/// to equal a built-in's snake-case name parses to the built-in variant, so
/// it can never spell a wildcard.
fn parse_budget_purpose(value: &Value) -> Option<CallPurpose> {
    let name = value.as_str()?;
    if name.is_empty() {
        return None;
    }
    Some(match name {
        "extraction" => CallPurpose::Extraction,
        "consolidation" => CallPurpose::Consolidation,
        "answer_gen" => CallPurpose::AnswerGen,
        "auto_check" => CallPurpose::AutoCheck,
        "tool_routing" => CallPurpose::ToolRouting,
        "voice" => CallPurpose::Voice,
        "eval" => CallPurpose::Eval,
        _ => CallPurpose::Other {
            name: name.to_owned(),
        },
    })
}

/// Actor rows name the canonical lowercase 32-hex `EntityId` form that
/// `WriteActor::entity_ref().to_hex()` produces; any other spelling (wrong
/// length, non-hex, uppercase) rejects the row.
fn parse_budget_actor(value: &Value) -> Option<EntityId> {
    let text = value.as_str()?;
    let id = EntityId::from_hex(text).ok()?;
    if id.to_hex() != text {
        return None;
    }
    Some(id)
}

fn parse_scoped_grants(value: &Value) -> Option<Vec<PolicyScopedGrant>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut grants = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = optional_string(entries, ACTOR_CLASS_KEY)?;
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let effector = required_string(entries, GRANT_EFFECTOR_KEY)?;
        if effector.is_empty() {
            return None;
        }
        let scope = optional_value(entries, GRANT_SCOPE_KEY)?;
        let budget = optional_value(entries, GRANT_BUDGET_KEY)?;
        let receipt_required = match single_map_value(entries, GRANT_RECEIPT_REQUIRED_KEY) {
            MapValue::Missing => true,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => value.as_bool()?,
        };
        grants.push(PolicyScopedGrant {
            actor_class,
            actor_ref,
            effector,
            scope,
            budget,
            receipt_required,
        });
    }
    Some(grants)
}

/// Parses the `owner_policy_rows` array. Every entry must be a valid row map
/// carrying only the five recognized keys — an unknown key rejects the whole
/// table, exactly as [`parse_budget_policy_row`] does, so a misspelled
/// `action` can never fall through to the gentle `Warn` default and quietly
/// widen the owner's plane.
fn parse_owner_policy_rows(value: &Value) -> Option<Vec<PolicyOwnerPolicyRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                POLICY_ROW_REF_KEY
                | POLICY_ROW_TEXT_KEY
                | POLICY_ROW_ACTIVE_KEY
                | POLICY_ROW_WORLD_REF_KEY
                | POLICY_ROW_ACTION_KEY => {}
                _ => return None,
            }
        }
        let row_ref = required_nonempty_string(entries, POLICY_ROW_REF_KEY)?;
        let text = required_nonempty_string(entries, POLICY_ROW_TEXT_KEY)?;
        let active = optional_bool_default(entries, POLICY_ROW_ACTIVE_KEY, true)?;
        let world_ref = optional_string(entries, POLICY_ROW_WORLD_REF_KEY)?;
        let action = match optional_string(entries, POLICY_ROW_ACTION_KEY)? {
            // A row that names no action only wants to be told about, so the
            // gentlest arm is the default: content still ships unchanged.
            None => OwnerRowAction::Warn,
            Some(action) => parse_owner_row_action(&action)?,
        };
        // `row_ref` is the owner plane's whole vocabulary: it is what the
        // model answers in, what a pattern rule names, and what resolution
        // looks up — and resolution takes the FIRST match, so a duplicate is a
        // rule that can never fire, however strict its action.
        //
        // The key is the PAIR, not the ref alone: one ref written twice under
        // two worlds is the scoped-override shape `active_owner_policy_rows`
        // exists to resolve, and only rows that would land in the same rubric
        // together shadow each other. Refusing them here drops the rows as
        // malformed rather than letting one silently swallow the other.
        if parsed.iter().any(|seen: &PolicyOwnerPolicyRow| {
            seen.row_ref == row_ref && seen.world_ref == world_ref
        }) {
            return None;
        }
        parsed.push(PolicyOwnerPolicyRow {
            row_ref,
            text,
            active,
            world_ref,
            action,
        });
    }
    Some(parsed)
}

fn parse_owner_row_action(action: &str) -> Option<OwnerRowAction> {
    match action {
        "warn" => Some(OwnerRowAction::Warn),
        "block" => Some(OwnerRowAction::Block),
        "route_to_help" | "route-to-help" => Some(OwnerRowAction::RouteToHelp),
        _ => None,
    }
}

fn required_nonempty_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    let value = required_string(entries, key)?;
    if value.is_empty() { None } else { Some(value) }
}

fn optional_bool_default(entries: &[(Value, Value)], key: &str, default: bool) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(default),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

fn parse_signatures(value: &Value) -> Option<Vec<PolicySignature>> {
    let Value::Array(rows) = value else {
        return None;
    };
    rows.iter().map(parse_signature_value).collect()
}

fn parse_signature_value(value: &Value) -> Option<PolicySignature> {
    match value {
        Value::String(sig) => Some(PolicySignature {
            alg: "unknown".to_owned(),
            key_id: None,
            sig: sig.as_str()?.to_owned(),
        }),
        Value::Map(entries) => {
            let alg = required_string(entries, SIGNATURE_ALG_KEY)?;
            let key_id = optional_string(entries, SIGNATURE_KEY_ID_KEY)?;
            let sig = match single_map_value(entries, SIGNATURE_SIG_KEY) {
                MapValue::Present(value) => value.as_str()?.to_owned(),
                MapValue::Missing => required_string(entries, SIGNATURE_SIGNATURE_KEY)?,
                MapValue::Duplicate => return None,
            };
            if alg.is_empty() || sig.is_empty() {
                return None;
            }
            Some(PolicySignature { alg, key_id, sig })
        }
        _ => None,
    }
}

enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => Some(value),
        MapValue::Missing | MapValue::Duplicate => None,
    }
}

fn optional_value(entries: &[(Value, Value)], key: &str) -> Option<Option<Value>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => Some(Some(value.clone())),
    }
}

fn required_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    required_value(entries, key)?.as_str().map(str::to_owned)
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Option<Option<String>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => {
            let value = value.as_str()?;
            if value.is_empty() {
                None
            } else {
                Some(Some(value.to_owned()))
            }
        }
    }
}

fn optional_bool(entries: &[(Value, Value)], key: &str) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(false),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

fn version_gt(left: &str, right: &str) -> Option<bool> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Some(left > right)
}

fn parse_version(value: &str) -> Option<[u64; 3]> {
    let trimmed = value.strip_prefix('v').unwrap_or(value);
    let mut out = [0_u64; 3];
    let mut count = 0usize;
    for (index, part) in trimmed.split('.').enumerate() {
        if index >= out.len() || part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        out[index] = part.parse().ok()?;
        count += 1;
    }
    if count == 0 { None } else { Some(out) }
}
