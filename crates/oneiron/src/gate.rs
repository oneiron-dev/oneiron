//! DEC-0005 Gate policy manifest resolver.
//!
//! GATE-001 deliberately stops at stable decision inputs. The unified write
//! chokepoint and new Gate outcomes are GATE-002 work; this module only
//! resolves vault-resident PolicyManifestV1 rows and feeds the existing
//! source-trust claim gate.

use std::cmp::Ordering;
use std::io::Cursor;

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, claim_sensitivity_band,
    sensitivity_band_from_value,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{ENTITY_ID_LEN, ENTITY_TYPE_POLICY_MANIFEST, EntityId};

const POLICY_SCHEMA_VERSION_KEY: &str = "schema_version";
const POLICY_SCHEMA_VERSION: &str = "1.1";
const POLICY_PACK_ID_KEY: &str = "pack_id";
const POLICY_PACK_VERSION_KEY: &str = "pack_version";
const POLICY_MIN_ENGINE_VERSION_KEY: &str = "min_engine_version";
const POLICY_DEFAULTS_KEY: &str = "defaults";
const POLICY_RULES_KEY: &str = "rules";
const POLICY_ACTOR_CEILINGS_KEY: &str = "actor_ceilings";
const POLICY_SOURCE_TRUST_KEY: &str = "source_trust";
const POLICY_SCOPED_GRANTS_KEY: &str = "scoped_grants";
const POLICY_SIGNATURE_KEY: &str = "signature";
const POLICY_SIGNATURES_KEY: &str = "signatures";

const AXIS_CRITICALITY_KEY: &str = "criticality";
const AXIS_SENSITIVITY_KEY: &str = "sensitivity";
const RULE_PREFIX_KEY: &str = "prefix";
const RULE_AXES_KEY: &str = "axes";
const ACTOR_CLASS_KEY: &str = "actor_class";
const ACTOR_REF_KEY: &str = "actor_ref";
const ACTOR_CEILING_KEY: &str = "ceiling";
const SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY: &str = "max_auto_sensitivity";
const SOURCE_TRUST_AUTO_KEY: &str = "auto";
const SOURCE_TRUST_RECEIPTED_KEY: &str = "receipted";
const SOURCE_TRUST_WARNED_KEY: &str = "warned";
const GRANT_EFFECTOR_KEY: &str = "effector";
const GRANT_SCOPE_KEY: &str = "scope";
const GRANT_BUDGET_KEY: &str = "budget";
const GRANT_RECEIPT_REQUIRED_KEY: &str = "receipt_required";
const SIGNATURE_ALG_KEY: &str = "alg";
const SIGNATURE_KEY_ID_KEY: &str = "key_id";
const SIGNATURE_SIG_KEY: &str = "sig";
const SIGNATURE_SIGNATURE_KEY: &str = "signature";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyApprovalCeiling {
    Auto,
    Proposed,
}

impl PolicyApprovalCeiling {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Proposed) || matches!(other, Self::Proposed) {
            Self::Proposed
        } else {
            Self::Auto
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyCriticality {
    Normal,
    Critical,
}

impl PolicyCriticality {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "normal" => Some(Self::Normal),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicySensitivity {
    Normal,
    Sensitive,
}

impl PolicySensitivity {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "normal" => Some(Self::Normal),
            "sensitive" => Some(Self::Sensitive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PolicyAxes {
    criticality: Option<PolicyCriticality>,
    sensitivity: Option<PolicySensitivity>,
    unknown_axis_seen: bool,
}

impl PolicyAxes {
    #[cfg_attr(not(test), allow(dead_code))]
    fn restrict(self, other: Self) -> Self {
        Self {
            criticality: restrict_optional(self.criticality, other.criticality),
            sensitivity: restrict_optional(self.sensitivity, other.sensitivity),
            unknown_axis_seen: self.unknown_axis_seen || other.unknown_axis_seen,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRule {
    prefix: String,
    axes: PolicyAxes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyPack {
    _pack_id: String,
    _pack_version: String,
    _min_engine_version: String,
    defaults: PolicyAxes,
    rules: Vec<PolicyRule>,
}

impl PolicyPack {
    #[cfg_attr(not(test), allow(dead_code))]
    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut best_len = 0usize;
        let mut resolved = self.defaults;

        for rule in &self.rules {
            if predicate.starts_with(&rule.prefix) {
                match rule.prefix.len().cmp(&best_len) {
                    Ordering::Greater => {
                        best_len = rule.prefix.len();
                        resolved = rule.axes;
                    }
                    Ordering::Equal => {
                        resolved = resolved.restrict(rule.axes);
                    }
                    Ordering::Less => {}
                }
            }
        }

        resolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorCeiling {
    actor_class: String,
    actor_ref: Option<String>,
    ceiling: PolicyApprovalCeiling,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateActor {
    pub(crate) actor_class: String,
    pub(crate) actor_ref: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateContentKind {
    Claim,
    EdgeProvenanceClaim,
    PolicyManifest,
    ExternalEffect,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateContentKind {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::EdgeProvenanceClaim => "edge_provenance_claim",
            Self::PolicyManifest => "policy_manifest",
            Self::ExternalEffect => "external_effect",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GateProvenanceHandles {
    pub(crate) actor_entity_ref: Option<EntityId>,
    pub(crate) substrate_ref: Option<EntityId>,
    pub(crate) source_revision_ref: Option<[u8; ENTITY_ID_LEN]>,
    pub(crate) body_snapshot_ref: Option<[u8; ENTITY_ID_LEN]>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateEvaluatorInput {
    pub(crate) actor: GateActor,
    pub(crate) source: ClaimSource,
    pub(crate) content_kind: GateContentKind,
    pub(crate) criticality: PolicyCriticality,
    pub(crate) policy_manifest_version: String,
    pub(crate) provenance: GateProvenanceHandles,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    Allow,
    Pending,
    Deny,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateOutcome {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Pending => "pending",
            Self::Deny => "deny",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateReasonCode {
    Allow,
    DenyMissingActorClass,
    DenyMissingActorProvenance,
    DenyMissingPolicyManifestVersion,
    DenyPolicyFailClosed,
    PendingActorCeiling,
    PendingSourceTrust,
    PendingCriticalityFloor,
    PendingPolicyManifestAuthority,
    PendingExternalEffectAuthority,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateReasonCode {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "gate.allow",
            Self::DenyMissingActorClass => "gate.deny.missing_actor_class",
            Self::DenyMissingActorProvenance => "gate.deny.missing_actor_provenance",
            Self::DenyMissingPolicyManifestVersion => "gate.deny.missing_policy_manifest_version",
            Self::DenyPolicyFailClosed => "gate.deny.policy_fail_closed",
            Self::PendingActorCeiling => "gate.pending.actor_ceiling",
            Self::PendingSourceTrust => "gate.pending.source_trust",
            Self::PendingCriticalityFloor => "gate.pending.criticality_floor",
            Self::PendingPolicyManifestAuthority => "gate.pending.policy_manifest_authority",
            Self::PendingExternalEffectAuthority => "gate.pending.external_effect_authority",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateDecision {
    outcome: GateOutcome,
    reason_codes: Vec<GateReasonCode>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateDecision {
    fn allow() -> Self {
        Self {
            outcome: GateOutcome::Allow,
            reason_codes: vec![GateReasonCode::Allow],
        }
    }

    fn deny(reason_code: GateReasonCode) -> Self {
        Self {
            outcome: GateOutcome::Deny,
            reason_codes: vec![reason_code],
        }
    }

    fn pending(reason_codes: Vec<GateReasonCode>) -> Self {
        Self {
            outcome: GateOutcome::Pending,
            reason_codes,
        }
    }

    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) fn reason_codes(&self) -> &[GateReasonCode] {
        &self.reason_codes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PolicyScopedGrant {
    pub(crate) actor_class: Option<String>,
    pub(crate) actor_ref: Option<String>,
    pub(crate) effector: String,
    pub(crate) scope: Option<Value>,
    pub(crate) budget: Option<Value>,
    pub(crate) receipt_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySignature {
    pub(crate) alg: String,
    pub(crate) key_id: Option<String>,
    pub(crate) sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceTrustRow {
    max_auto_sensitivity: Option<u8>,
    receipted: bool,
    warned: bool,
}

impl SourceTrustRow {
    fn merge(self, other: Self) -> Self {
        let max_auto_sensitivity = match (self.max_auto_sensitivity, other.max_auto_sensitivity) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };

        Self {
            max_auto_sensitivity,
            receipted: self.receipted && other.receipted,
            warned: self.warned && other.warned,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SourceTrustCeiling {
    user_stated: Option<SourceTrustRow>,
    observed: Option<SourceTrustRow>,
    inferred: Option<SourceTrustRow>,
    imported: Option<SourceTrustRow>,
    tool_output: Option<SourceTrustRow>,
    generated: Option<SourceTrustRow>,
    malformed_manifest_seen: bool,
}

impl SourceTrustCeiling {
    fn malformed() -> Self {
        Self {
            malformed_manifest_seen: true,
            ..Self::default()
        }
    }

    fn row(&self, source: ClaimSource) -> Option<SourceTrustRow> {
        match source {
            ClaimSource::UserStated => self.user_stated,
            ClaimSource::Observed => self.observed,
            ClaimSource::Inferred => self.inferred,
            ClaimSource::Imported => self.imported,
            ClaimSource::ToolOutput => self.tool_output,
            ClaimSource::Generated => self.generated,
        }
    }

    fn set_row(&mut self, source: ClaimSource, row: SourceTrustRow) {
        let slot = match source {
            ClaimSource::UserStated => &mut self.user_stated,
            ClaimSource::Observed => &mut self.observed,
            ClaimSource::Inferred => &mut self.inferred,
            ClaimSource::Imported => &mut self.imported,
            ClaimSource::ToolOutput => &mut self.tool_output,
            ClaimSource::Generated => &mut self.generated,
        };
        *slot = Some(slot.map_or(row, |existing| existing.merge(row)));
    }

    fn merge(&mut self, other: Self) {
        self.malformed_manifest_seen |= other.malformed_manifest_seen;
        for source in [
            ClaimSource::UserStated,
            ClaimSource::Observed,
            ClaimSource::Inferred,
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ] {
            if let Some(row) = other.row(source) {
                self.set_row(source, row);
            }
        }
    }

    fn fail_closed(&mut self) {
        self.malformed_manifest_seen = true;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyManifestDiagnostics {
    pub(crate) manifest_count: usize,
    pub(crate) malformed_manifest_seen: bool,
    pub(crate) unsupported_schema_seen: bool,
    pub(crate) engine_version_floor_seen: bool,
    pub(crate) unknown_axis_seen: bool,
}

impl PolicyManifestDiagnostics {
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_fail_closed(self) -> bool {
        self.manifest_count == 0
            || self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }

    fn loaded_manifest_forces_fail_closed(self) -> bool {
        self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    diagnostics: PolicyManifestDiagnostics,
    packs: Vec<PolicyPack>,
    actor_ceilings: Vec<ActorCeiling>,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    signatures: Vec<PolicySignature>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PolicyManifestResolution {
    #[must_use]
    pub(crate) fn diagnostics(&self) -> PolicyManifestDiagnostics {
        self.diagnostics
    }

    #[must_use]
    pub(crate) fn is_fail_closed(&self) -> bool {
        self.diagnostics.is_fail_closed()
    }

    #[must_use]
    pub(crate) fn actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> PolicyApprovalCeiling {
        if self.is_fail_closed() {
            return PolicyApprovalCeiling::Proposed;
        }

        let mut ceiling: Option<PolicyApprovalCeiling> = None;
        for row in &self.actor_ceilings {
            if row.actor_class != actor_class {
                continue;
            }
            match (&row.actor_ref, actor_ref) {
                (None, _) => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                (Some(row_ref), Some(request_ref)) if row_ref == request_ref => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                _ => {}
            }
        }
        ceiling.unwrap_or(PolicyApprovalCeiling::Proposed)
    }

    #[must_use]
    pub(crate) fn criticality_for_predicate(&self, predicate: &str) -> PolicyCriticality {
        if self.is_fail_closed() {
            return PolicyCriticality::Critical;
        }

        self.axes_for_predicate(predicate)
            .criticality
            .unwrap_or(PolicyCriticality::Critical)
    }

    #[must_use]
    pub(crate) fn sensitivity_for_predicate(&self, predicate: &str) -> PolicySensitivity {
        if self.is_fail_closed() {
            return PolicySensitivity::Sensitive;
        }

        self.axes_for_predicate(predicate)
            .sensitivity
            .unwrap_or(PolicySensitivity::Sensitive)
    }

    #[must_use]
    pub(crate) fn scoped_grants(&self) -> &[PolicyScopedGrant] {
        if self.is_fail_closed() {
            &[]
        } else {
            &self.scoped_grants
        }
    }

    #[must_use]
    pub(crate) fn signatures(&self) -> &[PolicySignature] {
        &self.signatures
    }

    #[must_use]
    pub(crate) fn evaluate_gate(&self, input: &GateEvaluatorInput) -> GateDecision {
        if input.actor.actor_class.is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorClass);
        }
        if input.provenance.actor_entity_ref.is_none() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorProvenance);
        }
        if input.policy_manifest_version.trim().is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingPolicyManifestVersion);
        }
        if self.is_fail_closed() {
            return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
        }

        let mut pending = Vec::new();

        if self.actor_ceiling(&input.actor.actor_class, input.actor.actor_ref.as_deref())
            == PolicyApprovalCeiling::Proposed
        {
            pending.push(GateReasonCode::PendingActorCeiling);
        }

        if !self.source_trust_allows_auto(input.source) {
            pending.push(GateReasonCode::PendingSourceTrust);
        }

        if input.criticality == PolicyCriticality::Critical {
            pending.push(GateReasonCode::PendingCriticalityFloor);
        }

        match input.content_kind {
            GateContentKind::Claim | GateContentKind::EdgeProvenanceClaim => {}
            GateContentKind::PolicyManifest => {
                pending.push(GateReasonCode::PendingPolicyManifestAuthority);
            }
            GateContentKind::ExternalEffect => {
                pending.push(GateReasonCode::PendingExternalEffectAuthority);
            }
        }

        if pending.is_empty() {
            GateDecision::allow()
        } else {
            GateDecision::pending(pending)
        }
    }

    fn source_trust_allows_auto(&self, source: ClaimSource) -> bool {
        if self.source_trust.malformed_manifest_seen {
            return false;
        }

        let Some(row) = self.source_trust.row(source) else {
            return !source.requires_explicit_auto_permit();
        };

        row.max_auto_sensitivity.is_some()
            && (!source.requires_explicit_auto_permit() || (row.receipted && row.warned))
    }

    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut resolved = PolicyAxes::default();
        for pack in &self.packs {
            resolved = resolved.restrict(pack.axes_for_predicate(predicate));
        }
        resolved
    }
}

struct DecodedPolicyManifest {
    pack: PolicyPack,
    actor_ceilings: Vec<ActorCeiling>,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    signatures: Vec<PolicySignature>,
    unsupported_schema: bool,
    engine_version_floor: bool,
    unknown_axis_seen: bool,
}

pub(crate) fn resolve_policy_manifest(
    store: &Store,
    txn: &heed::RwTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();

    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(key) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        }

        match decode_policy_manifest(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]) {
            Some(decoded) => {
                resolution.diagnostics.manifest_count += 1;
                resolution.diagnostics.unsupported_schema_seen |= decoded.unsupported_schema;
                resolution.diagnostics.engine_version_floor_seen |= decoded.engine_version_floor;
                resolution.diagnostics.unknown_axis_seen |= decoded.unknown_axis_seen;
                resolution.source_trust.merge(decoded.source_trust);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                resolution.signatures.extend(decoded.signatures);
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    if resolution.diagnostics.loaded_manifest_forces_fail_closed() {
        resolution.source_trust.fail_closed();
    }

    Ok(resolution)
}

pub(crate) fn check_claim_policy(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    check_source_trust(
        body.source,
        body.approval,
        claim_sensitivity_band(body),
        &policy.source_trust,
    )
}

fn check_source_trust(
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
    sensitivity: Option<u8>,
    ceiling: &SourceTrustCeiling,
) -> Result<()> {
    if approval != ClaimApprovalStatus::Auto {
        return Ok(());
    }

    let Some(source) = source else {
        return Ok(());
    };

    if ceiling.malformed_manifest_seen {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    let Some(sensitivity) = sensitivity else {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    };

    let Some(row) = ceiling.row(source) else {
        if source.requires_explicit_auto_permit() {
            return Err(Error::SourceNotTrustedForAuto {
                claim_source: source.as_str(),
            });
        }
        return Ok(());
    };

    let Some(max_auto_sensitivity) = row.max_auto_sensitivity else {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    };

    if sensitivity > max_auto_sensitivity {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    if source.requires_explicit_auto_permit() && (!row.receipted || !row.warned) {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    Ok(())
}

fn type_index_entity_id(key: &[u8]) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != ENTITY_TYPE_POLICY_MANIFEST {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}

fn decode_policy_manifest(data: &[u8]) -> Option<DecodedPolicyManifest> {
    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != data.len() as u64 {
        return None;
    }
    let Value::Map(entries) = value else {
        return None;
    };

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
        source_trust,
        scoped_grants,
        signatures,
        unsupported_schema,
        engine_version_floor,
        unknown_axis_seen,
    })
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
        let axes = parse_axes(required_value(entries, RULE_AXES_KEY)?)?;
        rules.push(PolicyRule { prefix, axes });
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
        Value::Boolean(false) => Some(SourceTrustRow {
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        }),
        Value::Integer(_) | Value::String(_) => Some(SourceTrustRow {
            max_auto_sensitivity: sensitivity_band_from_value(value),
            receipted: false,
            warned: false,
        }),
        Value::Map(entries) => {
            let mut max_auto_sensitivity = None;
            let mut auto_disabled = false;
            let mut receipted = false;
            let mut warned = false;

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
            })
        }
        _ => None,
    }
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

#[cfg_attr(not(test), allow(dead_code))]
fn restrict_optional<T>(left: Option<T>, right: Option<T>) -> Option<T>
where
    T: Copy + Restrict,
{
    match (left, right) {
        (Some(left), Some(right)) => Some(left.restrict(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
trait Restrict {
    fn restrict(self, other: Self) -> Self;
}

impl Restrict for PolicyCriticality {
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Critical) || matches!(other, Self::Critical) {
            Self::Critical
        } else {
            Self::Normal
        }
    }
}

impl Restrict for PolicySensitivity {
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Sensitive) || matches!(other, Self::Sensitive) {
            Self::Sensitive
        } else {
            Self::Normal
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
        claim_body_decode_count, encode_claim_body, reset_claim_body_decode_count,
    };
    use crate::types::{ENTITY_TYPE_CLAIM, TimeRange};

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test id")
    }

    fn test_time(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())
            .expect("open vault");
        (tmp, vault)
    }

    fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::from(POLICY_SCHEMA_VERSION_KEY),
                Value::from(POLICY_SCHEMA_VERSION),
            ),
            (Value::from(POLICY_PACK_ID_KEY), Value::from("gate-test")),
            (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
            (
                Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from(POLICY_DEFAULTS_KEY),
                Value::Map(vec![
                    (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                    (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                ]),
            ),
            (
                Value::from(POLICY_RULES_KEY),
                Value::Array(vec![Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("health.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("sensitive")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from(POLICY_ACTOR_CEILINGS_KEY),
                Value::Array(vec![
                    Value::Map(vec![
                        (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                    ]),
                    Value::Map(vec![
                        (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                        (Value::from(ACTOR_REF_KEY), Value::from("probation")),
                        (Value::from(ACTOR_CEILING_KEY), Value::from("proposed")),
                    ]),
                ]),
            ),
        ];
        entries.extend(extra_entries);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
        out
    }

    fn rewrite_policy_manifest_entries(
        data: &mut Vec<u8>,
        rewrite: impl FnOnce(&mut Vec<(Value, Value)>),
    ) {
        let mut cursor = Cursor::new(data.as_slice());
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
            unreachable!("test manifest is a map");
        };
        rewrite(&mut entries);
        data.clear();
        rmpv::encode::write_value(data, &Value::Map(entries)).expect("re-encode");
    }

    fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
        let row = Value::Map(vec![
            (
                Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                Value::from(u64::from(max_auto_sensitivity)),
            ),
            (
                Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                Value::Boolean(true),
            ),
            (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
        ]);
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![(Value::from(source.as_str()), row)]),
        )
    }

    fn scoped_grants_entry() -> (Value, Value) {
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(ACTOR_REF_KEY), Value::from("dreamer")),
                (Value::from(GRANT_EFFECTOR_KEY), Value::from("channel_send")),
                (
                    Value::from(GRANT_SCOPE_KEY),
                    Value::Map(vec![(Value::from("audience"), Value::from("cold"))]),
                ),
                (
                    Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                    Value::Boolean(true),
                ),
            ])]),
        )
    }

    fn signatures_entry() -> (Value, Value) {
        (
            Value::from(POLICY_SIGNATURES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
                (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
                (Value::from(SIGNATURE_SIG_KEY), Value::from("00")),
            ])]),
        )
    }

    fn policy_manifest_blob(data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);
        payload
    }

    fn put_policy_manifest_bytes(vault: &crate::Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = test_id(seed);
        let payload = policy_manifest_blob(data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    fn resolve(vault: &crate::Vault) -> Result<PolicyManifestResolution> {
        vault.with_write_txn(|wtxn| resolve_policy_manifest(&vault.store, wtxn))
    }

    fn source_trust_claim(source: ClaimSource) -> ClaimBody {
        let mut body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(test_id(0x21)),
            Value::from("Ada"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(source);
        body
    }

    fn source_trust_claim_data(source: ClaimSource) -> Vec<u8> {
        encode_claim_body(&source_trust_claim(source)).expect("claim encode")
    }

    fn gate_evaluator_input(
        actor_class: &str,
        actor_ref: Option<&str>,
        source: ClaimSource,
        criticality: PolicyCriticality,
    ) -> GateEvaluatorInput {
        GateEvaluatorInput {
            actor: GateActor {
                actor_class: actor_class.to_owned(),
                actor_ref: actor_ref.map(str::to_owned),
            },
            source,
            content_kind: GateContentKind::Claim,
            criticality,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(test_id(0xA0)),
                substrate_ref: Some(test_id(0xA1)),
                source_revision_ref: Some([0xA2; ENTITY_ID_LEN]),
                body_snapshot_ref: Some([0xA3; ENTITY_ID_LEN]),
            },
        }
    }

    fn gate_reason_strs(decision: &GateDecision) -> Vec<&'static str> {
        decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str())
            .collect()
    }

    fn assert_auto_source_rejected(
        vault: &crate::Vault,
        seed: u8,
        source: ClaimSource,
    ) -> Result<()> {
        let id = test_id(seed);
        let data = source_trust_claim_data(source);
        let err = vault
            .batch()
            .put(&id, ENTITY_TYPE_CLAIM, test_time(6), 6, &data)
            .commit()
            .expect_err("manifest must reject risky auto source");
        assert!(
            matches!(err, Error::SourceNotTrustedForAuto { claim_source: got } if got == source.as_str()),
            "expected source trust error for {}, got {err:?}",
            source.as_str()
        );
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    #[test]
    fn gate_evaluator_actor_source_criticality_matrix() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x71, &data)?;
        let policy = resolve(&vault)?;

        let cases = [
            (
                "auto actor trusted source normal criticality",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Normal,
                GateOutcome::Allow,
                vec![GateReasonCode::Allow],
            ),
            (
                "auto actor trusted source critical floor",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingCriticalityFloor],
            ),
            (
                "auto actor low source trust normal criticality",
                None,
                ClaimSource::ToolOutput,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingSourceTrust],
            ),
            (
                "auto actor low source trust critical floor",
                None,
                ClaimSource::ToolOutput,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingSourceTrust,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
            (
                "proposed actor trusted source normal criticality",
                Some("probation"),
                ClaimSource::UserStated,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingActorCeiling],
            ),
            (
                "proposed actor trusted source critical floor",
                Some("probation"),
                ClaimSource::UserStated,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
            (
                "proposed actor low source trust normal criticality",
                Some("probation"),
                ClaimSource::ToolOutput,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingSourceTrust,
                ],
            ),
            (
                "proposed actor low source trust critical floor",
                Some("probation"),
                ClaimSource::ToolOutput,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingSourceTrust,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
        ];

        for (name, actor_ref, source, criticality, outcome, reasons) in cases {
            let input = gate_evaluator_input("first_party", actor_ref, source, criticality);
            let decision = policy.evaluate_gate(&input);
            assert_eq!(decision.outcome(), outcome, "{name}");
            assert_eq!(decision.reason_codes(), reasons.as_slice(), "{name}");
            assert!(
                decision
                    .reason_codes()
                    .iter()
                    .all(|code| code.as_str().starts_with("gate.")),
                "{name}: reason codes must be stable gate.* strings"
            );
        }

        Ok(())
    }

    #[test]
    fn gate_evaluator_denial_reason_codes_are_stable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x72, &data)?;
        let policy = resolve(&vault)?;

        let mut missing_actor_class = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_actor_class.actor.actor_class.clear();
        let decision = policy.evaluate_gate(&missing_actor_class);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_actor_class"]
        );

        let mut missing_actor_provenance = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_actor_provenance.provenance.actor_entity_ref = None;
        let decision = policy.evaluate_gate(&missing_actor_provenance);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_actor_provenance"]
        );

        let mut missing_policy_version = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_policy_version.policy_manifest_version.clear();
        let decision = policy.evaluate_gate(&missing_policy_version);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_policy_manifest_version"]
        );

        let fail_closed_policy = PolicyManifestResolution::default();
        let input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        let decision = fail_closed_policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.policy_fail_closed"]
        );

        Ok(())
    }

    #[test]
    fn gate_evaluator_content_kind_reasons_are_stable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x73, &data)?;
        let policy = resolve(&vault)?;

        let mut edge_provenance = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        edge_provenance.content_kind = GateContentKind::EdgeProvenanceClaim;
        assert_eq!(
            edge_provenance.content_kind.as_str(),
            "edge_provenance_claim"
        );
        let decision = policy.evaluate_gate(&edge_provenance);
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        let mut policy_manifest = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        policy_manifest.content_kind = GateContentKind::PolicyManifest;
        assert_eq!(policy_manifest.content_kind.as_str(), "policy_manifest");
        let decision = policy.evaluate_gate(&policy_manifest);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.policy_manifest_authority"]
        );

        let mut external_effect = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        external_effect.content_kind = GateContentKind::ExternalEffect;
        assert_eq!(external_effect.content_kind.as_str(), "external_effect");
        let decision = policy.evaluate_gate(&external_effect);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        assert_eq!(decision.outcome().as_str(), "pending");

        Ok(())
    }

    #[test]
    fn policy_manifest_valid_fixture_resolves_gate_inputs() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
            signatures_entry(),
        ]);
        put_policy_manifest_bytes(&vault, 0x51, &data)?;

        let policy = resolve(&vault)?;
        assert!(!policy.is_fail_closed());
        assert_eq!(policy.diagnostics().manifest_count, 1);
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Auto
        );
        assert_eq!(
            policy.actor_ceiling("first_party", Some("probation")),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("health.allergy"),
            PolicyCriticality::Critical
        );
        assert_eq!(
            policy.sensitivity_for_predicate("health.allergy"),
            PolicySensitivity::Sensitive
        );
        assert_eq!(policy.scoped_grants().len(), 1);
        assert_eq!(policy.signatures().len(), 1);

        let id = test_id(0x63);
        let claim = source_trust_claim_data(ClaimSource::ToolOutput);
        reset_claim_body_decode_count();
        vault
            .batch()
            .put(&id, ENTITY_TYPE_CLAIM, test_time(3), 3, &claim)
            .commit()?;
        assert!(vault.get_raw(&id)?.is_some());
        assert_eq!(
            claim_body_decode_count(),
            1,
            "policy gate must reuse the write-door decode"
        );
        Ok(())
    }

    #[test]
    fn policy_manifest_missing_fixture_fails_closed_where_required() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("profile.name"),
            PolicyCriticality::Critical
        );

        assert_auto_source_rejected(&vault, 0x64, ClaimSource::ToolOutput)?;
        assert_auto_source_rejected(&vault, 0x65, ClaimSource::Imported)?;

        let id = test_id(0x66);
        let data = source_trust_claim_data(ClaimSource::Observed);
        vault
            .batch()
            .put(&id, ENTITY_TYPE_CLAIM, test_time(4), 4, &data)
            .commit()?;
        assert!(vault.get_raw(&id)?.is_some());
        Ok(())
    }

    #[test]
    fn policy_manifest_malformed_fixture_fails_closed() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x52, b"not-msgpack")?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().malformed_manifest_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("profile.name"),
            PolicyCriticality::Critical
        );
        assert_auto_source_rejected(&vault, 0x67, ClaimSource::ToolOutput)
    }

    #[test]
    fn policy_manifest_missing_schema_fixture_fails_closed() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
        });
        put_policy_manifest_bytes(&vault, 0x54, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().unsupported_schema_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_auto_source_rejected(&vault, 0x69, ClaimSource::ToolOutput)
    }

    #[test]
    fn policy_manifest_version_fixture_degrades_to_most_restrictive() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_MIN_ENGINE_VERSION_KEY) {
                    *value = Value::from("999.0.0");
                }
            }
        });
        put_policy_manifest_bytes(&vault, 0x53, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().engine_version_floor_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("health.allergy"),
            PolicyCriticality::Critical
        );
        assert_auto_source_rejected(&vault, 0x68, ClaimSource::ToolOutput)
    }

    #[test]
    fn policy_manifest_unknown_axis_fails_closed_and_exposes_no_scoped_grants() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                    let Value::Map(defaults) = value else {
                        unreachable!("defaults are a map");
                    };
                    defaults.push((Value::from("future_axis"), Value::from("permit")));
                }
            }
        });
        put_policy_manifest_bytes(&vault, 0x55, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().unknown_axis_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.sensitivity_for_predicate("profile.name"),
            PolicySensitivity::Sensitive
        );
        assert_auto_source_rejected(&vault, 0x6A, ClaimSource::ToolOutput)
    }

    #[test]
    fn legacy_source_trust_pack_entity_does_not_relax_policy_inputs() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut legacy = Vec::new();
        rmpv::encode::write_value(
            &mut legacy,
            &Value::Map(vec![
                (
                    Value::from("manifest"),
                    Value::from("dec_0005_predicate_pack"),
                ),
                source_trust_entry(ClaimSource::ToolOutput, 0),
            ]),
        )
        .expect("legacy source-trust encode");

        vault.put_entity(
            &test_id(0x56),
            crate::types::ENTITY_TYPE_TASK_LIST,
            test_time(1),
            1,
            &legacy,
        )?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert_eq!(policy.diagnostics().manifest_count, 0);
        assert_auto_source_rejected(&vault, 0x6B, ClaimSource::ToolOutput)
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replay_path_skips_policy_source_trust_gate() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let id = test_id(0x81);
        let data = source_trust_claim_data(ClaimSource::ToolOutput);

        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
            .commit()?;

        assert!(
            vault.get_raw(&id)?.is_some(),
            "replicated replay must not re-gate remote source trust"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replicated_policy_manifest_is_rejected_and_cannot_relax_source_trust() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        let occurred = test_time(1);

        let batch_id = test_id(0x82);
        let err = vault
            .batch()
            .put_replicated(&batch_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
            .commit()
            .expect_err("replicated policy manifests must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
            "expected policy manifest maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&batch_id)?.is_none());

        let txn_id = test_id(0x83);
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put_replicated(&txn_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
                    .apply(wtxn)
            })
            .expect_err("txn replicated policy manifests must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
            "expected policy manifest maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&txn_id)?.is_none());

        assert_auto_source_rejected(&vault, 0x84, ClaimSource::ToolOutput)
    }

    #[cfg(feature = "sync")]
    #[test]
    fn forward_rematerialize_quarantines_replicated_policy_manifest() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_insert_bytes;
        use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::forward_rematerialize;

        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        let id = test_id(0x85);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("local", &window_key);
        let blob = policy_manifest_blob(&data);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
            .expect("insert policy manifest into CRDT");
        doc.commit();

        let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
        assert_eq!(materialized, 0);
        assert!(vault.get_raw(&id)?.is_none());
        let records = quarantined_records(&vault)?;
        assert!(
            records.iter().any(|(_, record)| {
                record.container == QuarantineContainer::Entities
                    && record.reason_code == "MaintenanceKindNotWritable"
            }),
            "rejected policy manifest replay should be quarantined, got {records:?}"
        );

        assert_auto_source_rejected(&vault, 0x86, ClaimSource::ToolOutput)
    }
}
