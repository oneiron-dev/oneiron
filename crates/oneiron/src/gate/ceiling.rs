use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::agent_def::AgentCeiling;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{Error, Result};

use super::constants::MAX_DELEGATION_DEPTH;
use super::decision::{GateDecision, GateOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyApprovalCeiling {
    Auto,
    Proposed,
}

impl PolicyApprovalCeiling {
    pub(super) fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    /// Gate-side conversion from the persisted AGENT_DEF descriptor mirror.
    /// Lives here so the dependency direction stays `gate.rs` → `agent_def.rs`
    /// and `PolicyApprovalCeiling` stays `pub(crate)`.
    pub(crate) fn from_agent_ceiling(ceiling: AgentCeiling) -> Self {
        match ceiling {
            AgentCeiling::Auto => Self::Auto,
            AgentCeiling::Proposed => Self::Proposed,
        }
    }

    pub(super) fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Proposed) || matches!(other, Self::Proposed) {
            Self::Proposed
        } else {
            Self::Auto
        }
    }
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn foreign_agent_effective_ceiling(
    confirmed_scope: PolicyApprovalCeiling,
    introducer_ceiling: PolicyApprovalCeiling,
) -> PolicyApprovalCeiling {
    confirmed_scope.restrict(introducer_ceiling)
}

/// OF-074 symmetry helper mirroring [`foreign_agent_effective_ceiling`]: a
/// dispatched agent's effective ceiling is its definition-authored bound
/// restricted by the owner's `actor_ceilings` manifest projection.
#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn dispatched_agent_effective_ceiling(
    definition: PolicyApprovalCeiling,
    policy_projection: PolicyApprovalCeiling,
) -> PolicyApprovalCeiling {
    definition.restrict(policy_projection)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyCriticality {
    Normal,
    Critical,
}

impl PolicyCriticality {
    pub(super) fn parse(value: &Value) -> Option<Self> {
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
    pub(super) fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "normal" => Some(Self::Normal),
            "sensitive" => Some(Self::Sensitive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PolicyAxes {
    pub(super) criticality: Option<PolicyCriticality>,
    pub(super) sensitivity: Option<PolicySensitivity>,
    pub(super) unknown_axis_seen: bool,
}

impl PolicyAxes {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn restrict(self, other: Self) -> Self {
        Self {
            criticality: restrict_optional(self.criticality, other.criticality),
            sensitivity: restrict_optional(self.sensitivity, other.sensitivity),
            unknown_axis_seen: self.unknown_axis_seen || other.unknown_axis_seen,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyRule {
    pub(super) prefix: String,
    pub(super) exact: bool,
    pub(super) axes: PolicyAxes,
}

impl PolicyRule {
    fn matches(&self, predicate: &str) -> bool {
        if self.exact {
            predicate == self.prefix
        } else {
            predicate.starts_with(&self.prefix)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyPack {
    pub(super) _pack_id: String,
    pub(super) _pack_version: String,
    pub(super) _min_engine_version: String,
    pub(super) defaults: PolicyAxes,
    pub(super) rules: Vec<PolicyRule>,
}

impl PolicyPack {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut best_len = 0usize;
        let mut resolved = self.defaults;

        for rule in &self.rules {
            if rule.matches(predicate) {
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
pub(super) enum DelegationGrantRecord {
    Grant {
        grant_ref: String,
        actor_class: String,
        actor_ref: Option<String>,
        parent_grant_ref: Option<String>,
        ceiling: PolicyApprovalCeiling,
    },
    RevokeGrant {
        grant_ref: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoldedDelegation {
    effective_ceiling: Option<PolicyApprovalCeiling>,
    depth: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DelegationFoldCache {
    by_grant_ref: BTreeMap<String, FoldedDelegation>,
    pub(super) records: BTreeMap<String, DelegationGrantRecord>,
    /// Revocations remain durable even when a later manifest also mentions the grant.
    pub(super) revoked: BTreeSet<String>,
}
impl DelegationFoldCache {
    pub(crate) fn effective_ceiling(&self, grant_ref: &str) -> Option<PolicyApprovalCeiling> {
        self.by_grant_ref
            .get(grant_ref)
            .and_then(|x| x.effective_ceiling)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ActorCeiling {
    pub(super) actor_class: String,
    pub(super) actor_ref: Option<String>,
    pub(super) ceiling: PolicyApprovalCeiling,
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn foreign_agent_ceiling_after_widen_request(
    current_ceiling: PolicyApprovalCeiling,
    requested_ceiling: PolicyApprovalCeiling,
    normal_gate_decision: &GateDecision,
) -> PolicyApprovalCeiling {
    if normal_gate_decision.outcome() == GateOutcome::Allow {
        requested_ceiling
    } else {
        current_ceiling
    }
}

/// What an owner-plane row asks the engine to do when it fires. There is no
/// rewrite arm: the engine never substitutes content, so a row can only pass
/// content through with a notice (`Warn`), withhold it (`Block`), or hand the
/// turn to a help card (`RouteToHelp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerRowAction {
    Warn,
    Block,
    RouteToHelp,
}

impl OwnerRowAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }
}

/// One pattern rule the vault owner wrote, exactly as the manifest carried it.
///
/// The strings stay raw here on purpose: `gate` sits UNDER `policy_model` in
/// the crate's layering, so it stores what the owner authored and lets the
/// policy plane compile and validate it against that plane's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOwnerPatternRow {
    pub(crate) id: String,
    pub(crate) pattern: String,
    pub(crate) category: String,
    /// Absent when the row named no role; the policy plane supplies its own
    /// default, which is the unreliable-signal one.
    pub(crate) role: Option<String>,
}

/// One row of the vault owner's own policy. The owner plane is the ONLY plane
/// a local/sovereign vault classifies against, and it is opt-in: see
/// [`PolicyManifestResolution::owner_policy_enabled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOwnerPolicyRow {
    pub(crate) row_ref: String,
    pub(crate) text: String,
    pub(crate) active: bool,
    pub(crate) world_ref: Option<String>,
    pub(crate) action: OwnerRowAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySignature {
    pub(crate) alg: String,
    pub(crate) key_id: Option<String>,
    pub(crate) sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SourceTrustRow {
    pub(super) max_auto_sensitivity: Option<u8>,
    pub(super) receipted: bool,
    pub(super) warned: bool,
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
pub(super) struct SourceTrustCeiling {
    pub(super) user_stated: Option<SourceTrustRow>,
    pub(super) observed: Option<SourceTrustRow>,
    pub(super) inferred: Option<SourceTrustRow>,
    pub(super) imported: Option<SourceTrustRow>,
    pub(super) tool_output: Option<SourceTrustRow>,
    pub(super) generated: Option<SourceTrustRow>,
    pub(super) malformed_manifest_seen: bool,
}

impl SourceTrustCeiling {
    pub(super) fn malformed() -> Self {
        Self {
            malformed_manifest_seen: true,
            ..Self::default()
        }
    }

    pub(super) fn row(&self, source: ClaimSource) -> Option<SourceTrustRow> {
        match source {
            ClaimSource::UserStated => self.user_stated,
            ClaimSource::Observed => self.observed,
            ClaimSource::Inferred => self.inferred,
            ClaimSource::Imported => self.imported,
            ClaimSource::ToolOutput => self.tool_output,
            ClaimSource::Generated => self.generated,
        }
    }

    pub(super) fn set_row(&mut self, source: ClaimSource, row: SourceTrustRow) {
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

    pub(super) fn merge(&mut self, other: Self) {
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

    pub(super) fn fail_closed(&mut self) {
        self.malformed_manifest_seen = true;
    }
}

pub(super) fn check_source_trust(
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

pub(super) fn fold_delegated_grants(
    records: &[DelegationGrantRecord],
) -> Option<DelegationFoldCache> {
    let mut revoked = BTreeSet::new();
    let mut map = BTreeMap::new();
    for r in records {
        match r {
            DelegationGrantRecord::RevokeGrant { grant_ref } => {
                revoked.insert(grant_ref.clone());
            }
            DelegationGrantRecord::Grant { grant_ref, .. } => {
                map.entry(grant_ref.clone()).or_insert_with(|| r.clone());
            }
        }
    }
    let mut cache = DelegationFoldCache {
        by_grant_ref: BTreeMap::new(),
        records: map,
        revoked,
    };
    #[allow(clippy::items_after_statements)]
    fn visit(
        key: &str,
        cache: &mut DelegationFoldCache,
        revoked: &BTreeSet<String>,
        stack: &mut BTreeSet<String>,
    ) -> Option<FoldedDelegation> {
        if revoked.contains(key) {
            return Some(FoldedDelegation {
                effective_ceiling: None,
                depth: 1,
            });
        }
        if let Some(v) = cache.by_grant_ref.get(key) {
            return Some(v.clone());
        }
        if !stack.insert(key.to_owned()) {
            return None;
        }
        if stack.len() > usize::from(MAX_DELEGATION_DEPTH) {
            return None;
        }
        let result = match cache.records.get(key)?.clone() {
            DelegationGrantRecord::Grant {
                parent_grant_ref,
                ceiling,
                ..
            } => {
                let (effective, depth) = if let Some(parent) = parent_grant_ref {
                    let p = visit(&parent, cache, revoked, stack)?;
                    (
                        p.effective_ceiling.map(|x| x.restrict(ceiling)),
                        p.depth.saturating_add(1),
                    )
                } else {
                    (Some(ceiling), 1)
                };
                if depth > MAX_DELEGATION_DEPTH {
                    return None;
                }
                FoldedDelegation {
                    effective_ceiling: effective,
                    depth,
                }
            }
            _ => FoldedDelegation {
                effective_ceiling: None,
                depth: 1,
            },
        };
        stack.remove(key);
        cache.by_grant_ref.insert(key.to_owned(), result.clone());
        Some(result)
    }
    let revoked = cache.revoked.clone();
    #[allow(clippy::needless_collect)]
    for key in cache.records.keys().cloned().collect::<Vec<_>>() {
        visit(&key, &mut cache, &revoked, &mut BTreeSet::new())?;
    }
    Some(cache)
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
