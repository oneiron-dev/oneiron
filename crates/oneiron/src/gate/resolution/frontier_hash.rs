//! Read-frontier hash worker plus byte-level hash encoders.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicySelector, BudgetPolicyTable};

use super::manifest_types::{PolicyManifestDiagnostics, PolicyManifestResolution};
use crate::gate::ceiling::{
    DelegationGrantRecord, PolicyApprovalCeiling, PolicyAxes, PolicyCriticality,
    PolicyOwnerPolicyRow, PolicySensitivity, SourceTrustCeiling, SourceTrustRow,
};

pub(super) fn hash_policy_frontier_v0(
    hasher: &mut Sha256,
    resolution: &PolicyManifestResolution,
) -> Result<()> {
    hash_bytes(hasher, b"oneiron.gate.policy_frontier.v0");
    hash_diagnostics(hasher, resolution.diagnostics);
    hash_source_trust(hasher, &resolution.source_trust);
    hash_budget_exhaustion_policy(hasher, resolution.on_budget_exhausted());
    // The RESOLVED posture, beside its budget sibling: it decides whether an
    // opted-out send holds or ships, so flipping it must move the frontier and
    // invalidate every standing grant bound to the old one.
    hash_str(hasher, resolution.comm_opt_out_posture().as_str());
    // ONE-1296: hashed ONLY when the knob is present, so a manifest that never
    // names a checker keeps its exact no-checker frontier hash — and every
    // consent binding taken against it stays valid. A domain tag rides with
    // the value so no future optional field can collide with this one.
    if let Some(auto_checker) = resolution.auto_checker.as_deref() {
        hash_str(hasher, "auto_checker");
        hash_str(hasher, auto_checker);
    }
    // The raw resolved table, never the fail-closed accessor: a malformed
    // manifest contributes no decoded rows at all and its malformed-ness is
    // already frontier-relevant through `hash_diagnostics`.
    hash_budget_policy_table(hasher, &resolution.budget_policy);

    hash_len(hasher, resolution.packs.len());
    for pack in &resolution.packs {
        hash_str(hasher, &pack._pack_id);
        hash_str(hasher, &pack._pack_version);
        hash_str(hasher, &pack._min_engine_version);
        hash_axes(hasher, pack.defaults);
        hash_len(hasher, pack.rules.len());
        for rule in &pack.rules {
            hash_str(hasher, &rule.prefix);
            hash_bool(hasher, rule.exact);
            hash_axes(hasher, rule.axes);
        }
    }

    hash_len(hasher, resolution.actor_ceilings.len());
    for ceiling in &resolution.actor_ceilings {
        hash_str(hasher, &ceiling.actor_class);
        hash_opt_str(hasher, ceiling.actor_ref.as_deref());
        hash_approval_ceiling(hasher, ceiling.ceiling);
    }

    hash_len(hasher, resolution.delegation_fold.records.len());
    for (key, record) in &resolution.delegation_fold.records {
        hash_str(hasher, key);
        match record {
            DelegationGrantRecord::Grant {
                actor_class,
                actor_ref,
                parent_grant_ref,
                ceiling,
                ..
            } => {
                hash_str(hasher, "grant");
                hash_str(hasher, actor_class);
                hash_opt_str(hasher, actor_ref.as_deref());
                hash_opt_str(hasher, parent_grant_ref.as_deref());
                hash_approval_ceiling(hasher, *ceiling);
            }
            DelegationGrantRecord::RevokeGrant { .. } => hash_str(hasher, "revoke_grant"),
        }
    }
    hash_len(hasher, resolution.delegation_fold.revoked.len());
    for grant_ref in &resolution.delegation_fold.revoked {
        hash_str(hasher, grant_ref);
    }

    hash_len(hasher, resolution.scoped_grants.len());
    for grant in &resolution.scoped_grants {
        hash_opt_str(hasher, grant.actor_class.as_deref());
        hash_opt_str(hasher, grant.actor_ref.as_deref());
        hash_str(hasher, &grant.effector);
        hash_opt_value(hasher, grant.scope.as_ref())?;
        hash_opt_value(hasher, grant.budget.as_ref())?;
        hash_bool(hasher, grant.receipt_required);
    }

    hash_bool(hasher, resolution.owner_policy_enabled);
    hash_bool(hasher, resolution.owner_policy_rows_dropped);
    hash_len(hasher, resolution.owner_policy_rows.len());
    for row in &resolution.owner_policy_rows {
        hash_owner_policy_row(hasher, row);
    }

    resolution.hash_actor_burst_breaker(hasher);

    hash_opt_str(hasher, resolution.owner_policy_document.as_deref());
    hash_opt_str(hasher, resolution.owner_policy_output_contract.as_deref());
    hash_bool(hasher, resolution.owner_policy_patterns_dropped);
    hash_len(hasher, resolution.owner_policy_patterns.len());
    for row in &resolution.owner_policy_patterns {
        hash_str(hasher, &row.id);
        hash_str(hasher, &row.pattern);
        hash_str(hasher, &row.category);
        hash_opt_str(hasher, row.role.as_deref());
    }

    hash_len(hasher, resolution.signatures.len());
    for signature in &resolution.signatures {
        hash_str(hasher, &signature.alg);
        hash_opt_str(hasher, signature.key_id.as_deref());
        hash_str(hasher, &signature.sig);
    }

    Ok(())
}

fn hash_diagnostics(hasher: &mut Sha256, diagnostics: PolicyManifestDiagnostics) {
    hash_len(hasher, diagnostics.manifest_count);
    hash_bool(hasher, diagnostics.malformed_manifest_seen);
    hash_bool(hasher, diagnostics.unsupported_schema_seen);
    hash_bool(hasher, diagnostics.engine_version_floor_seen);
    hash_bool(hasher, diagnostics.unknown_axis_seen);
}

fn hash_source_trust(hasher: &mut Sha256, source_trust: &SourceTrustCeiling) {
    hash_bool(hasher, source_trust.malformed_manifest_seen);
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        hash_str(hasher, source.as_str());
        hash_source_trust_row(hasher, source_trust.row(source));
    }
}

fn hash_source_trust_row(hasher: &mut Sha256, row: Option<SourceTrustRow>) {
    let Some(row) = row else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_opt_u8(hasher, row.max_auto_sensitivity);
    hash_bool(hasher, row.receipted);
    hash_bool(hasher, row.warned);
    // The binding is frontier-relevant: rebinding a permit to a different
    // actor must move the hash, or a consent taken under one binding would
    // resolve unchanged under another.
    let actor_ref = row.actor_ref.as_ref().map(EntityId::to_hex);
    hash_opt_str(hasher, actor_ref.as_deref());
}

fn hash_owner_policy_row(hasher: &mut Sha256, row: &PolicyOwnerPolicyRow) {
    hash_str(hasher, &row.row_ref);
    hash_str(hasher, &row.text);
    hash_bool(hasher, row.active);
    hash_opt_str(hasher, row.world_ref.as_deref());
    hash_str(hasher, row.action.as_str());
}

fn hash_axes(hasher: &mut Sha256, axes: PolicyAxes) {
    hash_opt_criticality(hasher, axes.criticality);
    hash_opt_sensitivity(hasher, axes.sensitivity);
    hash_bool(hasher, axes.unknown_axis_seen);
}

fn hash_approval_ceiling(hasher: &mut Sha256, ceiling: PolicyApprovalCeiling) {
    hash_str(
        hasher,
        match ceiling {
            PolicyApprovalCeiling::Auto => "auto",
            PolicyApprovalCeiling::Proposed => "proposed",
        },
    );
}

fn hash_opt_criticality(hasher: &mut Sha256, criticality: Option<PolicyCriticality>) {
    let Some(criticality) = criticality else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(
        hasher,
        match criticality {
            PolicyCriticality::Normal => "normal",
            PolicyCriticality::Critical => "critical",
        },
    );
}

fn hash_opt_sensitivity(hasher: &mut Sha256, sensitivity: Option<PolicySensitivity>) {
    let Some(sensitivity) = sensitivity else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(
        hasher,
        match sensitivity {
            PolicySensitivity::Normal => "normal",
            PolicySensitivity::Sensitive => "sensitive",
        },
    );
}

fn hash_opt_value(hasher: &mut Sha256, value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return Ok(());
    };
    hash_bool(hasher, true);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| Error::InvariantViolation("policy frontier value encode failed"))?;
    hash_bytes(hasher, &encoded);
    Ok(())
}

pub(crate) fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(hasher, value);
}

fn hash_opt_u8(hasher: &mut Sha256, value: Option<u8>) {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hasher.update([value]);
}

pub(crate) fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

pub(crate) fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

pub(crate) fn hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_budget_exhaustion_policy(hasher: &mut Sha256, policy: BudgetExhaustionPolicy) {
    match policy {
        BudgetExhaustionPolicy::Suspend => hash_str(hasher, "suspend"),
        BudgetExhaustionPolicy::ContinueOnLocal => hash_str(hasher, "continue_on_local"),
        BudgetExhaustionPolicy::Overdraft { cap } => {
            hash_str(hasher, "overdraft");
            hash_u64(hasher, cap);
        }
    }
}

/// Row order is hashed because row order defines `row_index`; an absent table
/// and an explicit empty table hash identically (both are zero rows).
fn hash_budget_policy_table(hasher: &mut Sha256, table: &BudgetPolicyTable) {
    hash_len(hasher, table.rows().len());
    for row in table.rows() {
        match row.selector() {
            BudgetPolicySelector::Purpose(purpose) => {
                hash_str(hasher, "purpose");
                hash_str(hasher, BudgetPolicySelector::purpose_manifest_name(purpose));
            }
            BudgetPolicySelector::Actor(actor) => {
                hash_str(hasher, "actor");
                hash_bytes(hasher, actor.as_bytes());
            }
        }
        hash_bool(hasher, row.floor_units().is_some());
        if let Some(floor_units) = row.floor_units() {
            hash_u64(hasher, floor_units);
        }
        hash_bool(hasher, row.cap_units().is_some());
        if let Some(cap_units) = row.cap_units() {
            hash_u64(hasher, cap_units);
        }
    }
}
