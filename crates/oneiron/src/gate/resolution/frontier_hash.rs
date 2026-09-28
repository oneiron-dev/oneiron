//! Read-frontier hash worker plus byte-level hash encoders.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicySelector, BudgetPolicyTable};

use super::manifest_types::{PolicyManifestDiagnostics, PolicyManifestResolution};
use crate::gate::ask_policy::AskPolicySurface;
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
    hash_str(hasher, "single_valued_predicates");
    hash_len(hasher, resolution.single_valued_predicates.len());
    for predicate in &resolution.single_valued_predicates {
        hash_str(hasher, predicate);
    }
    // Hashed only when a manifest names a class row, so a manifest that never
    // did keeps its frontier and every consent binding taken against it.
    if let Some(carry) = resolution.connector_class_carry.as_ref() {
        hash_str(hasher, "connector_class_policy.v1");
        hash_str(hasher, resolution.connector_class_precedence.as_str());
        hash_len(hasher, carry.len());
        for (from, to) in carry {
            hash_str(hasher, from);
            hash_str(hasher, to);
        }
    }
    // A teacher floor change changes admission and invalidates approval
    // snapshots; include the resolved row in the policy frontier too.
    if let Some(vault_min) = resolution.teacher_probe_vault_min {
        hash_str(hasher, "teacher_probe");
        hash_u64(hasher, u64::from(vault_min));
        hash_len(hasher, resolution.teacher_probe_holders.len());
        for (holder, minimum) in &resolution.teacher_probe_holders {
            hash_str(hasher, holder);
            hash_u64(hasher, u64::from(*minimum));
        }
    }
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
    // Default rows and owner-authored overrides both affect admission and its
    // consent frontier. Absent policy keeps the old frontier unchanged.
    if let Some(defaults) = resolution.voice_ref_defaults.as_ref() {
        hash_voice_ref_policy(hasher, "voice_ref_defaults", defaults);
    }
    if resolution.voice_ref_limits
        != crate::voice_identity::ref_limits::VoiceRefLimitPolicy::default()
    {
        hash_voice_ref_policy(
            hasher,
            "voice_ref_owner_limits",
            &resolution.voice_ref_limits,
        );
    }
    if let Some(policy) = &resolution.pack_install_policy {
        hash_str(hasher, "pack_install_policy");
        let value = policy.encode();
        hash_opt_value(hasher, Some(&value))?;
    }
    if let Some(limits) = resolution.pptx_comment_limits {
        hash_str(hasher, "pptx_comment_limits:nested_narrowing");
        for value in [
            limits.max_patches,
            limits.max_author_name_bytes,
            limits.max_xml_bytes,
            limits.max_xml_attributes,
            limits.max_xml_namespaces,
            limits.max_xml_depth,
            limits.max_xml_nodes,
        ] {
            hash_u64(hasher, value as u64);
        }
    }
    // Behavior-deciding archive policy moves the frontier when vault or exact
    // holder bounds change. Hash declared rows, not only a selected caller.
    if !resolution.docx_archive_limits.is_empty() {
        hash_str(hasher, "docx_archive_limits");
        hash_len(hasher, resolution.docx_archive_limits.len());
        for policy in &resolution.docx_archive_limits {
            for value in [
                policy.vault.max_entries as u64,
                policy.vault.max_part_bytes,
                policy.vault.max_total_bytes,
            ] {
                hash_u64(hasher, value);
            }
            hash_len(hasher, policy.holders.len());
            for (actor, limits) in &policy.holders {
                hash_bytes(hasher, actor.as_bytes());
                for value in [
                    limits.max_entries as u64,
                    limits.max_part_bytes,
                    limits.max_total_bytes,
                ] {
                    hash_u64(hasher, value);
                }
            }
        }
    }
    // An absent/empty hosted policy changes no decision and keeps the
    // established frontier bytes for manifests that never named this knob.
    if !resolution.hosted_tts.rows.is_empty() {
        hash_str(hasher, "hosted_tts");
        hash_str(hasher, resolution.hosted_tts.precedence.as_str());
        hash_len(hasher, resolution.hosted_tts.rows.len());
        for row in &resolution.hosted_tts.rows {
            hash_str(hasher, &row.provider);
            match row.scope {
                crate::gate::hosted_tts_policy::HostedTtsScope::Vault => hash_str(hasher, "vault"),
                crate::gate::hosted_tts_policy::HostedTtsScope::Holder(id) => {
                    hash_str(hasher, "holder");
                    hash_bytes(hasher, id.as_bytes());
                }
            }
            hash_u64(hasher, row.limits.max_text_bytes as u64);
            hash_u64(hasher, row.limits.max_pcm_fragment_bytes as u64);
        }
    }
    // The shipped row and an absent legacy row resolve identically. Only a
    // behavior change contributes a new domain tag, preserving existing
    // no-review-policy consent bindings.
    if resolution.slide_review_policy != crate::llm::decision::SlideReviewPolicy::default() {
        let mut slide_policy = Vec::new();
        rmpv::encode::write_value(&mut slide_policy, &resolution.slide_review_policy.rows())
            .map_err(|_| Error::InvariantViolation("slide review policy frontier encoding"))?;
        hash_str(hasher, "slide_review_policy");
        hash_bytes(hasher, &slide_policy);
    }
    // Absent and explicit shipped baseline resolve identically. A stricter
    // trusted row changes the frontier; its six ceilings are hashed together.
    if let Some(bounds) = resolution.docedit_resource_policy {
        let baseline = crate::gate::docedit_resource::DoceditResourcePolicy::shipped();
        if bounds != baseline {
            hash_str(hasher, "docedit_resource_policy");
            for value in crate::gate::docedit_resource::row_values(bounds) {
                hash_u64(hasher, value);
            }
        }
    }
    if let Some(bounds) = resolution.diagnostic_bounds {
        hash_str(hasher, "diagnostic_bounds");
        hash_u64(hasher, bounds.window_secs);
        hash_u64(hasher, bounds.consent_depth);
        hash_u64(hasher, bounds.actor_writes);
    }

    // Attribution limits bound post-terminal receipt capture, not Gate authority.
    // Tuning them must not rebind existing consent/grant frontiers.
    if let Some(threshold) = resolution.proposal_check_threshold {
        hash_str(hasher, "proposal_check_threshold");
        hash_u64(hasher, threshold);
    }

    // An absent row and the shipped 4096 vault row have identical effective
    // policy. Keep their existing frontier hash stable; hash only restrictions
    // that actually move the default, scoped or otherwise.
    let nondefault: Vec<_> = resolution
        .sheet_answer_limits
        .iter()
        .chain(resolution.untrusted_sheet_answer_limits.iter())
        .filter(|row| {
            row.artifact_ref.is_some()
                || row.sheet.is_some()
                || Some(row.max_count) != resolution.sheet_answer_default_max_count
        })
        .collect();
    if !nondefault.is_empty() {
        hash_str(hasher, "sheet_answer_limits");
        hash_len(hasher, nondefault.len());
        for row in nondefault {
            hash_opt_str(hasher, row.artifact_ref.as_deref());
            hash_opt_str(hasher, row.sheet.as_deref());
            hash_u64(hasher, row.max_count);
        }
    }

    // Operational settings are identity-bearing only when declared: old vaults
    // retain their existing frontier, while any policy amendment moves it.
    if let Some(row) = resolution.linear_mirror {
        hash_str(hasher, "linear_mirror_policy");
        hash_u64(hasher, row.poll_interval_secs);
        hash_u64(hasher, row.request_timeout_secs);
    }
    if let Some(row) = resolution.linear_sync {
        hash_str(hasher, "linear_sync_budget");
        hash_u64(hasher, row.max_pull_pages_per_pass as u64);
    }
    if let Some(row) = resolution.wave_handoff {
        hash_str(hasher, "wave_handoff_policy");
        hash_u64(hasher, row.scan_limit as u64);
        hash_u64(hasher, row.retry_floor_ms);
        hash_u64(hasher, row.retry_cap_ms);
    }
    if let Some(precedence) = resolution.operational_precedence {
        hash_str(hasher, "operational_policy_precedence");
        hash_str(hasher, precedence.as_str());
    }
    if let Some(policy) = &resolution.weave_correction_policy {
        hash_str(hasher, "weave_correction_policy");
        policy.hash_into(hasher);
    }
    if let Some(ask) = &resolution.ask_policy {
        hash_str(hasher, "ask_operational_policy.v1");
        hash_u64(hasher, u64::from(ask.guest_fact_limit));
        hash_u64(hasher, u64::from(ask.retry_page_limit));
        hash_str(hasher, ask.default_surface.token());
        hash_str(hasher, ask.precedence.token());
        hash_len(hasher, ask.allowed_surfaces.len());
        for surface in &ask.allowed_surfaces {
            hash_str(hasher, surface.token());
        }
        hash_len(hasher, ask.holder_overrides.len());
        for (holder, override_row) in &ask.holder_overrides {
            hash_bytes(hasher, holder.as_bytes());
            hash_u64(
                hasher,
                u64::from(override_row.guest_fact_limit.unwrap_or(0)),
            );
            hash_u64(
                hasher,
                u64::from(override_row.retry_page_limit.unwrap_or(0)),
            );
            hash_opt_str(hasher, override_row.surface.map(AskPolicySurface::token));
        }
    }

    // Hash authored typed selectors/precedence, not an invented fallback.
    if !resolution.retry_source_policy.is_empty() {
        hash_str(hasher, "retry_source_policy");
        hash_len(hasher, resolution.retry_source_policy.len());
        for row in &resolution.retry_source_policy {
            match row.selector {
                crate::gate::retry_source_policy::RetrySelector::Vault => hash_str(hasher, "vault"),
                crate::gate::retry_source_policy::RetrySelector::Holder(id) => {
                    hash_str(hasher, "holder");
                    hash_bytes(hasher, id.as_bytes());
                }
                crate::gate::retry_source_policy::RetrySelector::Project(id) => {
                    hash_str(hasher, "project");
                    hash_bytes(hasher, id.as_bytes());
                }
            }
            hash_u64(hasher, row.max_sources.get() as u64);
            if let Some(precedence) = row.precedence {
                hash_str(hasher, precedence.as_str());
            }
        }
    }

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
        hash_str(hasher, "authority_scope");
        hash_opt_value(
            hasher,
            Some(&crate::federation::scope_codec::encode_scope_value(
                &grant.authority_scope,
            )?),
        )?;
        hash_opt_value(hasher, grant.scope.as_ref())?;
        hash_opt_value(hasher, grant.budget.as_ref())?;
        hash_bool(hasher, grant.receipt_required);
    }

    // Default grant rows change future authority, so they move the same
    // policy frontier as the other resolved capability rows.
    if !resolution.federation_grant_rows.is_empty() {
        hash_str(hasher, crate::federation::grant_policy::ROWS_KEY);
        hash_len(hasher, resolution.federation_grant_rows.len());
        for row in &resolution.federation_grant_rows {
            hash_opt_value(
                hasher,
                Some(&crate::federation::grant_policy::encode_row(row)?),
            )?;
        }
    }

    hash_bool(hasher, resolution.owner_policy_enabled);
    hash_bool(hasher, resolution.owner_policy_rows_dropped);
    hash_len(hasher, resolution.owner_policy_rows.len());
    for row in &resolution.owner_policy_rows {
        hash_owner_policy_row(hasher, row);
    }

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
        let bound: Vec<_> = source_trust
            .additional_bound_rows
            .iter()
            .filter(|((class, _), _)| *class == source)
            .collect();
        if !bound.is_empty() {
            hash_str(hasher, "additional_actor_bindings");
            hash_len(hasher, bound.len());
            for ((_, actor), row) in bound {
                hash_str(hasher, &actor.to_hex());
                hash_source_trust_row(hasher, Some(*row));
            }
        }
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
    hash_opt_str(hasher, row.human.as_deref());
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

pub(in crate::gate) fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
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

pub(in crate::gate) fn hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_voice_ref_policy(
    hasher: &mut Sha256,
    tag: &str,
    policy: &crate::voice_identity::ref_limits::VoiceRefLimitPolicy,
) {
    hash_str(hasher, tag);
    hash_str(
        hasher,
        policy.precedence.map_or("absent", |mode| mode.as_str()),
    );
    for value in policy.vault.fields() {
        hash_u64(hasher, value);
    }
    hash_len(hasher, policy.holders.len());
    for (holder, limits) in &policy.holders {
        hash_bytes(hasher, holder.as_bytes());
        for value in limits.fields() {
            hash_u64(hasher, value);
        }
    }
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
