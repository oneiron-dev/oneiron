use std::collections::BTreeSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::{ClaimBody, ClaimSource, claim_sensitivity_band};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard, BudgetPolicySelector, BudgetPolicyTable};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::ceiling::{
    ActorCeiling, DelegationFoldCache, DelegationGrantRecord, PolicyApprovalCeiling, PolicyAxes,
    PolicyCriticality, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack, PolicySensitivity,
    PolicySignature, SourceTrustCeiling, SourceTrustRow, check_source_trust, fold_delegated_grants,
};
use super::decision::{GateDecision, GateReasonCode, external_effect_receipt_reasons};
use super::decode::decode_policy_manifest;
use super::effect::is_mcp_effect_channel;
use super::grants::{
    PolicyScopedGrant, external_effect_grant_matches, scoped_read_grant_has_read_effector,
};
use super::input::{GateContentKind, GateEvaluatorInput, consent_ladder_reasons};

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

    pub(crate) fn loaded_manifest_forces_fail_closed(self) -> bool {
        self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    pub(super) diagnostics: PolicyManifestDiagnostics,
    packs: Vec<PolicyPack>,
    actor_ceilings: Vec<ActorCeiling>,
    pub(super) delegation_fold: DelegationFoldCache,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    owner_policy_rows_dropped: bool,
    owner_policy_enabled: bool,
    owner_policy_document: Option<String>,
    owner_policy_output_contract: Option<String>,
    owner_policy_patterns: Vec<PolicyOwnerPatternRow>,
    owner_policy_patterns_dropped: bool,
    signatures: Vec<PolicySignature>,
    on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    budget_policy: BudgetPolicyTable,
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
    pub(crate) fn enforces_write_gate(&self) -> bool {
        // A completely absent manifest preserves the existing bootstrap
        // behavior; any loaded malformed/unsupported manifest fails closed.
        self.diagnostics.manifest_count > 0 || self.diagnostics.loaded_manifest_forces_fail_closed()
    }

    #[must_use]
    pub(crate) fn on_budget_exhausted(&self) -> BudgetExhaustionPolicy {
        self.on_budget_exhausted.unwrap_or_default()
    }

    /// The resolved `budget_policy` rows, fail-closed: a loaded manifest that
    /// forces fail-closed (malformed, unsupported schema, engine-version
    /// floor, unknown axis, row-count overflow) exposes no usable table, and
    /// the caller must refuse rather than substitute an empty table. An
    /// absent manifest keeps the bootstrap posture and exposes the empty
    /// table, which is exactly the single-pool meter.
    #[must_use]
    pub(crate) fn budget_policy(&self) -> Option<&BudgetPolicyTable> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            None
        } else {
            Some(&self.budget_policy)
        }
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

    pub(crate) fn has_matching_actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> bool {
        self.actor_ceilings.iter().any(|row| {
            row.actor_class == actor_class
                && match (&row.actor_ref, actor_ref) {
                    (None, _) => true,
                    (Some(row_ref), Some(request_ref)) => row_ref == request_ref,
                    _ => false,
                }
        })
    }

    /// Effective `actor_ceilings` value from rows bound to THIS actor ref.
    ///
    /// Class-wide rows are deliberately excluded. ONE-1686 uses this narrower
    /// fold for transcript recording: class-wide ceilings govern claim
    /// admission, while only a row that names one writer may clamp that
    /// writer's ordinary transcript rows or authorize its elevated `system`
    /// authorship. Multiple exact rows still combine by the ordinary
    /// most-restrictive rule.
    pub(crate) fn actor_bound_ceiling(
        &self,
        actor_class: &str,
        actor_ref: &str,
    ) -> Option<PolicyApprovalCeiling> {
        self.actor_ceilings
            .iter()
            .filter(|row| {
                row.actor_class == actor_class && row.actor_ref.as_deref() == Some(actor_ref)
            })
            .fold(None, |ceiling, row| {
                Some(
                    ceiling.map_or(row.ceiling, |existing: PolicyApprovalCeiling| {
                        existing.restrict(row.ceiling)
                    }),
                )
            })
    }

    fn actor_ceiling_allows_auto_for_content(&self, input: &GateEvaluatorInput) -> bool {
        // ONE-1686 (RT-04): witness MESSAGE ingress is transcript RECORDING,
        // not claim admission. It has no proposed lane — a refused row is a
        // turn that never happened — so "this vault wrote no ceiling row for
        // the writer" must not silently end its ability to record ordinary
        // conversations. An `actor_ceilings` row that NAMES the writer is the
        // owner's lever and clamps here; no row keeps ordinary recording
        // available. Authority for the elevated `system` bucket is a separate,
        // fail-closed question the witness door's floor answers
        // (`gate::witness_message`). The AGENT_DEF self-limit is deliberately
        // not read here: a `Proposed`
        // definition means an agent's CLAIMS need review, not that it may not
        // be recorded speaking.
        if input.content_kind == GateContentKind::WitnessMessage {
            let actor_class = input.actor.actor_class.trim();
            return input.actor.actor_ref.as_deref().is_none_or(|actor_ref| {
                self.actor_bound_ceiling(actor_class, actor_ref)
                    .is_none_or(|ceiling| ceiling == PolicyApprovalCeiling::Auto)
            });
        }

        // A payload-aware scoped MCP grant is the one external-effect path
        // that dissolves the Proposed fork: store-backed matching already
        // proved server, tool, endpoint, and data-class scope. Blind grants
        // and every non-effect write retain the authored clamp below.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
            return input.content_kind == GateContentKind::ExternalEffect
                && input.external_effect.as_ref().is_some_and(|effect| {
                    effect.scoped_mcp_call.is_some() && effect.scoped_mcp_grant_authorized
                });
        }
        let actor_class = input.actor.actor_class.trim();
        if self.actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            == PolicyApprovalCeiling::Auto
        {
            return true;
        }

        // The edge-provenance no-matching-row auto exception is suppressed
        // for ANY definition-bound actor (B2 resolution 2026-07-10): an Auto
        // definition ceiling means "does not self-limit", not "inherits the
        // no-row exception" — no row → Proposed holds as written for
        // definition-bound actors.
        input.content_kind == GateContentKind::EdgeProvenanceClaim
            && matches!(actor_class, "agent" | "system")
            && !self.has_matching_actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            && input.agent_definition_ceiling.is_none()
    }

    fn dreamer_auto_grant_requires_manifest_signature(&self, input: &GateEvaluatorInput) -> bool {
        input.content_kind == GateContentKind::Claim
            && input.actor.actor_class.trim() == "agent"
            && input.provenance.dreamer_run_id.is_some()
            && self.actor_ceiling(
                input.actor.actor_class.trim(),
                input.actor.actor_ref.as_deref(),
            ) == PolicyApprovalCeiling::Auto
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

    /// Whether the vault owner turned their own policy plane on. Default OFF:
    /// a vault that has not opted in classifies nothing and calls no safeguard
    /// model, so the engine ships with no opinion about the owner's content.
    #[must_use]
    pub(crate) fn owner_policy_enabled(&self) -> bool {
        !self.diagnostics.loaded_manifest_forces_fail_closed() && self.owner_policy_enabled
    }

    #[must_use]
    pub(crate) fn active_owner_policy_rows(
        &self,
        world_ref: Option<&str>,
    ) -> Vec<&PolicyOwnerPolicyRow> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() || self.owner_policy_rows_dropped {
            return Vec::new();
        }

        let scoped_refs: Vec<&str> = match world_ref {
            Some(world_ref) => self
                .owner_policy_rows
                .iter()
                .filter(|row| row.active && row.world_ref.as_deref() == Some(world_ref))
                .map(|row| row.row_ref.as_str())
                .collect(),
            None => Vec::new(),
        };

        self.owner_policy_rows
            .iter()
            .filter(|row| row.active)
            .filter(|row| match (world_ref, row.world_ref.as_deref()) {
                (Some(world_ref), Some(row_world)) => row_world == world_ref,
                (Some(_), None) => !scoped_refs.contains(&row.row_ref.as_str()),
                (None, None) => true,
                (None, Some(_)) => false,
            })
            .collect()
    }

    #[must_use]
    pub(crate) fn owner_policy_rows_dropped(&self) -> bool {
        self.owner_policy_rows_dropped
    }

    /// The owner's policy document, or `None` when they wrote none. A fail-
    /// closed manifest reports `None`: an unreadable manifest is not evidence
    /// that a document exists.
    #[must_use]
    pub(crate) fn owner_policy_document(&self) -> Option<&str> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        self.owner_policy_document.as_deref()
    }

    /// The answer shape the owner's document asked for, as the manifest spelled
    /// it. The policy plane parses it; `gate` does not know the vocabulary.
    #[must_use]
    pub(crate) fn owner_policy_output_contract(&self) -> Option<&str> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        self.owner_policy_output_contract.as_deref()
    }

    /// The owner's pattern rules, raw. Empty on a fail-closed or dropped
    /// manifest — a rule the engine cannot read must not be treated as a rule
    /// that fired.
    #[must_use]
    pub(crate) fn owner_policy_patterns(&self) -> &[PolicyOwnerPatternRow] {
        if self.diagnostics.loaded_manifest_forces_fail_closed()
            || self.owner_policy_patterns_dropped
        {
            return &[];
        }
        &self.owner_policy_patterns
    }

    #[must_use]
    pub(crate) fn owner_policy_patterns_dropped(&self) -> bool {
        self.owner_policy_patterns_dropped
    }

    /// Every owner row ref the manifest carries, active or not, scoped or not.
    ///
    /// This is the vocabulary a pattern rule's `category` is validated against.
    /// It deliberately ignores `active` and `world_ref`: a rule naming a row
    /// that is merely scoped out of THIS request is a valid rule that cannot
    /// act right now, and validating against the active set would turn a
    /// world-scoped manifest into a configuration error.
    #[must_use]
    pub(crate) fn owner_policy_row_refs(&self) -> Vec<&str> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() || self.owner_policy_rows_dropped {
            return Vec::new();
        }
        self.owner_policy_rows
            .iter()
            .map(|row| row.row_ref.as_str())
            .collect()
    }

    #[must_use]
    pub(crate) fn has_scoped_read_grants(&self) -> bool {
        self.scoped_grants()
            .iter()
            .any(scoped_read_grant_has_read_effector)
    }

    #[must_use]
    pub(crate) fn signatures(&self) -> &[PolicySignature] {
        &self.signatures
    }

    pub(crate) fn read_frontier_hash(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_policy_frontier_v0(&mut hasher, self)?;
        Ok(hasher.finalize().into())
    }

    #[must_use]
    pub(crate) fn evaluate_gate(&self, input: &GateEvaluatorInput) -> GateDecision {
        let actor_class = input.actor.actor_class.trim();
        if actor_class.is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorClass);
        }
        if input.provenance.actor_entity_ref.is_none() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorProvenance);
        }
        if input.policy_manifest_version.trim().is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingPolicyManifestVersion);
        }
        let external_effect = if input.content_kind == GateContentKind::ExternalEffect {
            input.external_effect.as_ref()
        } else {
            None
        };
        if let Some(effect) = external_effect
            && effect.counterparty_opted_out
        {
            return GateDecision::deny(GateReasonCode::DenyCounterpartyOptOut)
                .with_receipt_reasons(external_effect_receipt_reasons(effect));
        }
        if self.is_fail_closed() {
            if input.content_kind == GateContentKind::ExternalEffect {
                let decision =
                    GateDecision::pending(vec![GateReasonCode::PendingExternalEffectAuthority]);
                return if let Some(effect) = external_effect {
                    decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
                } else {
                    decision
                };
            }
            return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
        }

        let mut pending = Vec::new();
        let mut actor_ceiling_allows_auto = self.actor_ceiling_allows_auto_for_content(input);
        if let Some(grant_ref) = input.actor.delegation_grant_ref.as_deref() {
            let bound = self
                .delegation_fold
                .records
                .get(grant_ref)
                .and_then(|r| match r {
                    DelegationGrantRecord::Grant {
                        actor_class,
                        actor_ref,
                        ..
                    } => Some((actor_class, actor_ref)),
                    _ => None,
                });
            let matches = bound.is_some_and(|(class, reference)| {
                class.trim() == actor_class
                    && reference.as_deref() == input.actor.actor_ref.as_deref()
            });
            actor_ceiling_allows_auto = actor_ceiling_allows_auto
                && matches
                && self.delegation_fold.effective_ceiling(grant_ref)
                    == Some(PolicyApprovalCeiling::Auto);
        }
        if !actor_ceiling_allows_auto {
            pending.push(GateReasonCode::PendingActorCeiling);
        }

        /* actor ceiling is already restrictive; delegated authority can only narrow it. */
        if actor_ceiling_allows_auto
            && self.dreamer_auto_grant_requires_manifest_signature(input)
            && self.signatures.is_empty()
        {
            pending.push(GateReasonCode::PendingPolicyManifestAuthority);
        }

        if !self.source_trust_allows_auto(
            input.source,
            input.sensitivity_band,
            input.actor.actor_ref.as_deref(),
        ) {
            pending.push(GateReasonCode::PendingSourceTrust);
        }

        // DEC-0006 write-side residual: `Critical` is a composed-effect SIGNAL,
        // not an unconditional gate. It contributes to the consent ladder
        // below (via `ConsentGateContext`), and the closed catastrophe set is
        // the only always-gate (invariant 7). The legacy unconditional floor
        // survives only where no consent context was composed, so a caller
        // that has not yet been moved onto the DEC-0006 path keeps its
        // pre-existing behaviour rather than silently losing a gate.
        if input.criticality == PolicyCriticality::Critical && input.consent.is_none() {
            pending.push(GateReasonCode::PendingCriticalityFloor);
        }

        pending.extend(consent_ladder_reasons(input.consent.as_ref()));

        match input.content_kind {
            // The witness door's own floor (`gate::witness_message`) carries the
            // envelope-shaped part of this content kind's verdict; what the
            // evaluator contributes is the actor/provenance floor, the
            // fail-closed manifest checks, and the ceiling clamp above.
            GateContentKind::Claim
            | GateContentKind::EdgeProvenanceClaim
            | GateContentKind::WitnessMessage => {}
            GateContentKind::PolicyManifest => {
                pending.push(GateReasonCode::PendingPolicyManifestAuthority);
            }
            GateContentKind::ExternalEffect => {
                if !self.external_effect_allows_auto(input) {
                    pending.push(GateReasonCode::PendingExternalEffectAuthority);
                }
            }
        }

        let decision = if pending.is_empty() {
            GateDecision::allow()
        } else {
            GateDecision::pending(pending)
        };

        if let Some(effect) = external_effect {
            decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
        } else {
            decision
        }
    }

    /// `actor_ref` selects which source-trust rows answer this write; see
    /// [`check_source_trust`], whose row selection this mirrors exactly.
    pub(super) fn source_trust_allows_auto(
        &self,
        source: Option<ClaimSource>,
        sensitivity: Option<u8>,
        actor_ref: Option<&str>,
    ) -> bool {
        let Some(source) = source else {
            return true;
        };

        if self.source_trust.malformed_manifest_seen {
            return false;
        }

        let Some(sensitivity) = sensitivity else {
            return false;
        };

        // An actor-bound row is invisible to every other actor, so the source
        // reads as carrying no row at all and keeps its default posture.
        let row = match self.source_trust.row(source) {
            Some(row) if row.binds_actor(actor_ref) => row,
            _ => return !source.requires_explicit_auto_permit(),
        };

        let Some(max_auto_sensitivity) = row.max_auto_sensitivity else {
            return false;
        };

        sensitivity <= max_auto_sensitivity
            && (!source.requires_explicit_auto_permit() || (row.receipted && row.warned))
    }

    fn external_effect_allows_auto(&self, input: &GateEvaluatorInput) -> bool {
        let Some(effect) = input.external_effect.as_ref() else {
            return false;
        };
        if effect.verb.trim().is_empty() || effect.channel.trim().is_empty() {
            return false;
        }
        // Payload-aware scoped grants are the only safe MCP auto path. The
        // boolean is set only by the store-backed four-axis match below; a
        // caller-supplied standing-grant reference has no authority here.
        if effect.scoped_mcp_call.is_some() || is_mcp_effect_channel(&effect.channel) {
            return effect.scoped_mcp_grant_authorized;
        }
        if !effect.has_permission {
            return false;
        }

        // Blind/non-scoped grants keep the Proposed-ceiling restriction. A
        // scoped MCP grant reaches the return above only after all axes pass.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
            return false;
        }
        if effect.standing_grant_ref.is_some() {
            return true;
        }
        if !effect.has_opted_in {
            return false;
        }

        self.scoped_grants().iter().any(|grant| {
            grant.budget.is_none() && external_effect_grant_matches(grant, &input.actor, effect)
        })
    }

    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut resolved = PolicyAxes::default();
        for pack in &self.packs {
            resolved = resolved.restrict(pack.axes_for_predicate(predicate));
        }
        resolved
    }
}

fn hash_policy_frontier_v0(
    hasher: &mut Sha256,
    resolution: &PolicyManifestResolution,
) -> Result<()> {
    hash_bytes(hasher, b"oneiron.gate.policy_frontier.v0");
    hash_diagnostics(hasher, resolution.diagnostics);
    hash_source_trust(hasher, &resolution.source_trust);
    hash_budget_exhaustion_policy(hasher, resolution.on_budget_exhausted());
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

/// Folds a once-per-vault owner string across manifests. A second manifest
/// naming the same field differently is a malformed policy state, not a
/// precedence question.
fn merge_single_owner_string(
    resolved: &mut Option<String>,
    decoded: Option<String>,
    malformed: &mut bool,
) {
    let Some(decoded) = decoded else {
        return;
    };
    match resolved {
        None => *resolved = Some(decoded),
        Some(existing) if *existing == decoded => {}
        Some(_) => *malformed = true,
    }
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

pub(super) fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
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

pub(super) fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

pub(super) fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

pub(super) fn hash_bool(hasher: &mut Sha256, value: bool) {
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

pub(crate) fn resolve_policy_manifest(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();
    let mut delegated_rows: Vec<DelegationGrantRecord> = Vec::new();

    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_POLICY_MANIFEST) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
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
                resolution.diagnostics.malformed_manifest_seen |=
                    decoded.source_trust.malformed_manifest_seen;
                resolution.diagnostics.unsupported_schema_seen |= decoded.unsupported_schema;
                resolution.diagnostics.engine_version_floor_seen |= decoded.engine_version_floor;
                resolution.diagnostics.unknown_axis_seen |= decoded.unknown_axis_seen;
                resolution.source_trust.merge(decoded.source_trust);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                delegated_rows.extend(decoded.delegated_grants);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                resolution
                    .owner_policy_rows
                    .extend(decoded.owner_policy_rows);
                resolution.owner_policy_rows_dropped |= decoded.owner_policy_rows_dropped;
                resolution.owner_policy_enabled |= decoded.owner_policy_enabled;
                resolution
                    .owner_policy_patterns
                    .extend(decoded.owner_policy_patterns);
                resolution.owner_policy_patterns_dropped |= decoded.owner_policy_patterns_dropped;
                // One document per plane. Two manifests each naming one is an
                // ambiguity nothing downstream could resolve, so it drops the
                // owner plane's model classification rather than picking a
                // winner.
                merge_single_owner_string(
                    &mut resolution.owner_policy_document,
                    decoded.owner_policy_document,
                    &mut resolution.diagnostics.malformed_manifest_seen,
                );
                merge_single_owner_string(
                    &mut resolution.owner_policy_output_contract,
                    decoded.owner_policy_output_contract,
                    &mut resolution.diagnostics.malformed_manifest_seen,
                );
                resolution.signatures.extend(decoded.signatures);
                if let Some(on_budget_exhausted) = decoded.on_budget_exhausted {
                    match resolution.on_budget_exhausted {
                        None => resolution.on_budget_exhausted = Some(on_budget_exhausted),
                        Some(existing) if existing == on_budget_exhausted => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                // Deterministic resolved order: type-index manifest scan
                // order, then row order inside each manifest. Row indices in
                // ladder events index this concatenation.
                resolution.budget_policy.extend_rows(decoded.budget_policy);
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    // Duplicate owner rows are refused per manifest by
    // `parse_owner_policy_rows`, but the RESOLVED table is the concatenation
    // of every manifest's rows and `active_owner_policy_rows` first-matches
    // over that concatenation. Two manifests naming the same `(row_ref,
    // world_ref)` pair once each are individually well formed and still shadow
    // one another here — the same rule that can never fire, however strict its
    // action, only assembled across entities instead of inside one. So the
    // question is asked again of the resolved set, and answered the same way:
    // drop the rows rather than let one silently swallow the other.
    if has_duplicate_owner_policy_row(&resolution.owner_policy_rows) {
        resolution.owner_policy_rows.clear();
        resolution.owner_policy_rows_dropped = true;
    }

    // A resolved table must stay addressable by a u16 row index: up to 65,536
    // rows (indices 0..=65535) are valid; the 65,537th row marks the whole
    // resolution malformed, fail-closing the write gate exactly like any
    // malformed manifest and refusing the budget-policy accessor. Never wrap
    // or silently truncate a row index.
    if resolution.budget_policy.rows().len() > usize::from(u16::MAX) + 1 {
        resolution.diagnostics.malformed_manifest_seen = true;
    }

    match fold_delegated_grants(&delegated_rows) {
        Some(fold) => resolution.delegation_fold = fold,
        None => {
            resolution.diagnostics.malformed_manifest_seen = true;
            resolution.delegation_fold = DelegationFoldCache::default();
        }
    }

    if resolution.diagnostics.loaded_manifest_forces_fail_closed() {
        resolution.source_trust.fail_closed();
    }

    Ok(resolution)
}

/// Whether any two rows that could be in force TOGETHER claim the same
/// `(row_ref, world_ref)` pair.
///
/// The PAIR, not the ref alone: one ref written under two worlds is the
/// scoped-override shape `active_owner_policy_rows` exists to resolve, and only
/// rows that would land in the same rubric together can shadow each other.
/// Same key as the per-manifest check in `parse_owner_policy_rows`.
///
/// And only ACTIVE rows, for exactly the reason the sentence above gives.
/// `active_owner_policy_rows` filters on `row.active` before it resolves
/// anything, so a disabled row is never a candidate and cannot shadow
/// anything. Counting one made a historical row a landmine: pairing it with
/// the live row that replaced it dropped the WHOLE resolved table and left an
/// enabled owner plane refusing to classify — a fail-closed answer to a
/// question that was never ambiguous.
fn has_duplicate_owner_policy_row(rows: &[PolicyOwnerPolicyRow]) -> bool {
    let mut seen = BTreeSet::new();
    rows.iter()
        .filter(|row| row.active)
        .any(|row| !seen.insert((row.row_ref.as_str(), row.world_ref.as_deref())))
}

impl Vault {
    /// Builds the ONE policy-aware LLM budget meter for one wake pass: the
    /// same `BudgetGuard`, bound at construction to the engine-stamped actor
    /// and to the live manifest's resolved `budget_policy` table.
    ///
    /// The factory resolves the manifest itself and is fail-closed: when the
    /// loaded resolution forces fail-closed (malformed manifest, unsupported
    /// schema version, engine-version floor, unknown axis, row-count
    /// overflow) it refuses with [`Error::InvalidConfig`] and never
    /// substitutes an empty or fabricated table. Production callers keep
    /// admitting with `guard.admit_for_request(&request)` exactly as before.
    pub fn policy_budget_guard(
        &self,
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
    ) -> Result<BudgetGuard> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let table = resolution.budget_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "policy manifest resolution is fail-closed; refusing to build a policy budget guard"
                    .to_owned(),
            )
        })?;
        Ok(BudgetGuard::with_policy_table(
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            actor,
            table,
        ))
    }
}

/// `actor_ref` is the hex entity ref of the actor presenting this write, or
/// `None` for an unattributed one. Actor-bound source-trust rows answer only
/// the actor they name, so an unattributed write never rides one.
pub(super) fn check_claim_source_trust(
    body: &ClaimBody,
    actor_ref: Option<&str>,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    check_source_trust(
        body.source,
        body.approval,
        claim_sensitivity_band(body),
        actor_ref,
        &policy.source_trust,
    )
}

pub(super) fn type_index_entity_id(key: &[u8], entity_type: u8) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != entity_type {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}
