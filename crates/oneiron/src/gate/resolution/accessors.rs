//! Read-only resolved-field accessors plus the frontier-hash entry.

use crate::autoreason_campaign::selection::{SelectionPolicy, SelectionPrecedence};
use sha2::{Digest, Sha256};

use crate::EntityId;

use crate::error::Result;
use crate::gate::hosted_tts_policy::HostedTtsLimits;
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};
use oneiron_docedit::ArchiveLimits;

use super::frontier_hash::hash_policy_frontier_v0;
use super::manifest_types::{
    AttributionLimits, CommOptOutPosture, PolicyManifestDiagnostics, PolicyManifestResolution,
    SheetAnswerPrecedence,
};
use crate::gate::ceiling::{
    PolicyAxes, PolicyCriticality, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicySensitivity,
    PolicySignature,
};
use crate::gate::grants::{PolicyScopedGrant, scoped_read_grant_has_read_effector};

#[cfg_attr(not(test), allow(dead_code))]
impl PolicyManifestResolution {
    /// Fully resolved, trusted install policy. Missing or malformed policy
    /// never becomes a permissive empty rule set.
    pub(crate) fn pack_install_policy(&self) -> Option<&crate::gate::PackInstallPolicy> {
        if self.diagnostics.is_fail_closed() {
            return None;
        }
        self.pack_install_policy.as_ref()
    }

    /// Trusted manifest rows, intersected across packs. Header is not a
    /// content class; without a policy row no cross-class carry is allowed.
    pub(crate) fn connector_class_carry(&self) -> std::collections::BTreeSet<(String, String)> {
        if self.is_fail_closed() {
            return Default::default();
        }
        self.connector_class_carry.clone().unwrap_or_default()
    }

    pub(crate) fn is_single_valued_predicate(&self, predicate: &str) -> bool {
        !self.is_fail_closed() && self.single_valued_predicates.contains(predicate)
    }

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

    /// Resolved restrictive cap, with vault cap and applicable artifact/sheet
    /// rows combined by minimum. An untrusted row can only narrow this cap.
    /// The holder may request a smaller limit, never exceed the vault cap.
    pub(crate) fn sheet_answer_limit(
        &self,
        artifact_ref: &str,
        sheet: &str,
        holder_override: Option<u64>,
    ) -> Option<u64> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        let SheetAnswerPrecedence::NestedNarrowingHolderCappedAtVault =
            self.sheet_answer_precedence?;
        let mut trusted_vault_cap = None::<u64>;
        let mut scoped_cap = u64::MAX;
        for row in &self.sheet_answer_limits {
            match (row.artifact_ref.as_deref(), row.sheet.as_deref()) {
                (None, None) => {
                    trusted_vault_cap = Some(
                        trusted_vault_cap.map_or(row.max_count, |old: u64| old.min(row.max_count)),
                    );
                }
                (Some(artifact), None) if artifact == artifact_ref => {
                    scoped_cap = scoped_cap.min(row.max_count);
                }
                (Some(artifact), Some(name)) if artifact == artifact_ref && name == sheet => {
                    scoped_cap = scoped_cap.min(row.max_count);
                }
                _ => {}
            }
        }
        // Untrusted rows can narrow the trusted vault cap, never replace the
        // shipped fallback when the owner omitted their vault row.
        let vault_cap = trusted_vault_cap.or(self.sheet_answer_default_max_count)?;
        let mut cap = vault_cap.min(scoped_cap);
        for row in &self.untrusted_sheet_answer_limits {
            match (row.artifact_ref.as_deref(), row.sheet.as_deref()) {
                (None, None) => cap = cap.min(row.max_count),
                (Some(artifact), None) if artifact == artifact_ref => cap = cap.min(row.max_count),
                (Some(artifact), Some(name)) if artifact == artifact_ref && name == sheet => {
                    cap = cap.min(row.max_count);
                }
                _ => {}
            }
        }
        if holder_override == Some(0) {
            return None;
        }
        Some(cap.min(holder_override.unwrap_or(u64::MAX)))
    }

    /// Effective correction quota from the resolved manifest, never from a
    /// caller-supplied request. Malformed policy cannot authorize a label.
    pub(crate) fn weave_correction_limit(&self, holder: &str) -> Option<usize> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        self.weave_correction_policy
            .as_ref()
            .map(|policy| policy.limit_for(holder))
    }

    /// Limits are resolved by nested narrowing across trusted manifests.
    /// A malformed loaded manifest never gets to relax admission by omission.
    #[must_use]
    pub(crate) fn attribution_limits(&self) -> Option<&AttributionLimits> {
        (!self.diagnostics.loaded_manifest_forces_fail_closed()).then_some(&self.attribution_limits)
    }

    /// Shipped manifest rows or the same bootstrap default if no ask row
    /// exists; an invalid loaded manifest never silently supplies authority.
    pub(crate) fn ask_operational_policy(&self) -> Option<crate::gate::AskOperationalPolicy> {
        (!self.diagnostics.loaded_manifest_forces_fail_closed())
            .then(|| self.ask_policy.clone().unwrap_or_default())
    }

    /// Resolve the required vault ceiling and every matching actor/scope row.
    pub(crate) fn retry_budget_for(
        &self,
        actor: crate::EntityId,
        scope: Option<&crate::llm::Scope>,
    ) -> crate::Result<crate::gate::retry_source_policy::ResolvedRetryBudget> {
        crate::gate::retry_source_policy::resolve(&self.retry_source_policy, actor, scope)
    }

    /// Only trusted policy rows select the room working set. A malformed
    /// loaded manifest refuses reads rather than silently restoring defaults.
    pub(crate) fn room_thread_settings(
        &self,
        actor: crate::EntityId,
    ) -> Result<crate::gate::RoomThreadSettings> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return Err(crate::Error::InvalidConfig(
                "invalid room thread policy".into(),
            ));
        }
        Ok(self
            .room_thread
            .clone()
            .unwrap_or_default()
            .effective(actor))
    }

    /// One snapshot supplies the same carry-forward floor to typed, raw and Gate doors.
    #[must_use]
    pub(crate) fn carry_forward_floor(
        &self,
        kind: crate::write_envelope::carry_forward::CarryForwardKind,
        actor: Option<crate::EntityId>,
    ) -> f32 {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return 1.0;
        }
        self.carry_forward_confidence.floor(kind, actor)
    }

    #[must_use]
    pub(crate) fn goal_limits(&self) -> crate::workspace_roster::GoalLimits {
        self.goal_limits.unwrap_or_default()
    }

    #[must_use]
    pub(crate) fn judge_calibration_policy(
        &self,
    ) -> Option<crate::skill_optimize::policy::JudgeCalibrationPolicy> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            None
        } else {
            Some(self.judge_calibration.unwrap_or_default())
        }
    }

    #[must_use]
    pub(in crate::gate) fn linear_mirror(&self) -> crate::gate::LinearMirrorPolicy {
        self.linear_mirror.unwrap_or_default()
    }
    pub(in crate::gate) fn linear_sync(&self) -> crate::gate::LinearSyncBudget {
        self.linear_sync.unwrap_or_default()
    }
    pub(in crate::gate) fn wave_handoff(&self) -> crate::gate::WaveHandoffPolicy {
        self.wave_handoff.unwrap_or_default()
    }

    pub(crate) fn proposal_check_threshold(&self) -> u64 {
        self.proposal_check_threshold
            .unwrap_or(crate::gate::proposal_observation::DEFAULT_PROPOSAL_CHECK_THRESHOLD)
    }

    /// Trusted vault policy narrowed by the holder's own limits and shipped defaults.
    pub(crate) fn voice_ref_limits(
        &self,
        owner: &crate::EntityId,
    ) -> Option<crate::voice_identity::ref_limits::VoiceRefLimits> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            None
        } else {
            self.voice_ref_defaults
                .as_ref()
                .and_then(|defaults| self.voice_ref_limits.effective(defaults, owner))
        }
    }

    #[must_use]
    pub(crate) fn on_budget_exhausted(&self) -> BudgetExhaustionPolicy {
        self.on_budget_exhausted.unwrap_or_default()
    }

    /// The resolved opt-out posture. No pack carrying the key resolves to the
    /// restrictive default, `Escalate`.
    #[must_use]
    pub(in crate::gate) fn comm_opt_out_posture(&self) -> CommOptOutPosture {
        self.comm_opt_out_posture.unwrap_or_default()
    }

    /// The manifest's opaque auto-checker ref (ONE-1296), or `None` when no
    /// manifest names one.
    ///
    /// Presence is the whole meaning: it is what arms the write door's consult.
    /// The engine never interprets the string, and the checker itself is
    /// supplied per-write rather than resolved from here.
    #[must_use]
    pub(crate) fn auto_checker(&self) -> Option<&str> {
        self.auto_checker.as_deref()
    }

    /// The quality floor lives in a trusted, seeded POLICY_MANIFEST row.
    /// Holder overrides are nested restrict-only rows capped at the vault.
    #[must_use]
    pub(crate) fn teacher_probe_policy(
        &self,
        holder_ref: Option<&str>,
    ) -> Option<crate::llm::manifest::TeacherProbePolicy> {
        if self.is_fail_closed() || !self.teacher_probe_trusted {
            return None;
        }
        let vault_min = self.teacher_probe_vault_min?;
        let effective = holder_ref
            .and_then(|holder| self.teacher_probe_holders.get(holder).copied())
            .unwrap_or(vault_min)
            .max(vault_min);
        crate::llm::manifest::TeacherProbePolicy::resolved(vault_min, effective, holder_ref).ok()
    }

    /// Conversion UI/notification choices from trusted, resolved manifest
    /// rows. A malformed policy cannot silently become shipped defaults.
    pub(crate) fn booking_conversion_policy(
        &self,
        holder_ref: Option<&str>,
    ) -> Option<crate::booking::BookingConversionPolicy> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        crate::booking::resolve_booking_conversion_rows(&self.booking_conversion_rows, holder_ref)
            .ok()
    }

    /// Compose trusted vault, campaign and holder rows in the shared manifest
    /// resolver. The vault row selects precedence; equal-scope rows intersect
    /// regardless of scan order, and every holder result remains vault-capped.
    /// An absent vault row or malformed manifest supplies no search permission.
    #[must_use]
    pub(crate) fn experiment_selection_policy(
        &self,
        campaign_id: &str,
        holder_id: Option<&str>,
    ) -> Option<SelectionPolicy> {
        if self.is_fail_closed() {
            return None;
        }
        let mut vault = None;
        let mut precedence = None;
        let mut campaign = None;
        let mut holder = None;
        for row in &self.experiment_selection {
            match (
                row.scope.campaign_id.as_deref(),
                row.scope.holder_id.as_deref(),
            ) {
                (None, None) => {
                    if precedence.is_some_and(|old| old != row.precedence) {
                        return None;
                    }
                    precedence = Some(row.precedence);
                    vault = Some(
                        vault.map_or(row.policy, |old: SelectionPolicy| old.narrow(row.policy)),
                    );
                }
                (Some(id), None) if id == campaign_id => {
                    campaign = Some(
                        campaign.map_or(row.policy, |old: SelectionPolicy| old.narrow(row.policy)),
                    );
                }
                (Some(id), Some(actor)) if id == campaign_id && Some(actor) == holder_id => {
                    holder = Some(
                        holder.map_or(row.policy, |old: SelectionPolicy| old.narrow(row.policy)),
                    );
                }
                _ => {}
            }
        }
        let vault = vault?;
        match (holder, precedence.unwrap_or_default()) {
            (Some(holder), SelectionPrecedence::HolderUnderVault) => Some(vault.narrow(holder)),
            _ => Some(match (campaign, holder) {
                (Some(campaign), Some(holder)) => vault.narrow(campaign).narrow(holder),
                (Some(campaign), None) => vault.narrow(campaign),
                (None, Some(holder)) => vault.narrow(holder),
                (None, None) => vault,
            }),
        }
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

    /// Retention may erase published telemetry only when the loaded manifest
    /// is usable. An absent manifest keeps the shipped bootstrap posture;
    /// malformed or unsupported loaded policy grants no deletion authority.
    #[must_use]
    pub(crate) fn retrieval_retention_policy(
        &self,
    ) -> Option<crate::gate::retrieval_retention::RetrievalRetentionPolicy> {
        (!self.diagnostics.loaded_manifest_forces_fail_closed()).then_some(self.retrieval_retention)
    }

    /// The trusted, nested-narrow voice limits. A malformed or absent policy
    /// never falls back to compiled operational allowances.
    pub(crate) fn voice_serving_limits(
        &self,
        holder: Option<crate::EntityId>,
    ) -> Result<crate::gate::VoiceServingLimits> {
        if self.diagnostics.is_fail_closed() {
            return Err(crate::error::Error::InvalidConfig(
                "voice serving policy unavailable".into(),
            ));
        }
        crate::gate::voice_serving::resolve(&self.voice_serving, holder)
    }

    /// Effective trusted per-vault limits. Malformed loaded policy refuses
    /// edits; a loaded policy missing the row refuses. Only an unseeded
    /// bootstrap vault uses the same shipped default as the persisted row.
    #[must_use]
    pub(crate) fn pptx_comment_limits(
        &self,
    ) -> Option<crate::edit_roundtrip::pptx::PptxOperationalLimits> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            None
        } else if self.diagnostics.manifest_count == 0 {
            // Unseeded bootstrap/test vaults have no row to read yet; real
            // opens persist the same shipped default in the trusted manifest.
            Some(crate::edit_roundtrip::pptx::PptxOperationalLimits::default())
        } else {
            self.pptx_comment_limits
        }
    }

    /// Restrictive DOCX workload fold: shipped/default vault upper bound,
    /// every trusted manifest's vault row, and the selected holder rows. A
    /// malformed loaded manifest yields no usable budget (never a fallback).
    pub(crate) fn docx_archive_limits(&self, holder: Option<EntityId>) -> Option<ArchiveLimits> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        let mut limits = ArchiveLimits::DEFAULT;
        for policy in &self.docx_archive_limits {
            limits = limits.narrow(policy.for_holder(holder));
        }
        Some(limits)
    }
    pub(crate) fn hosted_tts_limits(
        &self,
        provider: &str,
        holder: EntityId,
    ) -> Option<HostedTtsLimits> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return None;
        }
        self.hosted_tts.limits(provider, holder)
    }
    /// Effective artifact-review limits from trusted manifest rows; a holder
    /// may only narrow the vault setting, never widen it.
    pub(crate) fn slide_review_limits(
        &self,
        holder: crate::EntityId,
    ) -> Option<crate::llm::decision::SlideReviewLimits> {
        (!self.diagnostics.loaded_manifest_forces_fail_closed())
            .then(|| self.slide_review_policy.resolve(holder))
    }

    pub(crate) fn slide_review_route(
        &self,
        holder: crate::EntityId,
    ) -> Option<crate::llm::decision::SlideReviewRoute> {
        (!self.diagnostics.loaded_manifest_forces_fail_closed())
            .then(|| self.slide_review_policy.resolve_route(holder))
    }
    /// Only a valid loaded policy resolves document resource ceilings.
    /// An absent row uses the shipped manifest's baseline, not organ literals.
    pub(in crate::gate) fn docedit_resource_policy(
        &self,
    ) -> Option<crate::gate::docedit_resource::DoceditResourcePolicy> {
        if self.diagnostics.is_fail_closed() {
            return None;
        }
        Some(
            self.docedit_resource_policy
                .unwrap_or_else(crate::gate::docedit_resource::DoceditResourcePolicy::shipped),
        )
    }

    /// Rendering pins follow declared critical classes, not the fail-closed
    /// write fallback for unknown predicates. Only trusted folded policy can pin.
    #[must_use]
    pub(crate) fn pins_predicate(&self, predicate: &str) -> bool {
        !self.is_fail_closed()
            && self.axes_for_predicate(predicate).criticality == Some(PolicyCriticality::Critical)
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
    pub(in crate::gate) fn sensitivity_for_predicate(&self, predicate: &str) -> PolicySensitivity {
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

    /// Declared-source-only evaluation for doors without an envelope.
    // The declared-only form's one production caller is the federated
    // admission path, which exists only under `sync`.
    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut resolved = PolicyAxes::default();
        for pack in &self.packs {
            resolved = resolved.restrict(pack.axes_for_predicate(predicate));
        }
        resolved
    }
}
