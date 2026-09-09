//! Read-only resolved-field accessors plus the frontier-hash entry.

use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};

use super::frontier_hash::hash_policy_frontier_v0;
use super::manifest_types::{
    CommOptOutPosture, PolicyManifestDiagnostics, PolicyManifestResolution,
};
use crate::gate::ceiling::{
    PolicyAxes, PolicyCriticality, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicySensitivity,
    PolicySignature,
};
use crate::gate::grants::{PolicyScopedGrant, scoped_read_grant_has_read_effector};

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
    pub(in crate::gate) fn criticality_for_predicate(&self, predicate: &str) -> PolicyCriticality {
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
