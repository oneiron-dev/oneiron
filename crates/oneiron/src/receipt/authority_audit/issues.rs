//! The fold's diagnostics an audit row names, indexed by the entry they
//! name.

use std::collections::{BTreeMap, BTreeSet};

use crate::authority::{AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityOp};

/// The code an audit row carries for an entry this install holds back
/// (FIX 1104): a diagnostic beside `fold_valid`, never a verdict on it.
pub(crate) const AUTHORITY_AUDIT_HELD_BACK_CODE: &str = "held_back";

/// The fold's diagnostics, indexed by what they name.
pub(super) struct FoldIssues {
    by_entry: BTreeMap<AuthorityEntryHash, Vec<&'static str>>,
    conflicted_confirms: BTreeSet<[u8; 32]>,
    memory_floor: bool,
}

impl FoldIssues {
    pub(super) fn of(fold: &AuthorityFold) -> Self {
        let mut issues = Self {
            by_entry: BTreeMap::new(),
            conflicted_confirms: fold.conflicted_critical_write_confirms.clone(),
            memory_floor: false,
        };
        for issue in &fold.issues {
            let (entry, code) = match issue {
                AuthorityFoldIssue::InvalidEntry(entry) => (entry, "invalid_entry"),
                AuthorityFoldIssue::InvalidAncestry(entry) => (entry, "invalid_ancestry"),
                AuthorityFoldIssue::RetiredSigner(entry) => (entry, "retired_signer"),
                AuthorityFoldIssue::UnsettledHandoff(entry) => (entry, "unsettled_handoff"),
                AuthorityFoldIssue::SignerNotInAncestry(entry) => (entry, "signer_not_in_ancestry"),
                AuthorityFoldIssue::NonMonotonicSeq(entry) => (entry, "non_monotonic_seq"),
                AuthorityFoldIssue::StaleRosterApproval(entry) => (entry, "stale_roster_approval"),
                AuthorityFoldIssue::WrongVault(entry) => (entry, "wrong_vault"),
                AuthorityFoldIssue::ConflictingVaultRoot { entry, .. } => {
                    (entry, "conflicting_vault_root")
                }
                AuthorityFoldIssue::MissingAuthorityConsent(entry) => {
                    (entry, "missing_authority_consent")
                }
                AuthorityFoldIssue::MissingQuorum(entry) => (entry, "missing_quorum"),
                AuthorityFoldIssue::FederationLifecycleRejected { entry, .. } => {
                    (entry, "federation_lifecycle_rejected")
                }
                AuthorityFoldIssue::ActorBindingRejected { entry, .. } => {
                    (entry, "actor_binding_rejected")
                }
                AuthorityFoldIssue::CriticalWriteConfirmConflict { confirm_id } => {
                    issues.conflicted_confirms.insert(*confirm_id);
                    continue;
                }
                AuthorityFoldIssue::FoldMemoryFloor { .. } => {
                    issues.memory_floor = true;
                    continue;
                }
            };
            issues.by_entry.entry(*entry).or_default().push(code);
        }
        for entry in &fold.refused_world_edits {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_world_edit");
        }
        for entry in &fold.refused_world_keys {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_world_key");
        }
        for entry in &fold.refused_grant_travel {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_grant_travel");
        }
        for entry in fold.refused_owner_work() {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_owner_work");
        }
        for entry in &fold.conversation_training.refused {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push("refused_conversation_training");
        }
        for entry in fold.held_back_entries() {
            issues
                .by_entry
                .entry(*entry)
                .or_default()
                .push(AUTHORITY_AUDIT_HELD_BACK_CODE);
        }
        issues
    }

    /// The codes of a cold row: the diagnostics naming its entry, and the
    /// memory floor's. A cold row has no op, so no confirm conflict.
    pub(super) fn cold_codes(&self, hash: &AuthorityEntryHash) -> Vec<String> {
        let mut codes: Vec<String> = self
            .by_entry
            .get(hash)
            .into_iter()
            .flatten()
            .map(|code| (*code).to_owned())
            .collect();
        if self.memory_floor {
            codes.push("fold_memory_floor".to_owned());
        }
        codes
    }

    pub(super) fn codes(&self, hash: &AuthorityEntryHash, op: &AuthorityOp) -> Vec<String> {
        let mut codes: Vec<String> = self
            .by_entry
            .get(hash)
            .into_iter()
            .flatten()
            .map(|code| (*code).to_owned())
            .collect();
        if let AuthorityOp::CriticalWriteConfirm(action) = op
            && self.conflicted_confirms.contains(&action.confirm_id)
        {
            codes.push("critical_write_confirm_conflict".to_owned());
        }
        if self.memory_floor {
            codes.push("fold_memory_floor".to_owned());
        }
        codes
    }
}
