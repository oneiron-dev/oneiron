//! Who may attest a portable authority checkpoint (OF-469, checkpoint v2): the
//! eligible roots and the quorum they must reach. The image commits the policy
//! it was built under; a joining device takes the policy from its pairing pin,
//! never from the image it received.
//!
//! Managed mode requires the managed host root. Relay and self-host use
//! owner-root keys: one root while one or two are eligible, and two distinct
//! roots from three on (owner ruling 10-19, CHECKPOINT QUORUM = C; FIX 4936).
//! Workers, agents and capability holders never vote, and several software
//! keys never stand in for a hardware root.
//!
//! An owner selects roots and quorum through a main-log choice carrying his
//! act ([`CheckpointPolicySet`], folded by `checkpoint_choice`). Hosted vaults
//! use their host policy unless the operator explicitly enables the
//! enterprise/advanced opt-out capability (QUORUM-HOST-ROOT=C). This applies
//! to replicated choices too; signed history is not rewritten. Self-host and
//! relay choices are unchanged. An enabled selection drops only the host-voter
//! requirement: eligibility, the multi-root quorum, the configured floor,
//! canonical order and hardware-when-eligible stay. Each refusal names its
//! rule ([`RecordError::CheckpointPolicyRefused`]).

use super::*;
use crate::error::Result;
use crate::{HostingPrivacyPosture, Vault};

#[doc(hidden)]
pub use oneiron_records::authority::checkpoint_policy::{
    CHECKPOINT_CONFIGURED_QUORUM, CHECKPOINT_HARDWARE_WHEN_ELIGIBLE, CHECKPOINT_MULTI_ROOT_QUORUM,
    CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS, CheckpointPosture, CheckpointRoot,
    CheckpointRootPolicy,
};
#[doc(hidden)]
pub(super) use oneiron_records::authority::checkpoint_policy::{policy_refused, selectable_root};

/// The effective policy, including the operator's hosted opt-out capability.
/// Image building, rebuilding and countersign receipts use this same choice.
/// A hosted vault without that capability keeps its default host policy even
/// when its signed history contains an owner's choice from another install.
pub(super) fn checkpoint_root_policy_of(
    fold: &AuthorityFold,
    posture: HostingPrivacyPosture,
    selection_available: bool,
) -> Result<CheckpointRootPolicy> {
    let choice = fold
        .checkpoint_policy
        .selected()
        .filter(|_| posture != HostingPrivacyPosture::Hosted || selection_available);
    match choice {
        Some(choice) => CheckpointRootPolicy::from_choice(
            &fold.roster,
            posture,
            choice,
            CHECKPOINT_CONFIGURED_QUORUM,
        ),
        None => {
            CheckpointRootPolicy::from_roster(&fold.roster, posture, CHECKPOINT_CONFIGURED_QUORUM)
        }
    }
}

impl Vault {
    /// The checkpoint root policy in force in this vault's own fold, read in
    /// `txn`: the owner's choice when one counts, else the posture's.
    pub fn checkpoint_root_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<CheckpointRootPolicy> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        checkpoint_root_policy_of(
            &fold,
            self.privacy_posture(),
            self.checkpoint_policy_selection_available(),
        )
    }

    /// Whether `root` is an eligible root of the policy in force. A policy
    /// the roster cannot fix refuses, naming its rule.
    pub fn checkpoint_root_eligible(&self, root: &AuthorityKey) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .checkpoint_root_policy_in_txn(&txn)?
            .root(root)
            .is_some())
    }
}
