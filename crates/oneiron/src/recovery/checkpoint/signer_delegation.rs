//! The mode-root route a restore's key trusts beside its pins (OF-570 (e),
//! FIX 968).
//!
//! A key trusts the signers it pins or its device holds. Given its vault's
//! external mode-root policy and the delegations its roots signed
//! ([`crate::authority::BackupSignerDelegation`]), it also trusts each
//! signer one of them delegates: the commitment's check (`commitment`) and
//! a cold managed restore's source check (`admission::source`) accept a
//! signer either way, then verify both of its signatures the one shared way.
//! The route only adds: a policy or a delegation that does not verify adds
//! no signer and is warned, and no pinned signer is dropped. Only a host's
//! authenticated wake or migrate of a hosted vault hands one; a historical
//! restore keeps its pins alone.

use oneiron_crypto::backup::CheckpointSigner;

use super::CheckpointKey;
use crate::authority::{BackupModeRootPolicy, BackupSignerDelegation};

/// The signers a key trusts through its vault's mode roots, and the digest
/// of the policy they came from.
pub(super) struct DelegatedSigners {
    pub(super) policy_digest: [u8; 32],
    pub(super) signers: Vec<CheckpointSigner>,
}

impl CheckpointKey {
    /// This key, also trusting each signer one of `delegations` names once it
    /// verifies against `policy`, the vault's external mode-root policy its
    /// host keeps apart from every artifact: never a roster an image restores
    /// or a root an artifact names. The pins and device it trusts stay.
    #[must_use]
    pub fn trusting_mode_roots(
        mut self,
        policy: &BackupModeRootPolicy,
        delegations: &[BackupSignerDelegation],
    ) -> Self {
        let policy_digest = match policy.digest() {
            Ok(digest) if policy.engine_vault_id == self.vault_id => digest,
            Ok(_) => {
                tracing::warn!(
                    reason = "backup_mode_root_policy_foreign",
                    "the backup mode-root policy is another vault's; it delegates no signer here"
                );
                return self;
            }
            Err(error) => {
                tracing::warn!(
                    reason = "backup_mode_root_policy_invalid",
                    kind = ?error.kind(),
                    "the backup mode-root policy did not validate; it delegates no signer"
                );
                return self;
            }
        };
        let signers = delegations
            .iter()
            .filter_map(|delegation| match delegation.verify(policy) {
                Ok(signer) => Some(signer),
                Err(error) => {
                    tracing::warn!(
                        reason = "backup_signer_delegation_invalid",
                        kind = ?error.kind(),
                        "a backup signer delegation did not verify; it delegates no signer"
                    );
                    None
                }
            })
            .collect();
        self.delegated = Some(Box::new(DelegatedSigners {
            policy_digest,
            signers,
        }));
        self
    }

    /// The signers its mode roots delegated; none without a policy.
    pub(super) fn delegated_signers(&self) -> &[CheckpointSigner] {
        match self.delegated.as_deref() {
            Some(delegated) => &delegated.signers,
            None => &[],
        }
    }

    /// The digest of the policy its delegated signers came from.
    pub(super) fn mode_root_policy_digest(&self) -> Option<[u8; 32]> {
        self.delegated
            .as_deref()
            .map(|delegated| delegated.policy_digest)
    }
}
