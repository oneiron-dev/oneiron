//! Moved from `crates/oneiron/src/authority/backup_signer_delegation.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::checkpoint_policy::CHECKPOINT_MULTI_ROOT_QUORUM;
use crate::authority::checkpoint_policy::CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS;
use crate::authority::checkpoint_policy::CheckpointRootPolicy;
use crate::authority::checkpoint_policy::policy_refused;
use oneiron_authority::authority::invalid_authority;
use oneiron_base::error::Result;
use oneiron_crypto::backup::CheckpointSigner;
use serde::Deserialize;
use serde::Serialize;

/// The domain every delegation statement is signed under.
pub const BACKUP_SIGNER_DELEGATION_DOMAIN: &[u8] = b"oneiron/backup-signer-delegation/v1";

/// The policy's id is not a UUIDv7, or names another shape than the ruled
/// minimum quorum allows.
pub const POLICY_SHAPE: &str = "backup mode-root policy is not a canonical UUIDv7 policy";

/// A vault's external backup mode-root policy, held by its host: its id (a
/// UUIDv7) and version, the vault, and its roots with their quorum, host
/// and hardware rules, as an authority checkpoint's policy states them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupModeRootPolicy {
    pub id: [u8; 16],
    pub version: u64,
    pub engine_vault_id: [u8; 32],
    pub roots: CheckpointRootPolicy,
}

impl BackupModeRootPolicy {
    /// Checks its shape: a UUIDv7 id, canonical roots, and a quorum no
    /// lower than the ruled minimum (one root while one or two are
    /// eligible, two from three on).
    ///
    /// # Errors
    ///
    /// Any other policy, its rule named.
    pub fn validate(&self) -> Result<()> {
        self.roots.canonical_bytes()?;
        let floor = if self.roots.roots.len() <= CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS {
            1
        } else {
            CHECKPOINT_MULTI_ROOT_QUORUM
        };
        if self.id[6] >> 4 != 7 || self.id[8] >> 6 != 0b10 || usize::from(self.roots.quorum) < floor
        {
            return Err(policy_refused(POLICY_SHAPE));
        }
        Ok(())
    }

    /// The digest a statement names this policy by.
    ///
    /// # Errors
    ///
    /// A policy [`Self::validate`] refuses.
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let bytes = rmp_serde::to_vec_named(self).map_err(|_| invalid_authority())?;
        Ok(blake3::derive_key(
            "oneiron/backup-mode-root-policy/v1",
            &bytes,
        ))
    }
}

/// What one delegation's roots sign: the vault, the policy, the full signer
/// and the epoch it signs at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSignerStatement {
    pub engine_vault_id: [u8; 32],
    pub policy_id: [u8; 16],
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub install: [u8; 16],
    pub ed25519: [u8; 32],
    pub slhdsa: Vec<u8>,
    pub signing_epoch: u64,
}

impl BackupSignerStatement {
    /// The statement delegating `signer`, at `signing_epoch`, under `policy`.
    ///
    /// # Errors
    ///
    /// A policy [`BackupModeRootPolicy::validate`] refuses.
    pub fn delegating(
        policy: &BackupModeRootPolicy,
        signer: &CheckpointSigner,
        signing_epoch: u64,
    ) -> Result<Self> {
        Ok(Self {
            engine_vault_id: policy.engine_vault_id,
            policy_id: policy.id,
            policy_version: policy.version,
            policy_digest: policy.digest()?,
            install: signer.install,
            ed25519: signer.ed25519,
            slhdsa: signer.slhdsa.clone(),
            signing_epoch,
        })
    }

    /// The bytes a root signs: the domain, then the statement.
    ///
    /// # Errors
    ///
    /// The statement does not encode.
    pub fn transcript(&self) -> Result<Vec<u8>> {
        let mut out = BACKUP_SIGNER_DELEGATION_DOMAIN.to_vec();
        rmp_serde::encode::write_named(&mut out, self).map_err(|_| invalid_authority())?;
        Ok(out)
    }

    /// The signer it delegates.
    #[must_use]
    pub fn signer(&self) -> CheckpointSigner {
        CheckpointSigner {
            install: self.install,
            ed25519: self.ed25519,
            slhdsa: self.slhdsa.clone(),
        }
    }
}
