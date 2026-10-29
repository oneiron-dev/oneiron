//! Backup signers a vault's mode roots delegate (OF-570 (e), FIX 968).
//!
//! A restore trusts a checkpoint's signer when its key pins it or this
//! device holds its seed. A host whose install that signed a vault's backups
//! is gone may also trust a signer the vault's mode roots delegated: the
//! eligible roots of the vault's external [`BackupModeRootPolicy`], which the
//! host keeps apart from every artifact and changes only by a predecessor's
//! handoff, never the roster an image restores or a root an artifact names.
//! One delegation is one [`BackupSignerStatement`] under its own domain,
//! naming the vault, the policy by id, version and digest, the full signer
//! (install id, Ed25519 and SLH-DSA keys) and its signing epoch, signed by
//! distinct roots of that policy that reach its quorum, with its managed host
//! root and a hardware root where it requires them (CHECKPOINT QUORUM = C).
//! A delegation adds a signer beside the pinned ones; it never removes one.

use std::collections::BTreeSet;

use oneiron_crypto::backup::CheckpointSigner;
use serde::{Deserialize, Serialize};

use super::checkpoint_policy::policy_refused;
use super::{
    AuthorityKey, AuthoritySignature, CHECKPOINT_MULTI_ROOT_QUORUM,
    CHECKPOINT_SINGLE_ROOT_QUORUM_MAX_ROOTS, CheckpointRootPolicy, invalid_authority,
    verify_authority_signature,
};
use crate::error::Result;

/// The domain every delegation statement is signed under.
pub const BACKUP_SIGNER_DELEGATION_DOMAIN: &[u8] = b"oneiron/backup-signer-delegation/v1";

/// The policy's id is not a UUIDv7, or names another shape than the ruled
/// minimum quorum allows.
const POLICY_SHAPE: &str = "backup mode-root policy is not a canonical UUIDv7 policy";
/// The statement names another vault or policy than the one it is checked
/// against.
const STATEMENT_POLICY: &str = "backup signer delegation names another vault or policy";
/// A signature is not a distinct eligible root's over the statement.
const SIGNATURE_ROOT: &str = "backup signer delegation carries a signature no distinct root made";

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
        Ok(blake3::derive_key("oneiron/backup-mode-root-policy/v1", &bytes))
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

/// One statement and the root signatures over its transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSignerDelegation {
    pub statement: BackupSignerStatement,
    pub signatures: Vec<AuthoritySignature>,
}

impl BackupSignerDelegation {
    /// The signer `policy`'s roots delegate here: the statement names that
    /// policy and its vault, every signature is a distinct root's of it over
    /// the statement, and together they reach its quorum, host and hardware
    /// rules.
    ///
    /// # Errors
    ///
    /// Any of those fails, its rule named.
    pub fn verify(&self, policy: &BackupModeRootPolicy) -> Result<CheckpointSigner> {
        let statement = &self.statement;
        if statement.engine_vault_id != policy.engine_vault_id
            || statement.policy_id != policy.id
            || statement.policy_version != policy.version
            || statement.policy_digest != policy.digest()?
        {
            return Err(policy_refused(STATEMENT_POLICY));
        }
        let transcript = statement.transcript()?;
        let mut attested = BTreeSet::new();
        for signature in &self.signatures {
            if policy.roots.root(&signature.public_key).is_none()
                || !verify_authority_signature(signature, &transcript)
                || !attested.insert(signature.public_key.clone())
            {
                return Err(policy_refused(SIGNATURE_ROOT));
            }
        }
        if let Some(shortfall) = policy.roots.shortfall(&attested) {
            return Err(policy_refused(shortfall));
        }
        Ok(statement.signer())
    }
}

/// A vault's backup mode-root policy and the delegations its roots signed,
/// as its host hands them to a wake or migrate: [`Self::to_bytes`] is their
/// one encoding, which a restore plan carries opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupModeRoots {
    pub policy: BackupModeRootPolicy,
    pub delegations: Vec<BackupSignerDelegation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeRootsWire {
    policy: BackupModeRootPolicy,
    delegations: Vec<DelegationWire>,
}

/// A delegation's signatures by key: each key's suite is its own.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationWire {
    statement: BackupSignerStatement,
    signatures: Vec<(AuthorityKey, Vec<u8>)>,
}

impl BackupModeRoots {
    /// The encoding: MessagePack, named.
    ///
    /// # Errors
    ///
    /// It does not encode.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let wire = ModeRootsWire {
            policy: self.policy.clone(),
            delegations: self
                .delegations
                .iter()
                .map(|delegation| DelegationWire {
                    statement: delegation.statement.clone(),
                    signatures: delegation
                        .signatures
                        .iter()
                        .map(|signature| (signature.public_key.clone(), signature.signature.clone()))
                        .collect(),
                })
                .collect(),
        };
        rmp_serde::to_vec_named(&wire).map_err(|_| invalid_authority())
    }

    /// Reads [`Self::to_bytes`]'s encoding. Nothing is verified here.
    ///
    /// # Errors
    ///
    /// Any other bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: ModeRootsWire = rmp_serde::from_slice(bytes).map_err(|_| invalid_authority())?;
        Ok(Self {
            policy: wire.policy,
            delegations: wire
                .delegations
                .into_iter()
                .map(|delegation| BackupSignerDelegation {
                    statement: delegation.statement,
                    signatures: delegation
                        .signatures
                        .into_iter()
                        .map(|(public_key, signature)| AuthoritySignature {
                            suite: public_key.suite(),
                            public_key,
                            signature,
                        })
                        .collect(),
                })
                .collect(),
        })
    }
}
