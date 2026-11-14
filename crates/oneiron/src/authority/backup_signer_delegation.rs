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

#[doc(hidden)]
use oneiron_records::authority::backup_signer_delegation::POLICY_SHAPE;
#[doc(hidden)]
pub use oneiron_records::authority::backup_signer_delegation::{
    BACKUP_SIGNER_DELEGATION_DOMAIN, BackupModeRootPolicy, BackupSignerStatement,
};

/// The statement names another vault or policy than the one it is checked
/// against.
const STATEMENT_POLICY: &str = "backup signer delegation names another vault or policy";
/// A signature is not a distinct eligible root's over the statement.
const SIGNATURE_ROOT: &str = "backup signer delegation carries a signature no distinct root made";

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
                        .map(|signature| {
                            (signature.public_key.clone(), signature.signature.clone())
                        })
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
