//! Which roots this host's checkpoint head awaits (FIX 4882): for the head
//! image under the root policy the vault counts now, each policy root that
//! attested and each still awaited, and what the attested ones lack of the
//! quorum and the hardware rule. A root no install delivered stays pending:
//! a host whose own root the policy does not name never attests in its
//! place ([`ROOT_CHECKPOINT_MISSING_SIGNER`]).
//!
//! A policy change builds a new image on the next upkeep tick
//! ([`ROOT_CHECKPOINT_POLICY_CHANGE`]): a head built under another policy
//! awaits no root, since no root of the policy now may attest it.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::checkpoint::checkpoint_head_built_under_in_txn;
use super::checkpoint_attest::{ATTESTATIONS, KEY_BINDINGS, root_row_key, verify_root_attestation};
use super::checkpoint_root_attest::{linked_machine, peer_refused};
use super::*;
use crate::Vault;
use crate::error::{Error, RecordError, Result};

/// The shortfall of a head built under another root policy than this vault's.
const HEAD_UNDER_OTHER_POLICY: &str =
    "the checkpoint head was built under another root policy; the next upkeep builds one";

/// Where a policy root stands when no install delivered its attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheckpointMissingSigner {
    /// Pending: the image waits for the root, and no other key signs for it.
    Pending,
}

/// CALLS "FIX 4882 root checkpoint missing signer".
pub const ROOT_CHECKPOINT_MISSING_SIGNER: RootCheckpointMissingSigner =
    RootCheckpointMissingSigner::Pending;

impl RootCheckpointMissingSigner {
    const fn undelivered(self) -> CheckpointRootDelivery {
        match self {
            Self::Pending => CheckpointRootDelivery::Pending,
        }
    }
}

/// What the upkeep does when the root policy moves past the head's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheckpointPolicyChange {
    /// The next tick builds a new image under the current policy, growth or
    /// not, for its roots to attest.
    BuildNewImage,
    /// The head waits for its age, row or byte cutoff, as before FIX 4882.
    AtNextCutoff,
}

/// CALLS "FIX 4882 root checkpoint policy change".
pub const ROOT_CHECKPOINT_POLICY_CHANGE: RootCheckpointPolicyChange =
    RootCheckpointPolicyChange::BuildNewImage;

/// Where one policy root stands on the head image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRootDelivery {
    /// Its attestation is kept here under its kept key binding and verifies:
    /// it counts toward the quorum.
    Accepted,
    /// An attestation of it is kept here that does not count: made with
    /// another key binding than the one kept for the root now.
    SignedNotCounted,
    /// No install delivered its attestation here.
    Pending,
}

/// One root of the policy and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCheckpointRootState {
    pub key: AuthorityKey,
    pub tier: AuthorityTier,
    /// The managed host root.
    pub host: bool,
    pub delivery: CheckpointRootDelivery,
}

/// Which roots the checkpoint head awaits ([`Vault::authority_checkpoint_roots`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCheckpointRoots {
    /// The head image's id.
    pub image: [u8; 32],
    /// The digest of the root policy this vault counts now.
    pub policy: [u8; 32],
    /// Whether the head was built under that policy.
    pub current: bool,
    pub quorum: u8,
    /// Whether one attesting root must be hardware-backed.
    pub hardware: bool,
    /// Every root of the policy, ascending by key.
    pub roots: Vec<AuthorityCheckpointRootState>,
    /// What the accepted roots lack of the policy, named; `None` once the
    /// head reached it.
    pub shortfall: Option<&'static str>,
}

impl AuthorityCheckpointRoots {
    /// The roots the head still awaits: every root not accepted, while the
    /// head is under the current policy and short of it.
    pub fn awaited(&self) -> impl Iterator<Item = &AuthorityKey> {
        let short = self.current && self.shortfall.is_some();
        self.roots
            .iter()
            .filter(move |root| short && root.delivery != CheckpointRootDelivery::Accepted)
            .map(|root| &root.key)
    }
}

/// The root policy an image's bytes name, read alone and unchecked.
fn policy_named_by(bytes: &[u8]) -> Result<CheckpointRootPolicy> {
    #[derive(Deserialize)]
    struct PolicyOnly {
        root_policy: CheckpointRootPolicy,
    }
    let refused = || {
        Error::Record(RecordError::InvalidAuthorityLogBody(
            "checkpoint image policy",
        ))
    };
    let body = bytes
        .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
        .filter(|_| bytes.len() <= AUTHORITY_CHECKPOINT_V2_MAX_BYTES)
        .ok_or_else(refused)?;
    rmp_serde::from_slice::<PolicyOnly>(body)
        .map(|only| only.root_policy)
        .map_err(|_| refused())
}

impl Vault {
    /// Which roots this host's checkpoint head awaits under the root policy
    /// this vault counts now: see the module notes. `None` when no head is
    /// kept. A policy the roster cannot fix refuses, naming its rule.
    pub fn authority_checkpoint_roots(&self) -> Result<Option<AuthorityCheckpointRoots>> {
        let txn = self.store.env.read_txn()?;
        self.authority_checkpoint_roots_in_txn(&txn)
    }

    /// [`Vault::authority_checkpoint_roots`] for a linked machine of the
    /// vault. Refused for any other peer.
    pub fn authority_checkpoint_roots_for(
        &self,
        peer: PeerMachine,
    ) -> Result<Option<AuthorityCheckpointRoots>> {
        let txn = self.store.env.read_txn()?;
        if !linked_machine(&self.authority_fold_readonly_in_txn(&txn)?, peer) {
            return Err(peer_refused());
        }
        self.authority_checkpoint_roots_in_txn(&txn)
    }

    fn authority_checkpoint_roots_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<AuthorityCheckpointRoots>> {
        let Some((image, built_under)) = checkpoint_head_built_under_in_txn(&self.store, txn)?
        else {
            return Ok(None);
        };
        let context = self.checkpoint_context_in_txn(txn)?;
        let policy = context.policy.digest()?;
        let current = self.head_policy_in_txn(txn, image, built_under)? == Some(policy);
        let mut accepted = BTreeSet::new();
        let mut roots = Vec::with_capacity(context.policy.roots.len());
        for root in &context.policy.roots {
            let key = root_row_key(&root.key);
            let kept = KEY_BINDINGS.get(&self.store, txn, &key)?;
            let delivery = match ATTESTATIONS
                .get(&self.store, txn, &(image, key))?
                .filter(|stored| stored.policy == policy)
            {
                None => ROOT_CHECKPOINT_MISSING_SIGNER.undelivered(),
                Some(stored)
                    if kept.as_ref() == Some(&stored.attestation.binding)
                        && verify_root_attestation(
                            &root.key,
                            context.vault_id,
                            context.genesis,
                            &image,
                            policy,
                            &stored.attestation,
                        )
                        .is_ok() =>
                {
                    accepted.insert(root.key.clone());
                    CheckpointRootDelivery::Accepted
                }
                Some(_) => CheckpointRootDelivery::SignedNotCounted,
            };
            roots.push(AuthorityCheckpointRootState {
                key: root.key.clone(),
                tier: root.tier,
                host: root.host,
                delivery,
            });
        }
        let shortfall = if current {
            context.policy.shortfall(&accepted)
        } else {
            Some(HEAD_UNDER_OTHER_POLICY)
        };
        Ok(Some(AuthorityCheckpointRoots {
            image,
            policy,
            current,
            quorum: context.policy.quorum,
            hardware: context.policy.hardware,
            roots,
            shortfall,
        }))
    }

    /// The digest of the root policy head image `head` was built under:
    /// `built_under` when this install built it, else the policy its kept
    /// bytes name. `None` when its bytes are not kept.
    fn head_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        head: [u8; 32],
        built_under: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 32]>> {
        if built_under.is_some() {
            return Ok(built_under);
        }
        super::checkpoint::checkpoint_image_bytes_in_txn(&self.store, txn, &head)?
            .map(|bytes| policy_named_by(&bytes)?.digest())
            .transpose()
    }

    /// Whether the upkeep builds a new image because the root policy moved
    /// past the one head `head` was built under ([`ROOT_CHECKPOINT_POLICY_CHANGE`]).
    /// A policy the roster cannot fix builds nothing new.
    pub(super) fn checkpoint_policy_moved_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        head: Option<[u8; 32]>,
        built_under: Option<[u8; 32]>,
    ) -> Result<bool> {
        if ROOT_CHECKPOINT_POLICY_CHANGE == RootCheckpointPolicyChange::AtNextCutoff {
            return Ok(false);
        }
        let Some(head) = head else {
            return Ok(false);
        };
        let Ok(context) = self.checkpoint_context_in_txn(txn) else {
            return Ok(false);
        };
        let policy = context.policy.digest()?;
        Ok(self
            .head_policy_in_txn(txn, head, built_under)?
            .is_some_and(|built| built != policy))
    }

    /// Whether the kept attestations of `image` reach the root policy this
    /// vault counts now.
    pub(super) fn checkpoint_image_reached_policy(&self, image: [u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Ok(context) = self.checkpoint_context_in_txn(&txn) else {
            return Ok(false);
        };
        self.image_attested_in_txn(&txn, &context, image)
    }
}
