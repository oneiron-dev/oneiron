//! The host intake for one root's attestation of a checkpoint image this host
//! keeps (FIX 4882): a root this host does not hold attests the image
//! elsewhere ([`Vault::attest_checkpoint_image_as_root`]), and a linked
//! machine of the vault delivers it here. A device-held owner key (FIX 4921)
//! delivers through the same door.
//!
//! The delivering peer is a live linked machine of the vault, in any role, on
//! the key it proved. The image is one this host keeps, built under the root
//! policy this vault counts now. Exactly one root is verified, keyed by its
//! public key: the root must be the policy's, its binding must verify under
//! it, and both halves must verify, the classical one under the root and the
//! hash-based one under the install, key and epoch the binding certifies.
//! Nothing the attestation names chooses its trust: the root comes from this
//! vault's own policy. The binding and the attestation land in the side
//! tables the host's own attestations use, one per root, so a root never
//! counts twice. The quorum is judged again, and the attested head moves when
//! the image first reaches it.
//!
//! A delivery is idempotent by its exact image, policy, root and key binding
//! ([`ROOT_CHECKPOINT_RETRY`]): a kept one changes nothing, whatever its
//! signature bytes, since the hash-based half is randomized.

use super::checkpoint::checkpoint_head_in_txn;
use super::checkpoint_attest::{
    ATTESTATIONS, ATTESTED_HEAD, AttestedHead, KEY_BINDINGS, StoredAttestation, attest_refused,
    root_row_key, verify_root_attestation,
};
use super::checkpoint_image::checkpoint_image_id;
use super::checkpoint_root_attest::{linked_machine, peer_refused};
use super::*;
use crate::Vault;
use crate::error::{Error, Result};

/// How a delivered attestation is told apart from one already kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheckpointRetry {
    /// By the exact image, policy, root and key binding.
    ExactImagePolicyRootBinding,
}

/// CALLS "FIX 4882 root checkpoint retry".
pub const ROOT_CHECKPOINT_RETRY: RootCheckpointRetry =
    RootCheckpointRetry::ExactImagePolicyRootBinding;

impl RootCheckpointRetry {
    /// Whether a delivery made with `binding` under the policy whose digest
    /// is `policy` is the one kept: `stored` for the image and root, with
    /// `kept` the root's kept binding.
    fn kept(
        self,
        stored: Option<&StoredAttestation>,
        kept: Option<&AuthorityCheckpointKeyBinding>,
        policy: &[u8; 32],
        binding: &AuthorityCheckpointKeyBinding,
    ) -> bool {
        match self {
            Self::ExactImagePolicyRootBinding => {
                kept == Some(binding)
                    && stored.is_some_and(|stored| {
                        stored.policy == *policy && stored.attestation.binding == *binding
                    })
            }
        }
    }
}

/// What the intake did with one delivered attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointAttestationIntake {
    /// The attestation is kept now; `attested` when the image's kept
    /// attestations reach the policy.
    Kept { attested: bool },
    /// The same attestation was kept already: nothing changed.
    AlreadyKept { attested: bool },
}

impl Vault {
    /// Takes one root's attestation of kept image `image`, delivered by the
    /// linked machine `peer` (FIX 4882): see the module notes. Refused for
    /// any other peer, an image this host does not keep or built under
    /// another policy, a key no root of the policy holds, a binding for
    /// another vault, either half failing to verify, and a binding other than
    /// this install's own for a root this install certifies itself.
    pub fn import_device_checkpoint_attestation(
        &self,
        peer: PeerMachine,
        image: [u8; 32],
        attestation: &AuthorityCheckpointAttestation,
    ) -> Result<CheckpointAttestationIntake> {
        // Read before the write: loading the keys may open its own
        // transactions. An install with none certifies no root itself.
        let own_install = self.checkpoint_signer().ok().map(|signer| signer.install);
        let mut txn = self.store.env.write_txn()?;
        if !linked_machine(&self.authority_fold_readonly_in_txn(&txn)?, peer) {
            return Err(peer_refused());
        }
        let bytes = super::checkpoint::checkpoint_image_bytes_in_txn(&self.store, &txn, &image)?
            .ok_or_else(|| attest_refused("this host keeps no such checkpoint image"))?;
        if checkpoint_image_id(&bytes) != image {
            return Err(Error::CorruptedIndex("kept authority checkpoint image"));
        }
        let built_under = AuthorityCheckpointV2::decode(&bytes)?
            .root_policy
            .digest()?;
        let context = self.checkpoint_context_in_txn(&txn)?;
        let policy = context.policy.digest()?;
        if built_under != policy {
            return Err(attest_refused(
                "the checkpoint image was built under another root policy than this vault's",
            ));
        }
        let binding = &attestation.binding;
        let root = context
            .policy
            .root(&binding.root)
            .ok_or_else(|| {
                attest_refused("the attesting key is not a root of this vault's policy")
            })?
            .key
            .clone();
        if binding.vault_id != context.vault_id || binding.genesis != context.genesis {
            return Err(attest_refused(
                "the attestation's key binding is another vault's",
            ));
        }
        verify_root_attestation(
            &root,
            context.vault_id,
            context.genesis,
            &image,
            policy,
            attestation,
        )?;
        let key = root_row_key(&root);
        let kept = KEY_BINDINGS.get(&self.store, &txn, &key)?;
        let stored = ATTESTATIONS.get(&self.store, &txn, &(image, key.clone()))?;
        if ROOT_CHECKPOINT_RETRY.kept(stored.as_ref(), kept.as_ref(), &policy, binding) {
            let attested = self.image_attested_in_txn(&txn, &context, image)?;
            return Ok(CheckpointAttestationIntake::AlreadyKept { attested });
        }
        // A root this install certifies itself attests here; another
        // install's binding for it would push this one's out, and back.
        if kept
            .as_ref()
            .is_some_and(|kept| kept != binding && own_install == Some(kept.install))
        {
            return Err(attest_refused(
                "this install certifies its own checkpoint key for the root",
            ));
        }
        let before = self.image_attested_in_txn(&txn, &context, image)?;
        if kept.as_ref() != Some(binding) {
            KEY_BINDINGS.put(&self.store, &mut txn, &key, binding)?;
        }
        ATTESTATIONS.put(
            &self.store,
            &mut txn,
            &(image, key),
            &StoredAttestation {
                policy,
                attestation: attestation.clone(),
            },
        )?;
        let attested = self.image_attested_in_txn(&txn, &context, image)?;
        // The newest kept image moves the head; an older one only when no
        // attested head stands under this policy, so it never steps back.
        if !before
            && attested
            && (checkpoint_head_in_txn(&self.store, &txn)? == Some(image)
                || self
                    .authority_checkpoint_pin_in_txn(&txn, [0; 32])?
                    .is_none())
        {
            ATTESTED_HEAD.put(&self.store, &mut txn, &(), &AttestedHead { image, policy })?;
        }
        txn.commit()?;
        Ok(CheckpointAttestationIntake::Kept { attested })
    }
}
