//! What this home's root signed for a linked machine's own checkpoint image
//! (FIX 5195), kept until the machine asks again. The home answers a
//! countersign's last part only after its fold rebuild and the SLH-DSA
//! signature, and a machine waits one RPC timeout for each reply. So what the
//! root made is kept here, per machine and root, before the answer goes: when
//! the machine's timeout lost the answer, the same image's last part on its
//! next pass is answered from this cache, with no new rebuild and no new
//! signature. A machine's new head replaces its old one; no image bytes are
//! kept.
//!
//! A kept attestation is answered again only for the same image, and only
//! while this vault's fold still counts the policy it was made under, under
//! the image's posture, with the root in it; the peer is checked as a linked
//! machine on every ask. A row no machine asked for in the idle bound goes on
//! a later ask, never when a socket closes: the cache outlives the socket the
//! machine's timeout dropped. It is not the dialing side's delivery cache
//! (FIX 5109, `checkpoint_root_delivery`), so settling a home's head never
//! touches it, and never the attestation table. A reply cache, rebuilt by
//! signing again: Runtime-tier, and no checkpoint image carries it.

use serde::{Deserialize, Serialize};

use super::checkpoint_attest::root_row_key;
use super::checkpoint_image::checkpoint_image_id;
use super::checkpoint_policy::checkpoint_root_policy_of;
use super::checkpoint_root_attest::RootSigned;
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// How long a kept countersign waits for its machine to ask again before a
/// later ask drops it: the countersign stage's idle bound (FIX 5111).
const COUNTERSIGN_KEPT_IDLE_SECS: u64 = 10 * 60;

/// One kept countersign. Key: the machine's id + [`root_row_key`].
const COUNTERSIGNED: SideTable<(EntityId, Vec<u8>), KeptCountersign, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_COUNTERSIGN);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptCountersign {
    image: [u8; 32],
    /// The posture the image was folded in.
    posture: crate::HostingPrivacyPosture,
    /// The digest of the root policy it was made under.
    policy: [u8; 32],
    attestation: AuthorityCheckpointAttestation,
    /// The local second the machine last asked for it.
    touched_secs: u64,
}

impl Vault {
    /// `signer`'s root attests the image `image` that the linked machine
    /// `machine` wrote, answered from what the root kept for that machine
    /// when it is the same image and still counts, and kept for it before it
    /// is answered when signed anew (FIX 5195): see the module notes. A keep
    /// that fails is logged, and the attestation still goes.
    pub(super) fn countersign_kept_or_signed(
        &self,
        machine: EntityId,
        image: &[u8],
        signer: &dyn CheckpointRootSigner,
    ) -> Result<RootCheckpointAttest> {
        let id = checkpoint_image_id(image);
        let root = signer.root();
        let key = (machine, root_row_key(&root));
        match self.kept_countersign(&key, &root, id) {
            Ok(Some(attestation)) => {
                return Ok(RootCheckpointAttest::Attested {
                    image: id,
                    attestation: Box::new(attestation),
                });
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a kept countersign was not read; the root signs again"
            ),
        }
        let signed = match self.sign_checkpoint_image_as_root(image, signer)? {
            Ok(signed) => signed,
            Err(reason) => return Ok(RootCheckpointAttest::Waiting(reason)),
        };
        if let Err(error) = self.keep_countersign(&key, &signed) {
            tracing::warn!(
                kind = ?error.kind(),
                "a root's countersign of a machine's checkpoint was not kept here"
            );
        }
        Ok(signed.into_attest())
    }

    /// The attestation `root` kept under `key` for the image `id`, while it
    /// still counts, touched for the ask; rows idle past the bound go first.
    fn kept_countersign(
        &self,
        key: &(EntityId, Vec<u8>),
        root: &AuthorityKey,
        id: [u8; 32],
    ) -> Result<Option<AuthorityCheckpointAttestation>> {
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        self.drop_idle_countersigns(&mut txn, now)?;
        let kept = match COUNTERSIGNED.get(&self.store, &txn, key)? {
            Some(kept) if kept.image == id => kept,
            _ => {
                txn.commit()?;
                return Ok(None);
            }
        };
        if kept.attestation.binding.root != *root
            || !self.root_policy_counts_in_txn(&txn, kept.posture, root, kept.policy)?
        {
            COUNTERSIGNED.delete(&self.store, &mut txn, key)?;
            txn.commit()?;
            return Ok(None);
        }
        let kept = KeptCountersign {
            touched_secs: now,
            ..kept
        };
        COUNTERSIGNED.put(&self.store, &mut txn, key, &kept)?;
        txn.commit()?;
        Ok(Some(kept.attestation))
    }

    /// Keeps what the root signed under `key`, in place of the machine's
    /// older head for that root.
    fn keep_countersign(&self, key: &(EntityId, Vec<u8>), signed: &RootSigned) -> Result<()> {
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        self.drop_idle_countersigns(&mut txn, now)?;
        let kept = KeptCountersign {
            image: signed.image,
            posture: signed.posture,
            policy: signed.policy,
            attestation: signed.attestation.clone(),
            touched_secs: now,
        };
        COUNTERSIGNED.put(&self.store, &mut txn, key, &kept)?;
        txn.commit()?;
        Ok(())
    }

    /// Drops every kept countersign no machine asked for in the idle bound.
    fn drop_idle_countersigns(&self, txn: &mut heed::RwTxn<'_>, now: u64) -> Result<()> {
        for (key, kept) in COUNTERSIGNED.scan(&self.store, txn)? {
            if now.saturating_sub(kept.touched_secs) > COUNTERSIGN_KEPT_IDLE_SECS {
                COUNTERSIGNED.delete(&self.store, txn, &key)?;
            }
        }
        Ok(())
    }

    /// Whether this vault's fold still counts the root policy whose digest
    /// is `policy`, under `posture`, with `root` in it.
    pub(super) fn root_policy_counts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        posture: crate::HostingPrivacyPosture,
        root: &AuthorityKey,
        policy: [u8; 32],
    ) -> Result<bool> {
        let view = self.authority_view_readonly_in_txn(txn)?;
        let Ok(counted) = checkpoint_root_policy_of(&view, posture) else {
            return Ok(false);
        };
        Ok(counted.root(root).is_some() && counted.digest()? == policy)
    }
}
