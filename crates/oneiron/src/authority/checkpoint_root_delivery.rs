//! What a root held here signed for a home's checkpoint head (FIX 5109),
//! kept until the home's intake has it. A root signs a home's head on the
//! steady pass at seconds of SLH-DSA, so what it made is kept, per home and
//! root, and a delivery that failed goes again as it was signed: no new read
//! of the image and no new signature. It is never kept in the attestation
//! table, so this install's own attested head never moves to another host's
//! image.
//!
//! A kept attestation goes again only for the same head, and only while this
//! vault's fold still counts the policy it was made under, under the image's
//! posture, with the root in it. Each time the home names its head and the
//! roots that head awaits, the kept rows for that home settle
//! ([`Vault::settle_root_attestations`]): a row for another head, or for a
//! home that keeps none, goes, and so does one whose policy no longer counts
//! here. A delivered root the head no longer awaits is accepted, and its
//! bytes go. The rows are a delivery cache, rebuilt by signing again, so they
//! are Runtime-tier and no checkpoint image carries them. The home shows the
//! root pending until its intake keeps it
//! ([`Vault::authority_checkpoint_roots`]); this side reads where each stands
//! with [`Vault::checkpoint_root_deliveries`].

use serde::{Deserialize, Serialize};

use super::checkpoint_attest::root_row_key;
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One kept delivery. Key: [`home_tag`] + [`root_row_key`].
const DELIVERIES: SideTable<([u8; 17], Vec<u8>), KeptDelivery, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_ROOT_DELIVERY);

/// Where a root's attestation of a home's head stands, as this install knows
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootAttestationDeliveryState {
    /// Signed here; the home's intake has not taken it.
    SignedNotUploaded,
    /// The home's intake took it; the home has not reported the root
    /// accepted for that head yet.
    Delivered,
    /// The home's head no longer awaits the root.
    Accepted,
}

/// One root's attestation of one home's head
/// ([`Vault::checkpoint_root_deliveries`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAttestationDelivery {
    /// The home's machine; `None` for a home that proved none on its socket.
    pub home: Option<EntityId>,
    /// The head image's id.
    pub image: [u8; 32],
    pub root: AuthorityKey,
    pub state: RootAttestationDeliveryState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptDelivery {
    image: [u8; 32],
    root: AuthorityKey,
    /// The posture the image was folded in.
    posture: crate::HostingPrivacyPosture,
    /// The digest of the root policy it was made under.
    policy: [u8; 32],
    state: RootAttestationDeliveryState,
    /// Kept until the home's head no longer awaits the root.
    attestation: Option<AuthorityCheckpointAttestation>,
}

/// A home as a row key part: 1 then its machine id, or 0 then zeros for a
/// home that proved none.
fn home_tag(home: PeerMachine) -> [u8; 17] {
    let mut tag = [0; 17];
    if let PeerMachine::Proven { machine, .. } = home {
        tag[0] = 1;
        tag[1..].copy_from_slice(machine.as_bytes());
    }
    tag
}

fn home_of(tag: &[u8; 17]) -> Option<EntityId> {
    let machine: [u8; 16] = tag[1..].try_into().ok()?;
    (tag[0] == 1)
        .then(|| EntityId::from_bytes(machine).ok())
        .flatten()
}

/// What settling one kept row does, when it changes it.
enum Settle {
    /// The home's head no longer awaits a delivered root: accepted, and its
    /// bytes go.
    Accept,
    Drop,
}

impl Vault {
    /// Where each root held here stands on each home's head it signed (FIX
    /// 5109): signed but not uploaded, delivered, or accepted. See the module
    /// notes.
    pub fn checkpoint_root_deliveries(&self) -> Result<Vec<RootAttestationDelivery>> {
        let txn = self.store.env.read_txn()?;
        Ok(DELIVERIES
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|((home, _), kept)| RootAttestationDelivery {
                home: home_of(&home),
                image: kept.image,
                root: kept.root,
                state: kept.state,
            })
            .collect())
    }

    /// [`Vault::attest_checkpoint_image_as_root`] for the head `head` of the
    /// home `home`, whose bytes `image` are, keeping what the root signed
    /// until the home's intake has it (FIX 5109). Bytes that are not that
    /// head are attested as asked and not kept. A keep that fails is logged,
    /// and the attestation still goes.
    pub fn attest_home_checkpoint_as_root(
        &self,
        home: PeerMachine,
        head: [u8; 32],
        image: &[u8],
        signer: &dyn CheckpointRootSigner,
    ) -> Result<RootCheckpointAttest> {
        let signed = match self.sign_checkpoint_image_as_root(image, signer)? {
            Ok(signed) => signed,
            Err(reason) => return Ok(RootCheckpointAttest::Waiting(reason)),
        };
        if signed.image == head {
            let root = signed.attestation.binding.root.clone();
            let kept = KeptDelivery {
                image: signed.image,
                root,
                posture: signed.posture,
                policy: signed.policy,
                state: RootAttestationDeliveryState::SignedNotUploaded,
                attestation: Some(signed.attestation.clone()),
            };
            if let Err(error) = self.put_root_delivery(home, &kept) {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a root's attestation of the home's checkpoint was not kept here"
                );
            }
        }
        Ok(signed.into_attest())
    }

    /// The attestation `root` made of the head `head` of the home `home` and
    /// kept here, while it may go again: not yet accepted, and made under a
    /// policy this vault's fold still counts, with `root` in it (FIX 5109).
    pub fn kept_root_attestation(
        &self,
        home: PeerMachine,
        root: &AuthorityKey,
        head: [u8; 32],
    ) -> Result<Option<AuthorityCheckpointAttestation>> {
        let txn = self.store.env.read_txn()?;
        let Some(kept) =
            DELIVERIES.get(&self.store, &txn, &(home_tag(home), root_row_key(root)))?
        else {
            return Ok(None);
        };
        if kept.image != head || !self.kept_delivery_counts_in_txn(&txn, &kept)? {
            return Ok(None);
        }
        Ok(kept.attestation)
    }

    /// Marks what `root` signed of the head `head` of the home `home`
    /// delivered: the home's intake took it (FIX 5109).
    pub fn root_attestation_delivered(
        &self,
        home: PeerMachine,
        root: &AuthorityKey,
        head: [u8; 32],
    ) -> Result<()> {
        let key = (home_tag(home), root_row_key(root));
        let mut txn = self.store.env.write_txn()?;
        let Some(mut kept) = DELIVERIES.get(&self.store, &txn, &key)? else {
            return Ok(());
        };
        if kept.image != head || kept.state != RootAttestationDeliveryState::SignedNotUploaded {
            return Ok(());
        }
        kept.state = RootAttestationDeliveryState::Delivered;
        DELIVERIES.put(&self.store, &mut txn, &key, &kept)?;
        txn.commit()?;
        Ok(())
    }

    /// Settles what roots held here signed for the home `home` against what
    /// it names now: its head `head`, `None` when it keeps none, and the
    /// roots that head awaits (FIX 5109). See the module notes. A root never
    /// delivered that the head no longer awaits goes, and so does an accepted
    /// one it awaits again, so the root signs anew.
    pub fn settle_root_attestations(
        &self,
        home: PeerMachine,
        head: Option<[u8; 32]>,
        awaiting: &[AuthorityKey],
    ) -> Result<()> {
        let tag = home_tag(home);
        let mut settled = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for ((_, root), kept) in DELIVERIES.scan_from(&self.store, &txn, &tag)? {
                let settle = if head != Some(kept.image)
                    || !self.kept_delivery_counts_in_txn(&txn, &kept)?
                {
                    Settle::Drop
                } else {
                    match (kept.state, awaiting.contains(&kept.root)) {
                        (RootAttestationDeliveryState::Delivered, false) => Settle::Accept,
                        (RootAttestationDeliveryState::SignedNotUploaded, false)
                        | (RootAttestationDeliveryState::Accepted, true) => Settle::Drop,
                        _ => continue,
                    }
                };
                settled.push((root, kept, settle));
            }
        }
        if settled.is_empty() {
            return Ok(());
        }
        let mut txn = self.store.env.write_txn()?;
        for (root, mut kept, settle) in settled {
            let key = (tag, root);
            match settle {
                Settle::Accept => {
                    kept.state = RootAttestationDeliveryState::Accepted;
                    kept.attestation = None;
                    DELIVERIES.put(&self.store, &mut txn, &key, &kept)?;
                }
                Settle::Drop => {
                    DELIVERIES.delete(&self.store, &mut txn, &key)?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    fn put_root_delivery(&self, home: PeerMachine, kept: &KeptDelivery) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        DELIVERIES.put(
            &self.store,
            &mut txn,
            &(home_tag(home), root_row_key(&kept.root)),
            kept,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Whether this vault's fold still counts the policy `kept` was made
    /// under, under its image's posture, with its root in it.
    fn kept_delivery_counts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kept: &KeptDelivery,
    ) -> Result<bool> {
        self.root_policy_counts_in_txn(txn, kept.posture, &kept.root, kept.policy)
    }
}
