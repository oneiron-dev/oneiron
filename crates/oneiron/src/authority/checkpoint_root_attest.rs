//! A root of the vault's counted policy attests another host's checkpoint
//! image (FIX 4882). A vault holds one owner root, but a second mesh host, or
//! a hosted node attached without a re-root, serves under its own host issuer
//! and writes its images under it. Each image names the root policy the owner
//! chose, and that issuer attests nothing outside it
//! ([`Vault::write_authority_checkpoint_v2`]). So the install that holds a
//! policy root's signer attests them here, and the writing host takes the
//! attestation through its intake
//! ([`Vault::import_device_checkpoint_attestation`]).
//!
//! A root signs only an image it checked against its own fold. The bytes
//! decode strictly and the id is their hash. The vault and genesis are its
//! own. The image's root policy is the one its own fold counts now, under the
//! posture the image was folded in, and the root is in it. And its own held
//! rows, folded as the image says it was built, rebuild the image byte for
//! byte, but for what only the writing install knows: its chain parent, its
//! custody manifests and the rows it holds above a gap. A host's asserted
//! fold is never countersigned because it decodes. An image whose rows this
//! install does not hold yet waits, and so does one it cannot rebuild.
//!
//! The signer sits behind [`CheckpointRootSigner`]. The host root
//! ([`HostSlipIssuer`]) is today's only one; a device-held owner key (FIX
//! 4921) is another behind the same two calls. A host holds its signers on
//! the vault handle ([`Vault::hold_checkpoint_root_signer`]) for the device
//! sync's steady pass. An attestation made here goes to the writing host,
//! which verifies it again, and never into this install's attestation table,
//! so its own attested head never moves to another host's image. One made
//! for a home's head is kept in a delivery cache until the home has it (FIX
//! 5109, [`Vault::attest_home_checkpoint_as_root`]). The home stages the
//! image a machine sends it in parts in `checkpoint_root_stage`.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

use super::checkpoint_attest::{KEY_BINDINGS, attest_refused, root_row_key};
use super::checkpoint_image::checkpoint_image_id;
use super::checkpoint_policy::checkpoint_root_policy_of;
use super::*;
use crate::Vault;
use crate::error::{Error, Result};

/// The most image bytes one countersign part carries: inside the home's
/// inbound frame once base64 and the RPC envelope are added. An image goes in
/// as many parts as it takes, up to the image's own size cap.
pub const AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX: usize = 2 * 1024 * 1024;

const WAIT_NOT_COUNTED: &str = "the image's root policy is not the one this vault counts now";
const WAIT_NOT_A_ROOT: &str = "this root is not a root of the image's policy";
const WAIT_NOT_CAUGHT_UP: &str = "this install does not hold every row the image covers yet";
const WAIT_NOT_REBUILT: &str = "this install's own fold does not rebuild the image";

/// When roots' checkpoint attestations move between a machine and its home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheckpointPickup {
    /// On the device sync's existing steady pass, after its authority
    /// catch-up: no timer or queue of its own.
    ExistingTickAndCatchup,
}

/// CALLS "FIX 4882 root checkpoint pickup".
pub const ROOT_CHECKPOINT_PICKUP: RootCheckpointPickup =
    RootCheckpointPickup::ExistingTickAndCatchup;

/// Which images a root signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheckpointAuthority {
    /// Only an image under the root policy this vault's own fold counts,
    /// once the root's own fold rebuilds it.
    CountedSelectedPolicy,
}

/// CALLS "FIX 4882 root checkpoint authority".
pub const ROOT_CHECKPOINT_AUTHORITY: RootCheckpointAuthority =
    RootCheckpointAuthority::CountedSelectedPolicy;

impl RootCheckpointAuthority {
    /// Whether an image whose embedded policy is `embedded` is one a root
    /// may sign, where `counted` is the policy this vault's fold counts.
    fn signs_under(self, counted: &CheckpointRootPolicy, embedded: &CheckpointRootPolicy) -> bool {
        match self {
            Self::CountedSelectedPolicy => counted == embedded,
        }
    }
}

/// A root of the policy a vault counts, as a checkpoint signer: the root's
/// raw signature over a checkpoint statement, a key binding's or an
/// attestation's, and over nothing else.
pub trait CheckpointRootSigner: Send + Sync {
    /// The root key it signs as.
    fn root(&self) -> AuthorityKey;
    /// The root's raw signature over `statement`, which must be a checkpoint
    /// statement.
    fn sign_checkpoint_statement(&self, statement: &[u8]) -> Result<Vec<u8>>;
}

impl CheckpointRootSigner for HostSlipIssuer {
    fn root(&self) -> AuthorityKey {
        self.public_key()
    }

    fn sign_checkpoint_statement(&self, statement: &[u8]) -> Result<Vec<u8>> {
        self.sign_checkpoint(statement)
    }
}

/// What a root's check of another host's image came to.
#[derive(Debug, Clone)]
pub enum RootCheckpointAttest {
    /// The root attested the image `image`: the attestation for its writer's
    /// intake.
    Attested {
        image: [u8; 32],
        attestation: Box<AuthorityCheckpointAttestation>,
    },
    /// The root does not sign it now, and why. Never a fallback: the image
    /// waits for this root or another the policy names.
    Waiting(&'static str),
}

/// What a root signed of another host's image: its id, the posture it was
/// folded in, the digest of the root policy it names, and the attestation.
pub(super) struct RootSigned {
    pub(super) image: [u8; 32],
    pub(super) posture: crate::HostingPrivacyPosture,
    pub(super) policy: [u8; 32],
    pub(super) attestation: AuthorityCheckpointAttestation,
}

impl RootSigned {
    pub(super) fn into_attest(self) -> RootCheckpointAttest {
        RootCheckpointAttest::Attested {
            image: self.image,
            attestation: Box::new(self.attestation),
        }
    }
}

/// Whether `peer` is a live linked machine of the vault on the key it
/// proved, in any role, as the authority tail admits one.
pub(super) fn linked_machine(fold: &AuthorityFold, peer: PeerMachine) -> bool {
    match peer {
        PeerMachine::Proven { machine, key } => fold.machine_proof_key(machine) == Some(key),
        PeerMachine::Unknown => false,
    }
}

pub(super) fn peer_refused() -> Error {
    attest_refused("the peer is not a linked machine of this vault")
}

impl Vault {
    /// Holds `signer` on this handle for the device sync's steady pass, in
    /// place of one held for the same root: a host holds its own root's, and
    /// a device its owner key's (FIX 4921). Never persisted.
    pub fn hold_checkpoint_root_signer(&self, signer: Arc<dyn CheckpointRootSigner>) {
        let root = signer.root();
        let mut held = self
            .world_keys
            .checkpoint_roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        held.retain(|other| other.root() != root);
        held.push(signer);
    }

    /// The root signers this handle holds.
    #[must_use]
    pub fn checkpoint_root_signers(&self) -> Vec<Arc<dyn CheckpointRootSigner>> {
        self.world_keys
            .checkpoint_roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `signer`'s root attests checkpoint image `image`, which another host
    /// of this vault wrote, once it checks against this install's own fold
    /// (FIX 4882): see the module notes. Certifies this install's checkpoint
    /// key for the root first when no binding of it is kept; stores no
    /// attestation. Refused for bytes that are not a canonical image or name
    /// another vault. A root that attests a home's head keeps what it made
    /// through [`Vault::attest_home_checkpoint_as_root`] instead.
    pub fn attest_checkpoint_image_as_root(
        &self,
        image: &[u8],
        signer: &dyn CheckpointRootSigner,
    ) -> Result<RootCheckpointAttest> {
        Ok(match self.sign_checkpoint_image_as_root(image, signer)? {
            Ok(signed) => signed.into_attest(),
            Err(reason) => RootCheckpointAttest::Waiting(reason),
        })
    }

    /// [`Vault::attest_checkpoint_image_as_root`], with what the root signed
    /// in full; `Err` names why it does not sign now.
    pub(super) fn sign_checkpoint_image_as_root(
        &self,
        image: &[u8],
        signer: &dyn CheckpointRootSigner,
    ) -> Result<core::result::Result<RootSigned, &'static str>> {
        let candidate = AuthorityCheckpointV2::decode(image)?;
        let id = checkpoint_image_id(image);
        let root = signer.root();
        let (vault_id, genesis) = {
            let txn = self.store.env.read_txn()?;
            let genesis = self
                .authority_fold_readonly_in_txn(&txn)?
                .vault_id
                .ok_or_else(invalid_authority)?;
            if candidate.genesis != genesis {
                return Err(attest_refused("the checkpoint image is another vault's"));
            }
            if let Some(reason) =
                self.root_checkpoint_wait_in_txn(&txn, &candidate, image, &root)?
            {
                return Ok(Err(reason));
            }
            (*self.vault_id().as_bytes(), genesis)
        };
        let binding = self.root_checkpoint_binding(&root, signer, vault_id, genesis)?;
        let policy = candidate.root_policy.digest()?;
        let attestation = self.sign_checkpoint_attestation(
            vault_id,
            genesis,
            id,
            policy,
            binding,
            |transcript| signer.sign_checkpoint_statement(transcript),
        )?;
        Ok(Ok(RootSigned {
            image: id,
            posture: candidate.aggregate.posture,
            policy,
            attestation,
        }))
    }

    /// [`Vault::attest_checkpoint_image_as_root`] for a linked machine of the
    /// vault that asks this host's root to attest the image it wrote. Refused
    /// for any other peer.
    pub fn countersign_authority_checkpoint_for(
        &self,
        peer: PeerMachine,
        image: &[u8],
        signer: &dyn CheckpointRootSigner,
    ) -> Result<RootCheckpointAttest> {
        {
            let txn = self.store.env.read_txn()?;
            if !linked_machine(&self.authority_fold_readonly_in_txn(&txn)?, peer) {
                return Err(peer_refused());
            }
        }
        self.attest_checkpoint_image_as_root(image, signer)
    }

    /// Why `root` may not sign `candidate`, whose canonical bytes are
    /// `bytes`, now; `None` when it may.
    fn root_checkpoint_wait_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: &AuthorityCheckpointV2,
        bytes: &[u8],
        root: &AuthorityKey,
    ) -> Result<Option<&'static str>> {
        let posture = candidate.aggregate.posture;
        let view = self.authority_view_readonly_in_txn(txn)?;
        // A policy the roster cannot fix under that posture counts nothing.
        let Ok(counted) = checkpoint_root_policy_of(&view, posture) else {
            return Ok(Some(WAIT_NOT_COUNTED));
        };
        if !ROOT_CHECKPOINT_AUTHORITY.signs_under(&counted, &candidate.root_policy) {
            return Ok(Some(WAIT_NOT_COUNTED));
        }
        if counted.root(root).is_none() {
            return Ok(Some(WAIT_NOT_A_ROOT));
        }
        let covered: BTreeSet<AuthorityEntryHash> = candidate.covered.iter().copied().collect();
        let Ok(mut rebuilt) =
            self.build_authority_checkpoint_v2_as_in_txn(txn, posture, Some(&covered))
        else {
            return Ok(Some(WAIT_NOT_REBUILT));
        };
        if rebuilt.covered != candidate.covered {
            return Ok(Some(WAIT_NOT_CAUGHT_UP));
        }
        // What only the writing install knows; every other byte is this
        // install's own fold.
        rebuilt.parent = candidate.parent;
        rebuilt.archive_manifests = candidate.archive_manifests.clone();
        rebuilt.unresolved.held = candidate.unresolved.held.clone();
        rebuilt.unresolved.missing = candidate.unresolved.missing.clone();
        Ok((rebuilt.encode().ok().as_deref() != Some(bytes)).then_some(WAIT_NOT_REBUILT))
    }

    /// The kept binding of this install's checkpoint key for `root`, made
    /// once with `signer` when none is kept: every attestation the root
    /// makes here reuses it.
    fn root_checkpoint_binding(
        &self,
        root: &AuthorityKey,
        signer: &dyn CheckpointRootSigner,
        vault_id: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<AuthorityCheckpointKeyBinding> {
        let own = self.checkpoint_signer()?;
        let kept = {
            let txn = self.store.env.read_txn()?;
            KEY_BINDINGS.get(&self.store, &txn, &root_row_key(root))?
        };
        if let Some(binding) = kept.filter(|binding| {
            binding.install == own.install
                && binding.slhdsa == own.slhdsa
                && binding.vault_id == vault_id
                && binding.genesis == genesis
        }) {
            binding.verify(root)?;
            return Ok(binding);
        }
        self.checkpoint_key_binding(root, |statement| {
            signer.sign_checkpoint_statement(statement)
        })
    }
}
