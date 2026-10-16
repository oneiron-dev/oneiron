//! Hash-signed checkpoints (OF-570 (e)). Every sealed artifact carries a
//! commitment over its vault, kind, snapshot, sequence, epoch, predecessor and
//! sealed manifest (which binds the image and every body), dual-signed
//! Ed25519 + SLH-DSA-SHA2-256s as an E0 `BatchCheckpoint` record. A restore
//! verifies it before anything opens, against signers trusted from outside
//! the artifact: one whose seed this device's keystore holds, or ones the
//! caller pins. An artifact never names its own trust.
//!
//! Custody: one 32-byte seed per vault in this install's keystore
//! (`CheckpointSigning`), made on first use. Both keys are remade from it each
//! time they sign, as `BLAKE3-derive_key("oneiron/checkpoint-signing/<part>/v1",
//! seed)`: the Ed25519 seed and SLH-DSA's three FIPS 205 seeds. The 128-byte
//! SLH-DSA secret is never stored.
//!
//! Sequence and predecessor chain each vault's checkpoints: the vault keeps
//! the last one's sequence and commitment digest (`CHECKPOINT_CHAIN_HEAD`),
//! and a snapshot that loses a race to another is refused, never forked.
use std::sync::Arc;

use getrandom::SysRng;
use oneiron_crypto::{
    SigPurpose, SignatureRecord, SigningKey, SuiteId, VerifyPolicy, VerifyingKey, sign,
};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::side_table::{self, Named, SideTable};
use crate::world_keys::{keystore_error, refused, slot_seed};
use crate::{Error, Result, Vault};

const SUITE: SuiteId = SuiteId::SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1;
/// The crypto epoch every checkpoint signature is made at.
const EPOCH: u64 = 1;
const VERSION: u16 = 1;
const ED25519_KEY_ID: &[u8] = b"ed25519";
const SLHDSA_KEY_ID: &[u8] = b"slh-dsa-sha2-256s";
/// Longest commitment or signature record a reader takes.
pub(super) const MAX_SIGNED_FRAME: u64 = 128 * 1024;

/// The vault's last checkpoint: its sequence and commitment digest. Key: ().
const CHAIN_HEAD: SideTable<(), ChainHead, Named> =
    SideTable::new(&side_table::CHECKPOINT_CHAIN_HEAD);

fn codec() -> Error {
    Error::CorruptedIndex("checkpoint commitment")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChainHead {
    sequence: u64,
    commitment: [u8; 32],
}

/// One install's checkpoint signer for one vault: its install id and both
/// public keys. A host trusts its checkpoints by pinning it
/// ([`super::CheckpointKey::trusting`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSigner {
    pub install: [u8; 16],
    pub ed25519: [u8; 32],
    /// The SLH-DSA-SHA2-256s public key, 64 bytes.
    pub slhdsa: Vec<u8>,
}

/// Whose signatures a restore accepts.
#[derive(Clone)]
pub(super) enum Trust {
    /// A signer whose seed this keystore holds for the vault: this device's.
    Device(Arc<dyn DeviceKeystore>),
    /// These signers, pinned by the caller.
    Pinned(Vec<CheckpointSigner>),
    /// None: a key made only to seal.
    Nobody,
}

/// Both signing keys, remade from the slot seed.
pub(super) struct SigningKeys {
    install: [u8; 16],
    ed25519: SigningKey,
    slhdsa: SigningKey,
}

impl SigningKeys {
    fn expand(install: [u8; 16], seed: &[u8; 32]) -> Self {
        let part = |context: &str| Zeroizing::new(blake3::derive_key(context, seed));
        let ed25519 = part("oneiron/checkpoint-signing/ed25519/v1");
        let sk_seed = part("oneiron/checkpoint-signing/slh-sk-seed/v1");
        let sk_prf = part("oneiron/checkpoint-signing/slh-sk-prf/v1");
        let pk_seed = part("oneiron/checkpoint-signing/slh-pk-seed/v1");
        Self {
            install,
            ed25519: SigningKey::ed25519_from_seed(&ed25519),
            slhdsa: SigningKey::slhdsa_sha2_256s_from_seeds(&sk_seed, &sk_prf, &pk_seed),
        }
    }

    pub(super) fn signer(&self) -> Result<CheckpointSigner> {
        Ok(CheckpointSigner {
            install: self.install,
            ed25519: self
                .ed25519
                .verifying_key()
                .to_bytes()
                .try_into()
                .map_err(|_| codec())?,
            slhdsa: self.slhdsa.verifying_key().to_bytes(),
        })
    }
}

fn slot(vault_id: [u8; 32], install: [u8; 16]) -> KeystoreSlot {
    KeystoreSlot {
        vault_id,
        install,
        kind: SlotKind::CheckpointSigning,
    }
}

impl Vault {
    /// This install's checkpoint signing keys for this vault, the seed made in
    /// its keystore slot on first use.
    pub(super) fn checkpoint_signing_keys(&self) -> Result<SigningKeys> {
        let keystore = self.device_keystore()?;
        let install = *self.prepare_install_signing()?.as_bytes();
        let seed = slot_seed(
            keystore.as_ref(),
            &slot(*self.vault_id().as_bytes(), install),
        )?;
        Ok(SigningKeys::expand(install, &seed))
    }

    /// This install's checkpoint signer: what another host pins to trust the
    /// checkpoints and backups this one signs.
    pub fn checkpoint_signer(&self) -> Result<CheckpointSigner> {
        self.checkpoint_signing_keys()?.signer()
    }

    /// The vault's last checkpoint, read in `txn`: the next one's sequence and
    /// predecessor.
    pub(super) fn checkpoint_chain_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<ChainHead>> {
        CHAIN_HEAD.get(&self.store, txn, &())
    }

    /// Advances the chain from `from` to the checkpoint just signed. Refused
    /// when another checkpoint advanced it first.
    pub(super) fn advance_checkpoint_chain(
        &self,
        from: Option<ChainHead>,
        to: ChainHead,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            if CHAIN_HEAD.get(&self.store, txn, &())? != from {
                return Err(Error::InvalidConfig(
                    "another checkpoint was taken at the same time; take this one again".into(),
                ));
            }
            CHAIN_HEAD.put(&self.store, txn, &(), &to)
        })
    }
}

/// What one artifact's signature covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Commitment {
    pub(super) version: u16,
    pub(super) vault_id: [u8; 32],
    pub(super) kind: u8,
    pub(super) snapshot: [u8; 32],
    pub(super) sequence: u64,
    pub(super) epoch: u64,
    /// The previous checkpoint's commitment digest; `None` for the first.
    pub(super) predecessor: Option<[u8; 32]>,
    /// BLAKE3 of the sealed manifest's envelope.
    pub(super) manifest: [u8; 32],
    pub(super) created_at: u64,
    pub(super) signer: CheckpointSigner,
}

/// The link a new checkpoint takes in its vault's chain.
pub(super) struct Link {
    pub(super) keys: SigningKeys,
    pub(super) head: Option<ChainHead>,
}

impl Link {
    pub(super) fn sequence(&self) -> u64 {
        self.head.map_or(1, |head| head.sequence + 1)
    }

    pub(super) fn predecessor(&self) -> Option<[u8; 32]> {
        self.head.map(|head| head.commitment)
    }

    /// Signs `commitment`: its bytes, the signature record's, and the head
    /// the chain moves to.
    pub(super) fn sign(&self, commitment: &Commitment) -> Result<(Vec<u8>, Vec<u8>, ChainHead)> {
        let bytes = rmp_serde::to_vec_named(commitment).map_err(|_| codec())?;
        let record = sign(
            SUITE,
            SigPurpose::BatchCheckpoint,
            EPOCH,
            &commitment.signer.install,
            &bytes,
            &[
                (ED25519_KEY_ID, &self.keys.ed25519),
                (SLHDSA_KEY_ID, &self.keys.slhdsa),
            ],
            &mut SysRng,
        )
        .map_err(|_| refused("signing the checkpoint failed"))?;
        let head = ChainHead {
            sequence: commitment.sequence,
            commitment: *blake3::hash(&bytes).as_bytes(),
        };
        Ok((bytes, record.to_bytes(), head))
    }
}

pub(super) fn new_commitment(
    link: &Link,
    vault_id: [u8; 32],
    kind: u8,
    snapshot: [u8; 32],
    manifest: [u8; 32],
    created_at: u64,
) -> Result<Commitment> {
    Ok(Commitment {
        version: VERSION,
        vault_id,
        kind,
        snapshot,
        sequence: link.sequence(),
        epoch: EPOCH,
        predecessor: link.predecessor(),
        manifest,
        created_at,
        signer: link.keys.signer()?,
    })
}

/// Verifies `record` over `bytes` for `vault_id` and returns the commitment.
/// Refused unless `trust` accepts its signer and both signatures verify.
pub(super) fn verify(
    trust: &Trust,
    vault_id: &[u8; 32],
    bytes: &[u8],
    record: &[u8],
) -> Result<Commitment> {
    let commitment: Commitment = rmp_serde::from_slice(bytes).map_err(|_| codec())?;
    if commitment.version != VERSION
        || commitment.epoch != EPOCH
        || commitment.vault_id != *vault_id
    {
        return Err(codec());
    }
    let trusted = match trust {
        Trust::Device(keystore) => keystore
            .get(&slot(*vault_id, commitment.signer.install))
            .map_err(keystore_error)?
            .map(|seed| SigningKeys::expand(commitment.signer.install, &seed).signer())
            .transpose()?
            .is_some_and(|signer| signer == commitment.signer),
        Trust::Pinned(signers) => signers.contains(&commitment.signer),
        Trust::Nobody => false,
    };
    if !trusted {
        return Err(refused("the checkpoint's signer is not trusted here"));
    }
    let ed25519 = VerifyingKey::from_bytes(SuiteId::SIG_ED25519_V1, &commitment.signer.ed25519)
        .map_err(|_| codec())?;
    let slhdsa =
        VerifyingKey::from_bytes(SuiteId::SIG_SLHDSA_SHA2_256S_V1, &commitment.signer.slhdsa)
            .map_err(|_| codec())?;
    SignatureRecord::parse(record)
        .map_err(|_| codec())?
        .verify(
            bytes,
            &VerifyPolicy {
                suite: SUITE,
                purpose: SigPurpose::BatchCheckpoint,
                signer: &commitment.signer.install,
                min_epoch: EPOCH,
            },
            &[(ED25519_KEY_ID, &ed25519), (SLHDSA_KEY_ID, &slhdsa)],
        )
        .map_err(|_| refused("the checkpoint's signature does not verify"))?;
    Ok(commitment)
}
