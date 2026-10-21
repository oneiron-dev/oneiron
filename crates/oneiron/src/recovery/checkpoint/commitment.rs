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
// The commitment's codec, digest and signature check are the shared artifact
// codec's (`oneiron_crypto::backup`); signing, trust and the chain stay here.
pub use oneiron_crypto::backup::CheckpointSigner;
use oneiron_crypto::backup::{
    CHECKPOINT_SIGNATURE_EPOCH as EPOCH, CHECKPOINT_SIGNATURE_SUITE as SUITE,
    COMMITMENT_VERSION as VERSION, CheckpointFact, ED25519_KEY_ID, SLHDSA_KEY_ID,
    SignedCheckpointFact, commitment_digest, verify_commitment_signature,
};
pub(super) use oneiron_crypto::backup::{Commitment, MAX_SIGNED_FRAME};
use oneiron_crypto::{
    SigPurpose, SignatureRecord, SigningKey, SuiteId, VerifyPolicy, VerifyingKey, sign,
};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::{Callback, Rows};
use crate::world_keys::{keystore_error, refused, slot_seed};
use crate::{Error, Result, Vault};

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

impl ChainHead {
    /// The digest of the commitment this head names.
    pub(super) fn digest(&self) -> [u8; 32] {
        self.commitment
    }
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
        let part = |context: &str| crate::world_keys::derive_guarded(context, &[&seed[..]]);
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

    /// Signs `fact`, a complete artifact's checkpoint fact (FIX 7326), as
    /// the artifact's commitment was: the same dual record, purpose, epoch,
    /// install and keys, over the fact's own domain-separated subject.
    pub(super) fn sign_checkpoint_fact(
        &self,
        fact: &CheckpointFact,
    ) -> Result<SignedCheckpointFact> {
        let record = sign(
            SUITE,
            SigPurpose::BatchCheckpoint,
            EPOCH,
            &self.install,
            &fact.subject(),
            &[
                (ED25519_KEY_ID, &self.ed25519),
                (SLHDSA_KEY_ID, &self.slhdsa),
            ],
            &mut SysRng,
        )
        .map_err(|_| refused("signing the checkpoint fact failed"))?;
        SignedCheckpointFact::new(*fact, record.to_bytes()).map_err(|_| codec())
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

    /// Advances the chain from `from` to the checkpoint just signed, in a
    /// store write of its own that carries no other row, and returns that
    /// write's transaction id: what the backup watermark excludes as the
    /// backup's own. Refused when another checkpoint advanced it first.
    pub(super) fn advance_checkpoint_chain(
        &self,
        from: Option<ChainHead>,
        to: ChainHead,
    ) -> Result<u64> {
        self.store.group_write_as(Callback::Opaque, None, |txn| {
            match advance_in_txn(&self.store, txn, from, to) {
                Ok(own) => Rows::Commit(own),
                Err(error) => Rows::Discard(Err(error)),
            }
        })
    }
}

/// The chain's move from `from` to `to` in `txn`, and `txn`'s id.
fn advance_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    from: Option<ChainHead>,
    to: ChainHead,
) -> Result<u64> {
    if CHAIN_HEAD.get(store, txn, &())? != from {
        return Err(Error::InvalidConfig(
            "another checkpoint was taken at the same time; take this one again".into(),
        ));
    }
    CHAIN_HEAD.put(store, txn, &(), &to)?;
    Ok(txn.id() as u64)
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
        let bytes = commitment.encode().map_err(|_| codec())?;
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
            commitment: commitment_digest(&bytes),
        };
        Ok((bytes, record.to_bytes(), head))
    }
}

/// The public refs a version 2 commitment signs beside the manifest: the
/// prelude's registry binding (FIX 5826), the key header's commitment and
/// BLAKE3, and the custody position the snapshot read, so a host that never
/// opens the artifact reads them signed.
pub(super) struct SignedRefs {
    pub(super) registry_binding: Option<[u8; 32]>,
    pub(super) key_commitment: [u8; 32],
    pub(super) key_header_blake3: [u8; 32],
    pub(super) custody_ref: Option<oneiron_crypto::backup::CustodyRef>,
}

pub(super) fn new_commitment(
    link: &Link,
    vault_id: [u8; 32],
    kind: u8,
    snapshot: [u8; 32],
    manifest: [u8; 32],
    created_at: u64,
    refs: SignedRefs,
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
        registry_binding: refs.registry_binding,
        key_commitment: Some(refs.key_commitment),
        key_header_blake3: Some(refs.key_header_blake3),
        custody_ref: refs.custody_ref,
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
    let commitment = Commitment::decode(bytes).map_err(|_| codec())?;
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
    verify_commitment_signature(bytes, record, &commitment.signer)
        .map_err(|_| refused("the checkpoint's signature does not verify"))?;
    Ok(commitment)
}

impl Vault {
    /// Signs `transcript` with this install's checkpoint SLH-DSA-SHA2-256s key
    /// alone: a single-suite `BatchCheckpoint` record whose signer is the
    /// install id. It is the hash-based half of an authority checkpoint
    /// attestation (OF-469, checkpoint v2); the caller makes the classical half
    /// with the root's own key. Returns the install id, the SLH-DSA public key
    /// and the record's bytes.
    pub(crate) fn sign_authority_image(
        &self,
        transcript: &[u8],
    ) -> Result<([u8; 16], Vec<u8>, Vec<u8>)> {
        let keys = self.checkpoint_signing_keys()?;
        let record = sign(
            SuiteId::SIG_SLHDSA_SHA2_256S_V1,
            SigPurpose::BatchCheckpoint,
            EPOCH,
            &keys.install,
            transcript,
            &[(SLHDSA_KEY_ID, &keys.slhdsa)],
            &mut SysRng,
        )
        .map_err(|_| refused("signing the authority checkpoint failed"))?;
        Ok((
            keys.install,
            keys.slhdsa.verifying_key().to_bytes(),
            record.to_bytes(),
        ))
    }

    /// Verifies a record [`Self::sign_authority_image`] made over
    /// `transcript`: install `install`'s signature under the SLH-DSA public key
    /// `slhdsa`, at crypto epoch `min_epoch` or later. The caller names the key;
    /// the record never does.
    pub(crate) fn verify_authority_image(
        install: &[u8; 16],
        slhdsa: &[u8],
        min_epoch: u64,
        transcript: &[u8],
        record: &[u8],
    ) -> Result<()> {
        if record.len() as u64 > MAX_SIGNED_FRAME {
            return Err(codec());
        }
        let key = VerifyingKey::from_bytes(SuiteId::SIG_SLHDSA_SHA2_256S_V1, slhdsa)
            .map_err(|_| codec())?;
        SignatureRecord::parse(record)
            .map_err(|_| codec())?
            .verify(
                transcript,
                &VerifyPolicy {
                    suite: SuiteId::SIG_SLHDSA_SHA2_256S_V1,
                    purpose: SigPurpose::BatchCheckpoint,
                    signer: install,
                    min_epoch,
                },
                &[(SLHDSA_KEY_ID, &key)],
            )
            .map_err(|_| refused("the authority checkpoint's hash-based signature does not verify"))
    }
}
