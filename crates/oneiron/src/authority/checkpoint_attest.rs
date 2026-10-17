//! Checkpoint v2 attestations (OF-469): an eligible root attests one authority
//! checkpoint image with two signatures over one transcript, a classical
//! signature under the root's own authority key and a hash-based
//! SLH-DSA-SHA2-256s signature under the checkpoint key that root certified.
//! A verifier requires both; neither alone attests (identity.md, signatures).
//!
//! Key binding: the root's classical signature over
//! `"oneiron/authority/checkpoint-key-binding/v1" || rmp named { vault_id,
//! genesis, root, install, slhdsa, epoch }` certifies one install's SLH-DSA
//! key for checkpoint attestation only. It is verified under the root key the
//! verifier's policy names, never under a key the binding supplies alone.
//!
//! Attestation transcript: `"oneiron/authority/checkpoint-attestation/v2" ||
//! rmp named { vault_id, genesis, image, policy, binding }`, where `image` is
//! the unsigned image id, `policy` the root policy's digest and `binding` the
//! key binding's digest.
//!
//! A joining device takes the eligible roots, their certified keys and the
//! quorum from a challenge-bound [`AuthorityCheckpointPin`] it received through
//! owner-authorized pairing, never from the image or the attestations it is
//! handed: a received checkpoint cannot choose its own signer set.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::*;
use crate::Vault;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable};

/// The crypto epoch a certified checkpoint key signs at: a binding names it,
/// and a hash-based record below it is refused.
pub const CHECKPOINT_KEY_EPOCH: u64 = 1;
const KEY_BINDING_DOMAIN: &[u8] = b"oneiron/authority/checkpoint-key-binding/v1";
const ATTESTATION_DOMAIN: &[u8] = b"oneiron/authority/checkpoint-attestation/v2";
const BINDING_DIGEST_CONTEXT: &str = "oneiron/authority/checkpoint-key-binding/digest/v1";
const PIN_DIGEST_CONTEXT: &str = "oneiron/authority/checkpoint-pin/v1";
/// An SLH-DSA-SHA2-256s public key.
const SLHDSA_PUBLIC_KEY_LEN: usize = 64;

/// One root's attestation of one image. Key: image id + [`root_row_key`].
const ATTESTATIONS: SideTable<([u8; 32], Vec<u8>), StoredAttestation, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_ATTESTATION);
/// The newest image whose attestations reached this vault's policy. Key: ().
const ATTESTED_HEAD: SideTable<(), AttestedHead, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_ATTESTED_HEAD);
/// Each eligible root's certified checkpoint key. Key: [`root_row_key`].
const KEY_BINDINGS: SideTable<Vec<u8>, AuthorityCheckpointKeyBinding, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_KEY_BINDING);

fn attest_refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

fn encode_err() -> Error {
    Error::CorruptedIndex("authority checkpoint attestation")
}

/// A root key as a row key: a suite byte, then the key bytes.
fn root_row_key(root: &AuthorityKey) -> Vec<u8> {
    let (suite, bytes): (u8, &[u8]) = match root {
        AuthorityKey::Ed25519(bytes) => (1, bytes.as_slice()),
        AuthorityKey::P256(bytes) => (2, bytes.as_slice()),
    };
    let mut key = vec![suite];
    key.extend_from_slice(bytes);
    key
}

/// Whether `transcript` is a checkpoint statement: a key binding's or an
/// attestation's. The host root signs nothing else as a checkpoint.
pub(super) fn checkpoint_statement_domain(transcript: &[u8]) -> bool {
    [KEY_BINDING_DOMAIN, ATTESTATION_DOMAIN]
        .iter()
        .any(|domain| transcript.starts_with(domain))
}

fn statement<T: Serialize>(domain: &[u8], body: &T) -> Result<Vec<u8>> {
    let mut out = domain.to_vec();
    rmp_serde::encode::write_named(&mut out, body).map_err(|_| encode_err())?;
    Ok(out)
}

/// An [`AuthoritySignature`] as a named map: its suite's name, key and bytes.
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{AuthorityKey, AuthoritySignature, AuthoritySignatureSuite};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        suite: String,
        public_key: AuthorityKey,
        signature: Vec<u8>,
    }

    pub(super) fn serialize<S: Serializer>(
        signature: &AuthoritySignature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Wire {
            suite: signature.suite.as_str().to_owned(),
            public_key: signature.public_key.clone(),
            signature: signature.signature.clone(),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AuthoritySignature, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let suite = AuthoritySignatureSuite::parse(&wire.suite)
            .ok_or_else(|| serde::de::Error::custom("unknown authority signature suite"))?;
        Ok(AuthoritySignature {
            suite,
            public_key: wire.public_key,
            signature: wire.signature,
        })
    }
}

/// An eligible root's certificate for its checkpoint SLH-DSA key: the root's
/// classical signature over every other field. It binds the key to one
/// install's checkpoint signing seed, for checkpoint attestation only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointKeyBinding {
    pub vault_id: [u8; 32],
    /// The authority genesis entry hash.
    pub genesis: [u8; 32],
    pub root: AuthorityKey,
    /// The install whose checkpoint signing seed holds the key.
    pub install: [u8; 16],
    /// The SLH-DSA-SHA2-256s public key, 64 bytes.
    pub slhdsa: Vec<u8>,
    /// The crypto epoch the key signs at ([`CHECKPOINT_KEY_EPOCH`]).
    pub epoch: u64,
    #[serde(with = "signature_serde")]
    pub signature: AuthoritySignature,
}

#[derive(Serialize)]
struct BindingStatement {
    vault_id: [u8; 32],
    genesis: [u8; 32],
    root: AuthorityKey,
    install: [u8; 16],
    slhdsa: Vec<u8>,
    epoch: u64,
}

impl AuthorityCheckpointKeyBinding {
    /// What the root signs: the domain, then every field but the signature.
    pub fn statement(&self) -> Result<Vec<u8>> {
        statement(
            KEY_BINDING_DOMAIN,
            &BindingStatement {
                vault_id: self.vault_id,
                genesis: self.genesis,
                root: self.root.clone(),
                install: self.install,
                slhdsa: self.slhdsa.clone(),
                epoch: self.epoch,
            },
        )
    }

    fn check_shape(&self) -> Result<()> {
        if self.slhdsa.len() != SLHDSA_PUBLIC_KEY_LEN
            || self.epoch < CHECKPOINT_KEY_EPOCH
            || self.signature.public_key != self.root
            || self.signature.validate().is_err()
        {
            return Err(attest_refused("the checkpoint key binding is malformed"));
        }
        Ok(())
    }

    /// The whole binding, signature included, as rmp named.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.check_shape()?;
        rmp_serde::to_vec_named(self).map_err(|_| encode_err())
    }

    /// The digest an attestation names this binding by.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(blake3::derive_key(
            BINDING_DIGEST_CONTEXT,
            &self.canonical_bytes()?,
        ))
    }

    /// Verifies the binding as `root`'s, under `root` itself: the key a
    /// verifier's own policy names, never one the binding supplies alone.
    pub fn verify(&self, root: &AuthorityKey) -> Result<()> {
        self.check_shape()?;
        if &self.root != root || !verify_authority_signature(&self.signature, &self.statement()?) {
            return Err(attest_refused(
                "the checkpoint key binding does not verify under its root",
            ));
        }
        Ok(())
    }
}

/// One root's attestation of one checkpoint image: the classical signature
/// under the root key and the hash-based record under the key its binding
/// certifies, both over one transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointAttestation {
    pub binding: AuthorityCheckpointKeyBinding,
    #[serde(with = "signature_serde")]
    pub classical: AuthoritySignature,
    /// An SLH-DSA-SHA2-256s `BatchCheckpoint` signature record.
    pub hash_based: Vec<u8>,
}

#[derive(Serialize)]
struct AttestationStatement {
    vault_id: [u8; 32],
    genesis: [u8; 32],
    image: [u8; 32],
    policy: [u8; 32],
    binding: [u8; 32],
}

fn attestation_transcript(
    vault_id: [u8; 32],
    genesis: [u8; 32],
    image: [u8; 32],
    policy: [u8; 32],
    binding: &AuthorityCheckpointKeyBinding,
) -> Result<Vec<u8>> {
    statement(
        ATTESTATION_DOMAIN,
        &AttestationStatement {
            vault_id,
            genesis,
            image,
            policy,
            binding: binding.digest()?,
        },
    )
}

/// What a new device trusts a checkpoint by, fixed outside the checkpoint and
/// bound to one pairing's challenge: the exact image, the vault and its
/// genesis, the eligible roots and quorum, and each root's certified key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointPin {
    /// The single-use pairing link's fresh nonce.
    pub challenge: [u8; 32],
    pub vault_id: [u8; 32],
    /// The authority genesis entry hash.
    pub genesis: [u8; 32],
    /// The unsigned image id.
    pub checkpoint: [u8; 32],
    pub policy: CheckpointRootPolicy,
    /// Ascending by root key, one per root, each root in `policy`.
    pub bindings: Vec<AuthorityCheckpointKeyBinding>,
}

impl AuthorityCheckpointPin {
    /// Canonical bytes: a canonical policy and bindings ascending and unique
    /// by root, each an eligible root's, for this vault and genesis.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.policy.canonical_bytes()?;
        if self
            .bindings
            .windows(2)
            .any(|pair| pair[0].root >= pair[1].root)
        {
            return Err(attest_refused("the pin's key bindings are out of order"));
        }
        for binding in &self.bindings {
            binding.check_shape()?;
            if self.policy.root(&binding.root).is_none()
                || binding.vault_id != self.vault_id
                || binding.genesis != self.genesis
            {
                return Err(attest_refused(
                    "the pin carries a binding for another root or vault",
                ));
            }
        }
        rmp_serde::to_vec_named(self).map_err(|_| encode_err())
    }

    /// The digest the owner-delivered pairing link carries.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(blake3::derive_key(
            PIN_DIGEST_CONTEXT,
            &self.canonical_bytes()?,
        ))
    }

    /// The pinned binding of `root`.
    pub fn binding(&self, root: &AuthorityKey) -> Option<&AuthorityCheckpointKeyBinding> {
        self.bindings.iter().find(|binding| &binding.root == root)
    }
}

/// Every attestation verified against `pin` alone, deduplicated by root.
fn attested_roots(
    pin: &AuthorityCheckpointPin,
    image_id: &[u8; 32],
    attestations: &[AuthorityCheckpointAttestation],
) -> Result<BTreeSet<AuthorityKey>> {
    pin.canonical_bytes()?;
    if *image_id != pin.checkpoint {
        return Err(attest_refused("the image is not the pinned checkpoint"));
    }
    let policy = pin.policy.digest()?;
    let mut roots = BTreeSet::new();
    for attestation in attestations {
        let binding = &attestation.binding;
        let root = pin
            .policy
            .root(&binding.root)
            .ok_or_else(|| attest_refused("the attesting key is not a pinned root"))?;
        let pinned = pin
            .binding(&root.key)
            .ok_or_else(|| attest_refused("the pin certifies no checkpoint key for this root"))?;
        if binding.vault_id != pin.vault_id
            || binding.genesis != pin.genesis
            || binding.canonical_bytes()? != pinned.canonical_bytes()?
        {
            return Err(attest_refused(
                "the attestation's key binding is not the pinned one",
            ));
        }
        binding.verify(&root.key)?;
        let transcript =
            attestation_transcript(pin.vault_id, pin.genesis, *image_id, policy, binding)?;
        if attestation.classical.public_key != root.key
            || !verify_authority_signature(&attestation.classical, &transcript)
        {
            return Err(attest_refused(
                "the attestation's classical signature does not verify",
            ));
        }
        Vault::verify_authority_image(
            &binding.install,
            &binding.slhdsa,
            binding.epoch,
            &transcript,
            &attestation.hash_based,
        )?;
        roots.insert(root.key.clone());
    }
    Ok(roots)
}

/// Verifies `attestations` of `image_id` against `pin` and returns the roots
/// that attested. Each must be a pinned root's, carry exactly the pinned
/// binding, and carry both signatures; refused unless the distinct roots
/// reach the pinned quorum.
pub fn verify_authority_checkpoint_attestations(
    pin: &AuthorityCheckpointPin,
    image_id: &[u8; 32],
    attestations: &[AuthorityCheckpointAttestation],
) -> Result<BTreeSet<AuthorityKey>> {
    let roots = attested_roots(pin, image_id, attestations)?;
    if !pin.policy.admits(&roots) {
        return Err(attest_refused(
            "the attestations do not reach the pinned quorum",
        ));
    }
    Ok(roots)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttestation {
    /// The digest of the policy the attestation was made under.
    policy: [u8; 32],
    attestation: AuthorityCheckpointAttestation,
}

/// The attestations stored for `image` that were made under the root policy
/// whose digest is `policy`, as their roots made them.
pub(super) fn checkpoint_attestations_under_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    image: &[u8; 32],
    policy: &[u8; 32],
) -> Result<Vec<AuthorityCheckpointAttestation>> {
    Ok(ATTESTATIONS
        .scan_from(store, txn, image)?
        .into_iter()
        .filter(|(_, stored)| stored.policy == *policy)
        .map(|(_, stored)| stored.attestation)
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedHead {
    image: [u8; 32],
    /// The digest of the policy its attestations reached.
    policy: [u8; 32],
}

/// What an attestation is made against, read in one transaction.
#[derive(Clone, PartialEq, Eq)]
struct CheckpointContext {
    vault_id: [u8; 32],
    genesis: [u8; 32],
    policy: CheckpointRootPolicy,
}

impl CheckpointContext {
    fn eligible(&self, root: &AuthorityKey) -> Result<()> {
        self.policy
            .root(root)
            .map(|_| ())
            .ok_or_else(|| attest_refused("the key is not an eligible checkpoint root"))
    }
}

impl Vault {
    fn checkpoint_context_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<CheckpointContext> {
        let genesis = self
            .authority_fold_readonly_in_txn(txn)?
            .vault_id
            .ok_or_else(invalid_authority)?;
        Ok(CheckpointContext {
            vault_id: *self.vault_id().as_bytes(),
            genesis,
            policy: self.checkpoint_root_policy_in_txn(txn)?,
        })
    }

    /// The pin `image` would have under `context`: every stored binding of an
    /// eligible root, ascending by root.
    fn checkpoint_pin_for_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        context: &CheckpointContext,
        image: [u8; 32],
        challenge: [u8; 32],
    ) -> Result<AuthorityCheckpointPin> {
        let mut bindings = BTreeMap::new();
        for (_, binding) in KEY_BINDINGS.scan(&self.store, txn)? {
            if context.policy.root(&binding.root).is_some()
                && binding.vault_id == context.vault_id
                && binding.genesis == context.genesis
            {
                bindings.insert(binding.root.clone(), binding);
            }
        }
        Ok(AuthorityCheckpointPin {
            challenge,
            vault_id: context.vault_id,
            genesis: context.genesis,
            checkpoint: image,
            policy: context.policy.clone(),
            bindings: bindings.into_values().collect(),
        })
    }

    /// The stored attestations of the pin's image made under its policy with
    /// the binding it pins.
    fn pinned_attestations_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pin: &AuthorityCheckpointPin,
    ) -> Result<Vec<AuthorityCheckpointAttestation>> {
        let policy = pin.policy.digest()?;
        Ok(ATTESTATIONS
            .scan_from(&self.store, txn, &pin.checkpoint)?
            .into_iter()
            .filter(|(_, stored)| {
                stored.policy == policy
                    && pin.binding(&stored.attestation.binding.root)
                        == Some(&stored.attestation.binding)
            })
            .map(|(_, stored)| stored.attestation)
            .collect())
    }

    /// Whether the stored attestations of `image` reach `context`'s policy.
    fn image_attested_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        context: &CheckpointContext,
        image: [u8; 32],
    ) -> Result<bool> {
        let pin = self.checkpoint_pin_for_in_txn(txn, context, image, [0; 32])?;
        let attestations = self.pinned_attestations_in_txn(txn, &pin)?;
        Ok(verify_authority_checkpoint_attestations(&pin, &image, &attestations).is_ok())
    }

    /// Whether `root` still owes kept image `image`, built under the root
    /// policy whose digest is `built_under`, its attestation (OF-469 upkeep
    /// retry): no attestation of it by `root` under that policy with `root`'s
    /// stored binding is kept, that policy is still this vault's own, and
    /// `root` is eligible under it. A policy the roster can no longer fix
    /// owes nothing, and neither does an image built under an older policy:
    /// the next image is built under the current one.
    pub(super) fn checkpoint_attestation_owed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: &AuthorityKey,
        image: [u8; 32],
        built_under: &[u8; 32],
    ) -> Result<bool> {
        let key = root_row_key(root);
        if let Some(stored) = ATTESTATIONS.get(&self.store, txn, &(image, key.clone()))?
            && stored.policy == *built_under
            && KEY_BINDINGS.get(&self.store, txn, &key)?.as_ref()
                == Some(&stored.attestation.binding)
        {
            return Ok(false);
        }
        let Ok(context) = self.checkpoint_context_in_txn(txn) else {
            return Ok(false);
        };
        Ok(context.eligible(root).is_ok() && context.policy.digest()? == *built_under)
    }

    /// Certifies this install's checkpoint SLH-DSA key for `root`, which must
    /// be eligible under this vault's own root policy. `sign` makes the root's
    /// classical signature over the binding statement it is handed. Stores the
    /// binding, replacing the root's earlier one.
    pub fn checkpoint_key_binding(
        &self,
        root: &AuthorityKey,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<AuthorityCheckpointKeyBinding> {
        let signer = self.checkpoint_signer()?;
        let context = {
            let txn = self.store.env.read_txn()?;
            self.checkpoint_context_in_txn(&txn)?
        };
        context.eligible(root)?;
        let mut binding = AuthorityCheckpointKeyBinding {
            vault_id: context.vault_id,
            genesis: context.genesis,
            root: root.clone(),
            install: signer.install,
            slhdsa: signer.slhdsa,
            epoch: CHECKPOINT_KEY_EPOCH,
            signature: AuthoritySignature {
                suite: root.suite(),
                public_key: root.clone(),
                signature: Vec::new(),
            },
        };
        binding.signature.signature = sign(&binding.statement()?)?;
        binding.verify(root)?;
        let mut txn = self.store.env.write_txn()?;
        let now = self.checkpoint_context_in_txn(&txn)?;
        if now.vault_id != context.vault_id || now.genesis != context.genesis {
            return Err(attest_refused("the vault changed while the root signed"));
        }
        now.eligible(root)?;
        KEY_BINDINGS.put(&self.store, &mut txn, &root_row_key(root), &binding)?;
        txn.commit()?;
        Ok(binding)
    }

    /// `root` attests checkpoint image `image`: the root must be eligible and
    /// hold a stored binding of this install's checkpoint key. `sign` makes
    /// the root's classical signature over the transcript it is handed; this
    /// install makes the hash-based one. Stores the attestation; when the
    /// image's stored attestations first reach this vault's policy, it becomes
    /// the newest attested image.
    pub fn attest_authority_checkpoint(
        &self,
        image: [u8; 32],
        root: &AuthorityKey,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<AuthorityCheckpointAttestation> {
        let signer = self.checkpoint_signer()?;
        let (context, binding) = {
            let txn = self.store.env.read_txn()?;
            let context = self.checkpoint_context_in_txn(&txn)?;
            let binding = KEY_BINDINGS
                .get(&self.store, &txn, &root_row_key(root))?
                .ok_or_else(|| attest_refused("the root has certified no checkpoint key"))?;
            (context, binding)
        };
        context.eligible(root)?;
        if binding.install != signer.install
            || binding.slhdsa != signer.slhdsa
            || binding.vault_id != context.vault_id
            || binding.genesis != context.genesis
        {
            return Err(attest_refused(
                "the root's checkpoint key is bound to another install",
            ));
        }
        binding.verify(root)?;
        let policy = context.policy.digest()?;
        let transcript =
            attestation_transcript(context.vault_id, context.genesis, image, policy, &binding)?;
        let classical = AuthoritySignature {
            suite: root.suite(),
            public_key: root.clone(),
            signature: sign(&transcript)?,
        };
        if !verify_authority_signature(&classical, &transcript) {
            return Err(attest_refused(
                "the root's classical signature does not verify",
            ));
        }
        let (install, slhdsa, hash_based) = self.sign_authority_image(&transcript)?;
        if install != binding.install || slhdsa != binding.slhdsa {
            return Err(attest_refused(
                "this install's checkpoint key is not the bound one",
            ));
        }
        let attestation = AuthorityCheckpointAttestation {
            binding,
            classical,
            hash_based,
        };
        let key = root_row_key(root);
        let mut txn = self.store.env.write_txn()?;
        if self.checkpoint_context_in_txn(&txn)? != context
            || KEY_BINDINGS.get(&self.store, &txn, &key)?.as_ref() != Some(&attestation.binding)
        {
            return Err(Error::InvalidConfig(
                "the root policy or key binding changed while the root signed; attest again".into(),
            ));
        }
        let before = self.image_attested_in_txn(&txn, &context, image)?;
        ATTESTATIONS.put(
            &self.store,
            &mut txn,
            &(image, key),
            &StoredAttestation {
                policy,
                attestation: attestation.clone(),
            },
        )?;
        if !before && self.image_attested_in_txn(&txn, &context, image)? {
            ATTESTED_HEAD.put(&self.store, &mut txn, &(), &AttestedHead { image, policy })?;
        }
        txn.commit()?;
        Ok(attestation)
    }

    /// The host path: attests `image` with this engine's own host root key,
    /// which must be an eligible root (the managed host root, or the self-host
    /// box's root), certifying this install's checkpoint key for it first when
    /// no current binding exists.
    pub fn host_attest_authority_checkpoint(
        &self,
        issuer: &HostSlipIssuer,
        image: [u8; 32],
    ) -> Result<AuthorityCheckpointAttestation> {
        let root = issuer.public_key();
        let signer = self.checkpoint_signer()?;
        let stored = {
            let txn = self.store.env.read_txn()?;
            KEY_BINDINGS.get(&self.store, &txn, &root_row_key(&root))?
        };
        if !stored.is_some_and(|binding| {
            binding.install == signer.install && binding.slhdsa == signer.slhdsa
        }) {
            self.checkpoint_key_binding(&root, |statement| issuer.sign_checkpoint(statement))?;
        }
        self.attest_authority_checkpoint(image, &root, |transcript| {
            issuer.sign_checkpoint(transcript)
        })
    }

    /// The attestations stored for `image`, as their roots made them.
    pub fn authority_checkpoint_attestations(
        &self,
        image: &[u8; 32],
    ) -> Result<Vec<AuthorityCheckpointAttestation>> {
        let txn = self.store.env.read_txn()?;
        Ok(ATTESTATIONS
            .scan_from(&self.store, &txn, image)?
            .into_iter()
            .map(|(_, stored)| stored.attestation)
            .collect())
    }

    /// The pin a pairing with `challenge` hands a new device: the newest
    /// attested image, this vault's own policy and the stored bindings. `None`
    /// when no image reached quorum under the policy this vault fixes now.
    pub fn authority_checkpoint_pin(
        &self,
        challenge: [u8; 32],
    ) -> Result<Option<AuthorityCheckpointPin>> {
        let txn = self.store.env.read_txn()?;
        self.authority_checkpoint_pin_in_txn(&txn, challenge)
    }

    pub(super) fn authority_checkpoint_pin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        challenge: [u8; 32],
    ) -> Result<Option<AuthorityCheckpointPin>> {
        let Some(head) = ATTESTED_HEAD.get(&self.store, txn, &())? else {
            return Ok(None);
        };
        // A policy the roster can no longer fix pins nothing.
        let Ok(context) = self.checkpoint_context_in_txn(txn) else {
            return Ok(None);
        };
        if context.policy.digest()? != head.policy {
            return Ok(None);
        }
        let pin = self.checkpoint_pin_for_in_txn(txn, &context, head.image, challenge)?;
        let attestations = self.pinned_attestations_in_txn(txn, &pin)?;
        Ok(
            verify_authority_checkpoint_attestations(&pin, &head.image, &attestations)
                .is_ok()
                .then_some(pin),
        )
    }
}
