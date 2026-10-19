//! The checkpoint pin `pair` returns (OF-469, FIX 3376), lifted whole from
//! `oneiron::authority::AuthorityCheckpointPin`: the challenge, vault, genesis
//! and image it names, the root policy, and every root's key binding. It is
//! the trust input a later local replica adopts the vault's checkpoint by, so
//! no field is narrowed or dropped: byte values cross as `Vec<u8>` (generated
//! `Data`), enums as closed UniFFI enums, numerics at the engine's widths.
//! Nothing here stores the pin; the caller keeps it beside the credential.

use oneiron::authority::{
    AuthorityCheckpointKeyBinding, AuthorityCheckpointPin, AuthorityKey, AuthoritySignature,
    AuthoritySignatureSuite, AuthorityTier, CheckpointPosture, CheckpointRoot,
    CheckpointRootPolicy,
};

/// An authority key's signature suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CheckpointPinSuite {
    /// Ed25519, used by software-tier keys.
    Ed25519,
    /// P-256 ECDSA, used by hardware keys.
    P256,
}

/// One authority public key: its suite and its key bytes.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPinKey {
    /// The key's signature suite.
    pub suite: CheckpointPinSuite,
    /// 32 bytes for Ed25519; the compressed SEC1 point for P-256.
    pub key: Vec<u8>,
}

/// A root's classical signature over a key binding.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPinSignature {
    /// The signature's suite.
    pub suite: CheckpointPinSuite,
    /// The key that verifies the signature.
    pub public_key: CheckpointPinKey,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// An eligible root's assurance tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CheckpointPinTier {
    /// A software-held key.
    Software,
    /// A hardware-backed key.
    Hardware,
    /// An explicit custodial cloud key.
    CloudCustodial,
}

/// One eligible root of the pinned policy.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPinRoot {
    /// The root's key.
    pub key: CheckpointPinKey,
    /// The root's assurance tier.
    pub tier: CheckpointPinTier,
    /// The managed host root, which managed mode requires.
    pub host: bool,
}

/// The hosting mode a checkpoint policy was fixed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CheckpointPinPosture {
    /// Managed hosting: the managed host root attests.
    Managed,
    /// Relay: owner roots attest.
    Relay,
    /// Self-host: owner roots attest.
    SelfHost,
}

/// The eligible roots and the quorum a checkpoint needs from them.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPinPolicy {
    /// The hosting mode the policy was fixed under.
    pub posture: CheckpointPinPosture,
    /// Ascending by key, one row per root.
    pub roots: Vec<CheckpointPinRoot>,
    /// Distinct eligible roots that must attest.
    pub quorum: u8,
    /// One attesting root must be hardware-backed.
    pub hardware: bool,
    /// The owner selected these roots and this quorum (FIX 4883): no host
    /// root need attest.
    pub owner_selected: bool,
}

/// An eligible root's certificate for its checkpoint SLH-DSA key.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPinBinding {
    /// The vault id, 32 bytes.
    pub vault_id: Vec<u8>,
    /// The authority genesis entry hash, 32 bytes.
    pub genesis: Vec<u8>,
    /// The root the binding certifies a key for.
    pub root: CheckpointPinKey,
    /// The install whose checkpoint signing seed holds the key, 16 bytes.
    pub install: Vec<u8>,
    /// The SLH-DSA-SHA2-256s public key.
    pub slhdsa: Vec<u8>,
    /// The crypto epoch the key signs at.
    pub epoch: u64,
    /// The root's signature over every other field.
    pub signature: CheckpointPinSignature,
}

/// What a joining device trusts the vault's checkpoint by, fixed by the
/// pairing link: the exact image, the vault and its genesis, the eligible
/// roots and quorum, and each root's certified key.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPin {
    /// The single-use pairing link's nonce, 32 bytes.
    pub challenge: Vec<u8>,
    /// The vault id, 32 bytes.
    pub vault_id: Vec<u8>,
    /// The authority genesis entry hash, 32 bytes.
    pub genesis: Vec<u8>,
    /// The pinned checkpoint image id, 32 bytes.
    pub checkpoint: Vec<u8>,
    /// The eligible roots and quorum.
    pub policy: CheckpointPinPolicy,
    /// Ascending by root key, one per root.
    pub bindings: Vec<CheckpointPinBinding>,
}

impl From<AuthoritySignatureSuite> for CheckpointPinSuite {
    fn from(suite: AuthoritySignatureSuite) -> Self {
        match suite {
            AuthoritySignatureSuite::Ed25519 => Self::Ed25519,
            AuthoritySignatureSuite::P256 => Self::P256,
        }
    }
}

impl From<&AuthorityKey> for CheckpointPinKey {
    fn from(key: &AuthorityKey) -> Self {
        let bytes = match key {
            AuthorityKey::Ed25519(bytes) => bytes.to_vec(),
            AuthorityKey::P256(bytes) => bytes.clone(),
        };
        Self {
            suite: key.suite().into(),
            key: bytes,
        }
    }
}

impl From<&AuthoritySignature> for CheckpointPinSignature {
    fn from(signature: &AuthoritySignature) -> Self {
        Self {
            suite: signature.suite.into(),
            public_key: (&signature.public_key).into(),
            signature: signature.signature.clone(),
        }
    }
}

impl From<AuthorityTier> for CheckpointPinTier {
    fn from(tier: AuthorityTier) -> Self {
        match tier {
            AuthorityTier::Software => Self::Software,
            AuthorityTier::Hardware => Self::Hardware,
            AuthorityTier::CloudCustodial => Self::CloudCustodial,
        }
    }
}

impl From<&CheckpointRoot> for CheckpointPinRoot {
    fn from(root: &CheckpointRoot) -> Self {
        Self {
            key: (&root.key).into(),
            tier: root.tier.into(),
            host: root.host,
        }
    }
}

impl From<CheckpointPosture> for CheckpointPinPosture {
    fn from(posture: CheckpointPosture) -> Self {
        match posture {
            CheckpointPosture::Managed => Self::Managed,
            CheckpointPosture::Relay => Self::Relay,
            CheckpointPosture::SelfHost => Self::SelfHost,
        }
    }
}

impl From<&CheckpointRootPolicy> for CheckpointPinPolicy {
    fn from(policy: &CheckpointRootPolicy) -> Self {
        Self {
            posture: policy.posture.into(),
            roots: policy.roots.iter().map(CheckpointPinRoot::from).collect(),
            quorum: policy.quorum,
            hardware: policy.hardware,
            owner_selected: policy.owner_selected,
        }
    }
}

impl From<&AuthorityCheckpointKeyBinding> for CheckpointPinBinding {
    fn from(binding: &AuthorityCheckpointKeyBinding) -> Self {
        Self {
            vault_id: binding.vault_id.to_vec(),
            genesis: binding.genesis.to_vec(),
            root: (&binding.root).into(),
            install: binding.install.to_vec(),
            slhdsa: binding.slhdsa.clone(),
            epoch: binding.epoch,
            signature: (&binding.signature).into(),
        }
    }
}

impl From<&AuthorityCheckpointPin> for CheckpointPin {
    fn from(pin: &AuthorityCheckpointPin) -> Self {
        Self {
            challenge: pin.challenge.to_vec(),
            vault_id: pin.vault_id.to_vec(),
            genesis: pin.genesis.to_vec(),
            checkpoint: pin.checkpoint.to_vec(),
            policy: (&pin.policy).into(),
            bindings: pin
                .bindings
                .iter()
                .map(CheckpointPinBinding::from)
                .collect(),
        }
    }
}
