//! The checkpoint pin `NativeClient.pair` returns (OF-469, FIX 3376), lifted
//! whole from `oneiron::authority::AuthorityCheckpointPin`: the challenge,
//! vault, genesis and image it names, the root policy, and every root's key
//! binding. It is the trust input a later local replica adopts the vault's
//! checkpoint by, so nothing here narrows or drops a field: byte values cross
//! as lowercase hex, enums as their snake_case names, and an epoch past the
//! JS integer width refuses rather than wraps. Nothing on this surface stores
//! the pin; the caller keeps it beside the credential.

use napi_derive::napi;
use oneiron::authority::{
    AuthorityCheckpointKeyBinding, AuthorityCheckpointPin, AuthorityKey, AuthoritySignature,
    CheckpointPosture, CheckpointRoot, CheckpointRootPolicy,
};

use super::boundary::boundary_error;

/// One authority public key: its suite and its key bytes.
#[napi(object)]
pub struct NapiCheckpointPinKey {
    /// `ed25519` | `p256`.
    pub suite: String,
    /// Lowercase hex: 32 bytes for Ed25519, the compressed SEC1 point for
    /// P-256.
    pub key: String,
}

/// A root's classical signature over a key binding.
#[napi(object)]
pub struct NapiCheckpointPinSignature {
    /// `ed25519` | `p256`.
    pub suite: String,
    /// The key that verifies the signature.
    pub public_key: NapiCheckpointPinKey,
    /// The signature bytes, lowercase hex.
    pub signature: String,
}

/// One eligible root of the pinned policy.
#[napi(object)]
pub struct NapiCheckpointPinRoot {
    pub key: NapiCheckpointPinKey,
    /// `software` | `hardware` | `cloud_custodial`.
    pub tier: String,
    /// The managed host root, which managed mode requires.
    pub host: bool,
}

/// The eligible roots and the quorum a checkpoint needs from them.
#[napi(object)]
pub struct NapiCheckpointPinPolicy {
    /// `managed` | `relay` | `self_host`.
    pub posture: String,
    /// Ascending by key, one row per root.
    pub roots: Vec<NapiCheckpointPinRoot>,
    /// Distinct eligible roots that must attest.
    pub quorum: u32,
    /// One attesting root must be hardware-backed.
    pub hardware: bool,
}

/// An eligible root's certificate for its checkpoint SLH-DSA key.
#[napi(object)]
pub struct NapiCheckpointPinBinding {
    /// 32 bytes, lowercase hex.
    pub vault_id: String,
    /// The authority genesis entry hash, lowercase hex.
    pub genesis: String,
    pub root: NapiCheckpointPinKey,
    /// The install whose checkpoint signing seed holds the key: 16 bytes,
    /// lowercase hex.
    pub install: String,
    /// The SLH-DSA-SHA2-256s public key, lowercase hex.
    pub slhdsa: String,
    /// The crypto epoch the key signs at.
    pub epoch: i64,
    pub signature: NapiCheckpointPinSignature,
}

/// What a joining device trusts the vault's checkpoint by, fixed by the
/// pairing link: the exact image, the vault and its genesis, the eligible
/// roots and quorum, and each root's certified key.
#[napi(object)]
pub struct NapiCheckpointPin {
    /// The single-use pairing link's nonce, lowercase hex.
    pub challenge: String,
    /// 32 bytes, lowercase hex.
    pub vault_id: String,
    /// The authority genesis entry hash, lowercase hex.
    pub genesis: String,
    /// The pinned checkpoint image id, lowercase hex.
    pub checkpoint: String,
    pub policy: NapiCheckpointPinPolicy,
    /// Ascending by root key, one per root.
    pub bindings: Vec<NapiCheckpointPinBinding>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key_from_engine(key: &AuthorityKey) -> NapiCheckpointPinKey {
    let bytes = match key {
        AuthorityKey::Ed25519(bytes) => hex(bytes),
        AuthorityKey::P256(bytes) => hex(bytes),
    };
    NapiCheckpointPinKey {
        suite: key.suite().as_str().to_owned(),
        key: bytes,
    }
}

fn signature_from_engine(signature: &AuthoritySignature) -> NapiCheckpointPinSignature {
    NapiCheckpointPinSignature {
        suite: signature.suite.as_str().to_owned(),
        public_key: key_from_engine(&signature.public_key),
        signature: hex(&signature.signature),
    }
}

fn root_from_engine(root: &CheckpointRoot) -> NapiCheckpointPinRoot {
    NapiCheckpointPinRoot {
        key: key_from_engine(&root.key),
        tier: root.tier.as_str().to_owned(),
        host: root.host,
    }
}

fn policy_from_engine(policy: &CheckpointRootPolicy) -> NapiCheckpointPinPolicy {
    let posture = match policy.posture {
        CheckpointPosture::Managed => "managed",
        CheckpointPosture::Relay => "relay",
        CheckpointPosture::SelfHost => "self_host",
    };
    NapiCheckpointPinPolicy {
        posture: posture.to_owned(),
        roots: policy.roots.iter().map(root_from_engine).collect(),
        quorum: u32::from(policy.quorum),
        hardware: policy.hardware,
    }
}

fn binding_from_engine(
    binding: &AuthorityCheckpointKeyBinding,
) -> napi::Result<NapiCheckpointPinBinding> {
    let epoch = i64::try_from(binding.epoch).map_err(|_| {
        boundary_error("the checkpoint pin's key epoch does not fit a JS integer".to_owned())
    })?;
    Ok(NapiCheckpointPinBinding {
        vault_id: hex(&binding.vault_id),
        genesis: hex(&binding.genesis),
        root: key_from_engine(&binding.root),
        install: hex(&binding.install),
        slhdsa: hex(&binding.slhdsa),
        epoch,
        signature: signature_from_engine(&binding.signature),
    })
}

/// Lifts the pin `pair_pinned` returned, every field kept.
pub(super) fn pin_from_engine(pin: &AuthorityCheckpointPin) -> napi::Result<NapiCheckpointPin> {
    Ok(NapiCheckpointPin {
        challenge: hex(&pin.challenge),
        vault_id: hex(&pin.vault_id),
        genesis: hex(&pin.genesis),
        checkpoint: hex(&pin.checkpoint),
        policy: policy_from_engine(&pin.policy),
        bindings: pin
            .bindings
            .iter()
            .map(binding_from_engine)
            .collect::<napi::Result<_>>()?,
    })
}
