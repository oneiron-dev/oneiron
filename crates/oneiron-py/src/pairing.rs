//! What the native `pair` hands the Python wrapper (OF-469, FIX 3376): the
//! origin, the credential, the credential's comm reach (FIX 5058) and the
//! checkpoint pin the link named, lifted whole
//! from `oneiron::authority::AuthorityCheckpointPin`. The pin is the trust
//! input a later local replica adopts the vault's checkpoint by, so no field
//! is narrowed or dropped: byte values cross as lowercase hex and enums as
//! their snake_case names, the shape `CheckpointPin` in `__init__.pyi`
//! declares. Nothing here stores the pin; the caller keeps it beside the
//! credential.

use oneiron::authority::{
    AuthorityCheckpointKeyBinding, AuthorityCheckpointPin, AuthorityKey, AuthoritySignature,
    CheckpointPosture, CheckpointRoot, CheckpointRootPolicy, CommReach,
};
use serde::Serialize;

/// The private pairing result; `Oneiron.pair` connects with its url and
/// credential and returns the credential, pin and comm reach.
#[derive(Serialize)]
pub(crate) struct Paired {
    url: String,
    credential: String,
    pin: Option<CheckpointPin>,
    /// Whom the paired credential may address, as the server took it.
    comm: CommReach,
}

impl Paired {
    /// The result of `OneironClient::pair_pinned`, pin lifted.
    pub(crate) fn from_engine(
        (url, credential, pin, comm): (String, String, Option<AuthorityCheckpointPin>, CommReach),
    ) -> Self {
        Self {
            url,
            credential,
            pin: pin.as_ref().map(CheckpointPin::from_engine),
            comm,
        }
    }
}

#[derive(Serialize)]
struct CheckpointPinKey {
    suite: &'static str,
    key: String,
}

#[derive(Serialize)]
struct CheckpointPinSignature {
    suite: &'static str,
    public_key: CheckpointPinKey,
    signature: String,
}

#[derive(Serialize)]
struct CheckpointPinRoot {
    key: CheckpointPinKey,
    tier: &'static str,
    host: bool,
}

#[derive(Serialize)]
struct CheckpointPinPolicy {
    posture: &'static str,
    roots: Vec<CheckpointPinRoot>,
    quorum: u8,
    hardware: bool,
    /// The owner selected these roots and this quorum (FIX 4883).
    owner_selected: bool,
}

#[derive(Serialize)]
struct CheckpointPinBinding {
    vault_id: String,
    genesis: String,
    root: CheckpointPinKey,
    install: String,
    slhdsa: String,
    epoch: u64,
    signature: CheckpointPinSignature,
}

#[derive(Serialize)]
struct CheckpointPin {
    challenge: String,
    vault_id: String,
    genesis: String,
    checkpoint: String,
    policy: CheckpointPinPolicy,
    bindings: Vec<CheckpointPinBinding>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl CheckpointPinKey {
    fn from_engine(key: &AuthorityKey) -> Self {
        let bytes = match key {
            AuthorityKey::Ed25519(bytes) => hex(bytes),
            AuthorityKey::P256(bytes) => hex(bytes),
        };
        Self {
            suite: key.suite().as_str(),
            key: bytes,
        }
    }
}

impl CheckpointPinSignature {
    fn from_engine(signature: &AuthoritySignature) -> Self {
        Self {
            suite: signature.suite.as_str(),
            public_key: CheckpointPinKey::from_engine(&signature.public_key),
            signature: hex(&signature.signature),
        }
    }
}

impl CheckpointPinRoot {
    fn from_engine(root: &CheckpointRoot) -> Self {
        Self {
            key: CheckpointPinKey::from_engine(&root.key),
            tier: root.tier.as_str(),
            host: root.host,
        }
    }
}

impl CheckpointPinPolicy {
    fn from_engine(policy: &CheckpointRootPolicy) -> Self {
        Self {
            posture: match policy.posture {
                CheckpointPosture::Managed => "managed",
                CheckpointPosture::Relay => "relay",
                CheckpointPosture::SelfHost => "self_host",
            },
            roots: policy
                .roots
                .iter()
                .map(CheckpointPinRoot::from_engine)
                .collect(),
            quorum: policy.quorum,
            hardware: policy.hardware,
            owner_selected: policy.owner_selected,
        }
    }
}

impl CheckpointPinBinding {
    fn from_engine(binding: &AuthorityCheckpointKeyBinding) -> Self {
        Self {
            vault_id: hex(&binding.vault_id),
            genesis: hex(&binding.genesis),
            root: CheckpointPinKey::from_engine(&binding.root),
            install: hex(&binding.install),
            slhdsa: hex(&binding.slhdsa),
            epoch: binding.epoch,
            signature: CheckpointPinSignature::from_engine(&binding.signature),
        }
    }
}

impl CheckpointPin {
    fn from_engine(pin: &AuthorityCheckpointPin) -> Self {
        Self {
            challenge: hex(&pin.challenge),
            vault_id: hex(&pin.vault_id),
            genesis: hex(&pin.genesis),
            checkpoint: hex(&pin.checkpoint),
            policy: CheckpointPinPolicy::from_engine(&pin.policy),
            bindings: pin
                .bindings
                .iter()
                .map(CheckpointPinBinding::from_engine)
                .collect(),
        }
    }
}
