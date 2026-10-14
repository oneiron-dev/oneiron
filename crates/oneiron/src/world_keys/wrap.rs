//! One world key sealed to one recipient, and opened back with the recipient's secret.
//!
//! Before any key derivation, the envelope header must match the reader's own binding:
//! purpose `WorldDek`, the vault, `key_id` = world ‖ generation ‖ mint, the recipient,
//! the AEAD and KEM suites, and the epoch. The plaintext repeats the owner and the
//! policy revision. Those two, and the key's commitment, are compared after the AEAD
//! and before the key is returned.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, OpenKey, OpenPolicy, Purpose, SealKey,
    SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::{WORLD_KEY_EPOCH, WorldKey, WorldKeyBinding, WrapRecipient, base_world, refused};
use crate::error::Result;

const PAYLOAD_LABEL: &[u8] = b"oneiron/world-key/v1\0";
const PAYLOAD_LEN: usize = PAYLOAD_LABEL.len() + 16 + 32 + 32;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// Seals `key` to `recipient`'s public key under `binding`. The binding must name
/// this key, and never base reality.
pub fn seal_world_key(
    binding: &WorldKeyBinding,
    recipient: WrapRecipient,
    public: &HybridPublicKey,
    key: &WorldKey,
) -> Result<Envelope> {
    if binding.key.world == base_world() {
        return Err(refused("base reality has no world key"));
    }
    if binding.key != key.id || binding.commitment != key.commitment() {
        return Err(refused("the binding names another key"));
    }
    let key_id = binding.key.envelope_key_id();
    let to = recipient.envelope_recipient();
    let payload = world_key_payload(binding, key);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::WorldDek,
        epoch: WORLD_KEY_EPOCH,
        key_id: &key_id,
        recipient: &to,
        vault_id: &binding.vault_id,
    };
    seal(
        &params,
        SealKey::Hybrid {
            recipient: public,
            kem_suite: KEM,
        },
        &payload,
        &mut SysRng,
    )
    .map_err(|_| refused("sealing failed"))
}

/// The plaintext a wrap of `key` under `binding` seals.
pub(super) fn world_key_payload(binding: &WorldKeyBinding, key: &WorldKey) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    payload.extend_from_slice(PAYLOAD_LABEL);
    payload.extend_from_slice(binding.owner.as_bytes());
    payload.extend_from_slice(&binding.policy.0);
    payload.extend_from_slice(key.expose());
    payload
}

/// Opens `envelope` with `recipient`'s secret, refusing any envelope not made for
/// exactly `binding` and `recipient`, and any binding that names base reality.
pub fn open_world_key(
    binding: &WorldKeyBinding,
    recipient: WrapRecipient,
    secret: &HybridSecretKey,
    envelope: &Envelope,
) -> Result<WorldKey> {
    if binding.key.world == base_world() {
        return Err(refused("base reality has no world key"));
    }
    let key_id = binding.key.envelope_key_id();
    let to = recipient.envelope_recipient();
    let policy = OpenPolicy {
        purpose: Purpose::WorldDek,
        vault_id: &binding.vault_id,
        recipient: &to,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let payload = envelope
        .open(OpenKey::Hybrid(secret), &policy)
        .map_err(|_| refused("the wrap does not open for this binding and recipient"))?;
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(PAYLOAD_LABEL) {
        return Err(refused("the wrap's payload is malformed"));
    }
    let body = &payload[PAYLOAD_LABEL.len()..];
    if body[..16] != binding.owner.as_bytes()[..] || body[16..48] != binding.policy.0[..] {
        return Err(refused("the wrap names another owner or policy"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&body[48..]);
    let key = WorldKey {
        id: binding.key,
        bytes,
    };
    if key.commitment() != binding.commitment {
        return Err(refused("the wrap opens to other key bytes"));
    }
    Ok(key)
}
