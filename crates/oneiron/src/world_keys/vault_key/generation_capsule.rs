//! One data-key generation sealed to one machine, and opened back.
//!
//! Before any key derivation, the envelope header must match the reader's own
//! binding: purpose `DataKeyGeneration`, the vault, `key_id` = vault ‖
//! generation ‖ commitment, the recipient, the AEAD and KEM suites, and the
//! epoch. The plaintext repeats the commitment. That, and the opened key's
//! own commitment, are compared after the AEAD and before the key is
//! returned. There is no pad: the plaintext holds the key whole.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, OpenKey, OpenPolicy, Purpose, SealKey,
    SealParams, SuiteId, WrapType, seal,
};
use zeroize::Zeroizing;

use super::{VaultDataKey, refused};
use crate::entity_id::EntityId;
use crate::error::Result;

const PAYLOAD_LABEL: &[u8] = oneiron_authority::authority::DATA_KEY_GENERATION_PAYLOAD_LABEL;
const PAYLOAD_LEN: usize = oneiron_authority::authority::DATA_KEY_GENERATION_PAYLOAD_LEN;
const EPOCH: u64 = oneiron_authority::authority::DATA_KEY_GENERATION_EPOCH;
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// Everything a capsule is bound to. A reader states it from its own records;
/// the envelope's claims are never the expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataKeyGenerationBinding {
    /// The authority vault, as the carrying entry names it.
    pub(crate) vault_id: [u8; 32],
    /// The store vault, the commitment's domain.
    pub(crate) data_vault_id: [u8; 32],
    /// The generation the capsule delivers.
    pub(crate) generation: u32,
    /// The commitment naming the delivered key.
    pub(crate) commitment: [u8; 32],
}

impl DataKeyGenerationBinding {
    /// The envelope `key_id`: vault (32) ‖ generation (4, big-endian) ‖
    /// commitment (32). The same bytes as
    /// `DataKeyGenerationRecord::envelope_key_id`.
    fn envelope_key_id(&self) -> [u8; 68] {
        let mut out = [0u8; 68];
        out[..32].copy_from_slice(&self.vault_id);
        out[32..36].copy_from_slice(&self.generation.to_be_bytes());
        out[36..].copy_from_slice(&self.commitment);
        out
    }
}

/// Seals `key` to `machine`'s public key under `binding`. The binding must
/// name this key.
pub(crate) fn seal_data_key_capsule(
    binding: &DataKeyGenerationBinding,
    machine: EntityId,
    public: &HybridPublicKey,
    key: &VaultDataKey,
) -> Result<Envelope> {
    if binding.generation == 0 || key.commitment(&binding.data_vault_id) != binding.commitment {
        return Err(refused("the binding names another key"));
    }
    let key_id = binding.envelope_key_id();
    let to = oneiron_authority::authority::capsule_recipient(&machine);
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    payload.extend_from_slice(PAYLOAD_LABEL);
    payload.extend_from_slice(&binding.commitment);
    payload.extend_from_slice(&key.guarded_bytes()[..]);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::DataKeyGeneration,
        epoch: EPOCH,
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

/// Opens `envelope` with `machine`'s secret, refusing any envelope not made
/// for exactly `binding` and `machine`, and any envelope that opens to bytes
/// the binding's commitment does not name.
pub(crate) fn open_data_key_capsule(
    binding: &DataKeyGenerationBinding,
    machine: EntityId,
    secret: &HybridSecretKey,
    envelope: &Envelope,
) -> Result<VaultDataKey> {
    if binding.generation == 0 {
        return Err(refused("no data-key generation is numbered zero"));
    }
    let key_id = binding.envelope_key_id();
    let to = oneiron_authority::authority::capsule_recipient(&machine);
    let policy = OpenPolicy {
        purpose: Purpose::DataKeyGeneration,
        vault_id: &binding.vault_id,
        recipient: &to,
        key_id: &key_id,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let payload = envelope
        .open(OpenKey::Hybrid(secret), &policy)
        .map_err(|_| refused("the capsule does not open for this binding and recipient"))?;
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(PAYLOAD_LABEL) {
        return Err(refused("the capsule's payload is malformed"));
    }
    let body = &payload[PAYLOAD_LABEL.len()..];
    if body[..32] != binding.commitment[..] {
        return Err(refused("the capsule names another commitment"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&body[32..]);
    let key = VaultDataKey::from_guarded(bytes);
    if key.commitment(&binding.data_vault_id) != binding.commitment {
        return Err(refused("the capsule opens to other key bytes"));
    }
    Ok(key)
}
