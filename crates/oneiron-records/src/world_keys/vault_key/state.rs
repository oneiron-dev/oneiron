//! Moved from `crates/oneiron/src/world_keys/vault_key/state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_crypto::Argon2Cost;
use oneiron_crypto::Envelope;
use oneiron_crypto::HybridSecretKey;
use oneiron_crypto::Kek;
use oneiron_crypto::OpenKey;
use oneiron_crypto::OpenPolicy;
use oneiron_crypto::Passphrase;
use oneiron_crypto::Purpose;
use oneiron_crypto::SuiteId;
use oneiron_crypto::backup::KeyHeaderWrap as StoredWrap;
use oneiron_crypto::backup::VaultKeyWrapInfo;
use oneiron_crypto::backup::VaultKeyWrapKind;
use oneiron_store::key_material::refused;
use oneiron_store::vault_page_seal::VaultDataKey;
use oneiron_store::vault_page_seal::WrapDigest;
use zeroize::Zeroizing;

pub const PAYLOAD_LABEL: &[u8] = b"oneiron/vault-dek/v1\0";

pub const PAYLOAD_LEN: usize = PAYLOAD_LABEL.len() + 32;

pub const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;

pub const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;

/// The crypto epoch every vault-key envelope is sealed at.
pub const VAULT_KEY_EPOCH: u64 = 1;

/// The most Argon2id work an unlock will do for a password wrap.
pub const ARGON2_MAX: Argon2Cost = Argon2Cost {
    m_kib: Argon2Cost::MAX_M_KIB,
    t: Argon2Cost::MAX_T,
    p: Argon2Cost::MAX_P,
};

/// A stored wrap's digest: its id and its envelope's BLAKE3.
pub fn wrap_digest(stored: &StoredWrap) -> WrapDigest {
    WrapDigest::new(
        stored.info.id.clone(),
        *blake3::hash(&stored.envelope).as_bytes(),
    )
}

/// An escrow capsule presented from outside the vault's wraps, filed as
/// escrow wrap `label` would be, so it opens under that wrap's id. None
/// of it is stored, so it names no time.
pub fn presented_escrow(label: &str, capsule: &[u8]) -> Result<StoredWrap> {
    check_name(label)?;
    let kind = VaultKeyWrapKind::Escrow {
        label: label.to_owned(),
    };
    Ok(StoredWrap {
        info: VaultKeyWrapInfo {
            id: kind.id(),
            kind,
            created_at: 0,
        },
        envelope: capsule.to_vec(),
    })
}

/// A host-chosen name inside a wrap id: 1 to 64 of `A-Z a-z 0-9 . _ -`.
pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(refused(
            "a wrap name is 1 to 64 letters, digits, dots, dashes or underscores",
        ))
    }
}

/// What unlocks one wrap.
pub enum UnlockSecret<'a> {
    Kek(Kek),
    Passphrase(&'a Passphrase),
    Hybrid(&'a HybridSecretKey),
}

pub fn open_wrap(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    stored: &StoredWrap,
    secret: &UnlockSecret<'_>,
) -> Result<VaultDataKey> {
    let id = stored.info.kind.id();
    if id != stored.info.id {
        return Err(refused("a vault key wrap is filed under another id"));
    }
    let policy = OpenPolicy {
        purpose: Purpose::VaultDek,
        vault_id,
        recipient: id.as_bytes(),
        key_id: commitment,
        wraps: &[stored.info.kind.wrap_type()],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: VAULT_KEY_EPOCH,
        argon2_max: ARGON2_MAX,
    };
    let open_key = match (&stored.info.kind, secret) {
        (VaultKeyWrapKind::Device { .. }, UnlockSecret::Kek(kek)) => OpenKey::DeviceKeystore(kek),
        (VaultKeyWrapKind::Passkey { .. }, UnlockSecret::Kek(kek)) => OpenKey::Passkey(kek),
        (VaultKeyWrapKind::Password, UnlockSecret::Passphrase(passphrase)) => {
            OpenKey::Passphrase(passphrase)
        }
        (VaultKeyWrapKind::Escrow { .. }, UnlockSecret::Hybrid(secret)) => OpenKey::Hybrid(secret),
        _ => return Err(refused("the secret does not fit the wrap")),
    };
    let envelope =
        Envelope::parse(&stored.envelope).map_err(|_| refused("a vault key wrap is malformed"))?;
    let payload = envelope
        .open(open_key, &policy)
        .map_err(|_| refused("the vault key wrap does not open with this secret"))?;
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(PAYLOAD_LABEL) {
        return Err(refused("the vault key wrap's payload is malformed"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&payload[PAYLOAD_LABEL.len()..]);
    let key = VaultDataKey::from_guarded(bytes);
    if key.commitment(vault_id) != *commitment {
        return Err(refused("the vault key wrap opens to another key"));
    }
    Ok(key)
}
