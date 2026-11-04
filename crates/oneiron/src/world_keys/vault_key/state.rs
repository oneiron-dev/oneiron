//! Vault-key state shared by the [`vault_key`](self) children.
//!
//! Held-key state, wrap codecs and escrow tables moved out of the vault-key
//! root (FIX 10384): whole items, `pub(super)` visibility, no behaviour
//! change. The root re-exports every name so existing `super::X` paths keep
//! resolving.
use super::{
    Argon2Cost, Deserialize, DeviceKeystore, Envelope, EscrowAddWarning, EscrowRetirement,
    HybridPublicKey, HybridSecretKey, Kek, Named, OpenKey, OpenPolicy, Passphrase, Purpose, Result,
    SealKey, SealParams, Serialize, SideTable, StoredWrap, SuiteId, SysRng, VaultDataKey,
    VaultKeyWrapInfo, VaultKeyWrapKind, WrapDigest, Zeroizing, refused, seal, side_table,
};
pub(super) const PAYLOAD_LABEL: &[u8] = b"oneiron/vault-dek/v1\0";
pub(super) const PAYLOAD_LEN: usize = PAYLOAD_LABEL.len() + 32;
pub(super) const PASSKEY_PRF_CONTEXT: &str = "oneiron/vault-key-passkey-prf-input/v1";
pub(super) const ESCROW_SEED_LABEL: &[u8] = b"oneiron/vault-key-escrow-recipient/v1";
pub(super) const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
pub(super) const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The crypto epoch every vault-key envelope is sealed at.
pub(super) const VAULT_KEY_EPOCH: u64 = 1;
/// The most Argon2id work an unlock will do for a password wrap.
pub(super) const ARGON2_MAX: Argon2Cost = Argon2Cost {
    m_kib: Argon2Cost::MAX_M_KIB,
    t: Argon2Cost::MAX_T,
    p: Argon2Cost::MAX_P,
};

pub(super) const STATE: SideTable<(), VaultKeyState, Named> =
    SideTable::new(&side_table::VAULT_KEY_STATE);
pub(super) const WRAPS: SideTable<String, StoredWrap, Named> =
    SideTable::new(&side_table::VAULT_KEY_WRAP);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VaultKeyState {
    pub(super) commitment: [u8; 32],
    pub(super) created_at: u64,
}

/// A stored wrap's digest: its id and its envelope's BLAKE3.
pub(super) fn wrap_digest(stored: &StoredWrap) -> WrapDigest {
    WrapDigest::new(
        stored.info.id.clone(),
        *blake3::hash(&stored.envelope).as_bytes(),
    )
}
/// An escrow capsule presented from outside the vault's wraps, filed as
/// escrow wrap `label` would be, so it opens under that wrap's id. None
/// of it is stored, so it names no time.
pub(super) fn presented_escrow(label: &str, capsule: &[u8]) -> Result<StoredWrap> {
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
/// A passkey's PRF output as a KEK: copied once from the caller's guard into
/// guarded storage (FIX 6048, FIX 6334). The output never travels as a
/// plain array; the caller's guard wipes it.
pub(super) fn passkey_kek(prf: &Zeroizing<[u8; 32]>) -> Kek {
    Kek::from_bytes_ref(prf)
}

/// A host-chosen name inside a wrap id: 1 to 64 of `A-Z a-z 0-9 . _ -`.
pub(super) fn check_name(name: &str) -> Result<()> {
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
pub(super) enum UnlockSecret<'a> {
    Kek(Kek),
    Passphrase(&'a Passphrase),
    Hybrid(&'a HybridSecretKey),
}

/// What seals one new wrap.
pub(super) enum WrapSecret<'a> {
    Kek(Kek),
    Passphrase(&'a Passphrase, Argon2Cost),
    Hybrid(&'a HybridPublicKey),
}

pub(super) fn seal_wrap(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    kind: &VaultKeyWrapKind,
    secret: &WrapSecret<'_>,
    key: &VaultDataKey,
) -> Result<Vec<u8>> {
    let id = kind.id();
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::VaultDek,
        epoch: VAULT_KEY_EPOCH,
        key_id: commitment,
        recipient: id.as_bytes(),
        vault_id,
    };
    let seal_key = match (kind, secret) {
        (VaultKeyWrapKind::Device { .. }, WrapSecret::Kek(kek)) => SealKey::DeviceKeystore(kek),
        (VaultKeyWrapKind::Passkey { .. }, WrapSecret::Kek(kek)) => SealKey::Passkey(kek),
        (VaultKeyWrapKind::Password, WrapSecret::Passphrase(passphrase, cost)) => {
            SealKey::Passphrase {
                passphrase,
                cost: *cost,
            }
        }
        (VaultKeyWrapKind::Escrow { .. }, WrapSecret::Hybrid(recipient)) => SealKey::Hybrid {
            recipient,
            kem_suite: KEM,
        },
        _ => return Err(refused("the secret does not fit the wrap")),
    };
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    payload.extend_from_slice(PAYLOAD_LABEL);
    payload.extend_from_slice(&key.guarded_bytes()[..]);
    let envelope = seal(&params, seal_key, &payload, &mut SysRng)
        .map_err(|_| refused("sealing the vault key failed"))?;
    Ok(envelope.to_bytes())
}

pub(super) fn open_wrap(
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
/// Which escrow capsule each escrow wrap last handed to the host's outbound
/// spool, by the blake3 of its envelope.
pub(super) const ESCROW_SPOOLED: SideTable<String, [u8; 32], Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_SPOOLED);

/// The escrow labels retired after their recipients were released, by label.
pub(super) const ESCROW_RETIRED: SideTable<String, EscrowRetirement, Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_RETIRED);

/// The fingerprint of the recipient each escrow label was sealed to, kept
/// once the label retires, so a later add of the same key under another
/// label warns (FIX 2857). Public facts only.
pub(super) const ESCROW_RECIPIENT: SideTable<String, [u8; 32], Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_RECIPIENT);

/// An escrow recipient's fingerprint: the BLAKE3 of its public key's wire
/// form, as a managed label and a restore's recipient facts name it.
pub(super) fn recipient_fingerprint(recipient: &HybridPublicKey) -> [u8; 32] {
    *blake3::hash(&recipient.to_bytes()).as_bytes()
}

/// Logs what an escrow add warned of, by label only.
pub(super) fn log_escrow_warnings(label: &str, warnings: &[EscrowAddWarning]) {
    for warning in warnings {
        let EscrowAddWarning::RetiredRecipient { retired_label } = warning;
        tracing::warn!(
            label,
            retired_label = %retired_label,
            "an escrow wrap was sealed to a recipient released and retired under another label"
        );
    }
}
