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
#[doc(hidden)]
pub(super) use oneiron_records::world_keys::vault_key::state::{
    AEAD, ARGON2_MAX, KEM, PAYLOAD_LABEL, PAYLOAD_LEN, UnlockSecret, VAULT_KEY_EPOCH, check_name,
    open_wrap, presented_escrow, wrap_digest,
};

pub(super) const PASSKEY_PRF_CONTEXT: &str = "oneiron/vault-key-passkey-prf-input/v1";
pub(super) const ESCROW_SEED_LABEL: &[u8] = b"oneiron/vault-key-escrow-recipient/v1";
pub(super) const STATE: SideTable<(), VaultKeyState, Named> =
    SideTable::new(&side_table::VAULT_KEY_STATE);
pub(super) const WRAPS: SideTable<String, StoredWrap, Named> =
    SideTable::new(&side_table::VAULT_KEY_WRAP);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VaultKeyState {
    pub(super) commitment: [u8; 32],
    pub(super) created_at: u64,
}

/// A passkey's PRF output as a KEK: copied once from the caller's guard into
/// guarded storage (FIX 6048, FIX 6334). The output never travels as a
/// plain array; the caller's guard wipes it.
pub(super) fn passkey_kek(prf: &Zeroizing<[u8; 32]>) -> Kek {
    Kek::from_bytes_ref(prf)
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
