//! Vault-key state shared by the [`vault_key`](self) children.
//!
//! Held-key state, wrap codecs and escrow tables moved out of the vault-key
//! root (FIX 10384): whole items, `pub(super)` visibility, no behaviour
//! change. The root re-exports every name so existing `super::X` paths keep
//! resolving.
use super::{
    Argon2Cost, Deserialize, Envelope, EscrowAddWarning, EscrowRetirement, HybridPublicKey, Kek,
    KeyHeaderLink, Named, OpenKey, OpenPolicy, Passphrase, Purpose, RecoveryPreset, Result,
    SealKey, SealParams, Serialize, SideTable, StoredWrap, SysRng, VaultDataKey, VaultKeyWrapKind,
    WrapType, Zeroizing, refused, seal, side_table,
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
/// One link of the vault's data-key chain per generation, keyed by the
/// generation as a zero-padded decimal string, so the keys sort by generation.
pub(super) const LINKS: SideTable<String, KeyHeaderLink, Named> =
    SideTable::new(&side_table::VAULT_KEY_LINK);

/// Whether a generation number is the first one, which a stored row leaves out.
fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VaultKeyState {
    pub(super) commitment: [u8; 32],
    pub(super) created_at: u64,
    /// The owner's recovery preset: which wraps the key may carry.
    pub(super) recovery: RecoveryPreset,
    /// The generation the commitment names. Left out at 0, so a vault that
    /// never started a new generation reads as it did before.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(super) generation: u32,
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
        (VaultKeyWrapKind::Sheet, WrapSecret::Kek(kek)) => SealKey::SymmetricKek(kek),
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

/// The derive-key context of a data-key link's KEK: the newer generation's key
/// seals the older one under it, old-under-new only.
pub(super) const LINK_CONTEXT: &str = "oneiron/vault-key-link/v1";

/// Seals `older` under a key derived from `newer` as link `generation`: an E0
/// envelope like [`seal_wrap`], but the KEK comes from the newer data key, the
/// key id names the older key, and the recipient names the link.
pub(super) fn seal_link(
    vault_id: &[u8; 32],
    newer: &VaultDataKey,
    older: &VaultDataKey,
    generation: u32,
) -> Result<KeyHeaderLink> {
    let kek = Kek::from_zeroizing(newer.derive(LINK_CONTEXT, vault_id));
    let previous = older.commitment(vault_id);
    let recipient = format!("vault-key-link:{generation}");
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::VaultDek,
        epoch: VAULT_KEY_EPOCH,
        key_id: &previous,
        recipient: recipient.as_bytes(),
        vault_id,
    };
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    payload.extend_from_slice(PAYLOAD_LABEL);
    payload.extend_from_slice(&older.guarded_bytes()[..]);
    let envelope = seal(&params, SealKey::SymmetricKek(&kek), &payload, &mut SysRng)
        .map_err(|_| refused("sealing the vault key link failed"))?;
    Ok(KeyHeaderLink {
        generation,
        previous,
        envelope: envelope.to_bytes(),
    })
}

/// Opens `link` with the newer generation's key. Refuses a link that does not
/// open under it, and one that opens to bytes its `previous` does not name.
pub(super) fn open_link(
    vault_id: &[u8; 32],
    newer: &VaultDataKey,
    link: &KeyHeaderLink,
) -> Result<VaultDataKey> {
    let kek = Kek::from_zeroizing(newer.derive(LINK_CONTEXT, vault_id));
    let recipient = format!("vault-key-link:{}", link.generation);
    let policy = OpenPolicy {
        purpose: Purpose::VaultDek,
        vault_id,
        recipient: recipient.as_bytes(),
        key_id: &link.previous,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: VAULT_KEY_EPOCH,
        argon2_max: ARGON2_MAX,
    };
    let envelope =
        Envelope::parse(&link.envelope).map_err(|_| refused("a data-key link is malformed"))?;
    let payload = envelope
        .open(OpenKey::SymmetricKek(&kek), &policy)
        .map_err(|_| refused("a data-key link does not open with this key"))?;
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(PAYLOAD_LABEL) {
        return Err(refused("a data-key link's payload is malformed"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&payload[PAYLOAD_LABEL.len()..]);
    let key = VaultDataKey::from_guarded(bytes);
    if key.commitment(vault_id) != link.previous {
        return Err(refused("a data-key link does not open to the key it names"));
    }
    Ok(key)
}

/// The earlier data keys `links` (newest first) reach from `current`, newest
/// first: link n opens with the current key, then each older link with the key
/// the one above it opened to. Refuses a gap, a repeat, or a link out of order.
pub(super) fn walk_links(
    vault_id: &[u8; 32],
    current: &VaultDataKey,
    links: &[KeyHeaderLink],
) -> Result<Vec<VaultDataKey>> {
    let mut earlier = Vec::with_capacity(links.len());
    let mut expected = links.first().map_or(0, |link| link.generation);
    for (index, link) in links.iter().enumerate() {
        if link.generation == 0 || link.generation != expected {
            return Err(refused("a data-key link is missing or out of order"));
        }
        let newer = if index == 0 {
            current
        } else {
            &earlier[index - 1]
        };
        earlier.push(open_link(vault_id, newer, link)?);
        expected = expected.saturating_sub(1);
    }
    Ok(earlier)
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
