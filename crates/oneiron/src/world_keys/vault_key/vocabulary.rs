//! Vault-key wrap choices and caller-supplied unlock material.
//! The entry type is `VaultKeyUnlock`.
//! `super` owns held keys and forwards this public vocabulary.

use super::*;

/// Whether this vault has a data key, and whether this handle holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VaultKeyStatus {
    NoKey,
    Locked,
    Unlocked,
}

/// The WebAuthn PRF input (`prf.eval.first`) a passkey wrap's KEK is the output
/// at: `BLAKE3-derive_key("oneiron/vault-key-passkey-prf-input/v1", vault id ‖
/// credential)`. The vault and the credential name fix it, so a new host with
/// only a sealed artifact (whose head names both) asks the authenticator for
/// the output the wrap was sealed under. It is public; the secret is the
/// authenticator's.
pub fn passkey_prf_input(vault_id: &[u8; 32], credential: &str) -> Result<[u8; 32]> {
    check_name(credential)?;
    let mut hasher = blake3::Hasher::new_derive_key(PASSKEY_PRF_CONTEXT);
    hasher.update(vault_id);
    hasher.update(credential.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

/// The escrow recipient a 32-byte seed grows into: `HybridSecretKey::from_seed`
/// under the label `oneiron/vault-key-escrow-recipient/v1`. A recovery box keeps
/// and releases the seed alone; the wrap seals to the public half. An all-zero
/// seed is refused.
pub fn escrow_recipient(seed: &[u8; 32]) -> Result<HybridSecretKey> {
    HybridSecretKey::from_seed(seed, ESCROW_SEED_LABEL)
        .map_err(|_| refused("an escrow seed is 32 bytes, not all zero"))
}

/// One wrap to add to the held vault data key, with the secret it seals to.
pub enum NewVaultKeyWrap<'a> {
    /// This install's keystore.
    Device,
    /// The vault password, replacing an earlier one; Argon2id at `cost`, or
    /// RFC 9106's second recommended option.
    Password {
        password: &'a [u8],
        cost: Option<Argon2Cost>,
    },
    /// A passkey's PRF output at [`passkey_prf_input`], borrowed from the
    /// guard that wipes it (FIX 6334).
    Passkey {
        credential: &'a str,
        prf: &'a Zeroizing<[u8; 32]>,
    },
    /// A recovery or transfer public key.
    Escrow {
        label: &'a str,
        recipient: &'a HybridPublicKey,
    },
}

/// What unlocks the vault key a sealed artifact carries, on a host that may not
/// hold the vault: the secrets the unlock doors take.
pub enum VaultKeyUnlock<'a> {
    /// This install's keystore, holding the slot of one of the device wraps.
    Device(&'a dyn DeviceKeystore),
    Password(&'a [u8]),
    /// A passkey's PRF output, borrowed from the guard that wipes it (FIX
    /// 6334).
    Passkey {
        credential: &'a str,
        prf: &'a Zeroizing<[u8; 32]>,
    },
    Escrow {
        label: &'a str,
        secret: &'a HybridSecretKey,
    },
    /// An escrow capsule presented from outside the carried wraps: one a
    /// registry kept (CROSS-ARCH-0022 #ov-custody), opened with its
    /// recipient's released secret. It opens as escrow wrap `label` would,
    /// bound to the vault id, the wrap id and the key's commitment, so a
    /// capsule of another vault or key opens nothing. The artifact need not
    /// carry the wrap; a sealed vault admits it at open only while it holds
    /// that very capsule ([`unlock_page_seal`](crate::world_keys::unlock_page_seal)).
    EscrowCapsule {
        label: &'a str,
        capsule: &'a [u8],
        secret: &'a HybridSecretKey,
    },
    /// The data-key kit's pieces, two or one and the kit passphrase (FIX
    /// 5614): they rebuild the vault data key itself, bound to `vault_id`,
    /// the id the owner names, which must be the artifact's or the vault's.
    /// The key opens only as the one its commitment names; no wrap opens
    /// and none need be carried (`kit`).
    Kit {
        vault_id: [u8; 32],
        pieces: &'a [crate::recovery::KitPiece],
        passphrase: Option<&'a crate::recovery::KitPassphrase>,
    },
}
