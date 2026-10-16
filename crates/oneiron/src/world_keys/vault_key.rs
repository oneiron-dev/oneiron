//! The vault data key and the wraps that unlock it (OF-570 E1).
//!
//! A vault has one data key: 32 random bytes, the root that the vault's sealed
//! artifacts derive their own keys from (a checkpoint's sealing key, a custody
//! head's). It never rests in the clear. Each way to unlock it is one E0 envelope,
//! purpose `VaultDek`, and the daily ones wrap it symmetrically, so no public-key
//! step sits on that path:
//! - this device: a this-device-only keystore slot (`VaultUnlock`) holds the KEK;
//! - a vault password: Argon2id over the passphrase;
//! - a passkey: the host hands in the WebAuthn PRF output as the KEK;
//! - escrow: a hybrid capsule (X25519 + ML-KEM-1024) to a recovery or transfer
//!   key, the one wrap that crosses a public-key boundary.
//!
//! The wraps and a commitment to the key live in `vault_meta`; the key itself
//! lives only in this handle's memory once unlocked. A wrap that opens to bytes
//! the commitment does not name is refused. Which wraps a vault keeps is the
//! owner's choice; the engine refuses to drop the last one. The data key unlocks
//! no private world: those keys live apart (`world_keys`).

use std::sync::{Arc, PoisonError};

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Passphrase,
    Purpose, SealKey, SealParams, SuiteId, WrapType, seal,
};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{os_fill, refused};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

const PAYLOAD_LABEL: &[u8] = b"oneiron/vault-dek/v1\0";
const PAYLOAD_LEN: usize = PAYLOAD_LABEL.len() + 32;
const COMMITMENT_CONTEXT: &str = "oneiron/vault-key-commitment/v1";
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The crypto epoch every vault-key envelope is sealed at.
const VAULT_KEY_EPOCH: u64 = 1;
/// The most Argon2id work an unlock will do for a password wrap.
const ARGON2_MAX: Argon2Cost = Argon2Cost {
    m_kib: Argon2Cost::MAX_M_KIB,
    t: Argon2Cost::MAX_T,
    p: Argon2Cost::MAX_P,
};

const STATE: SideTable<(), VaultKeyState, Named> = SideTable::new(&side_table::VAULT_KEY_STATE);
const WRAPS: SideTable<String, StoredWrap, Named> = SideTable::new(&side_table::VAULT_KEY_WRAP);

/// The unlocked vault data key. No `Clone`, no `Serialize`, a `Debug` that
/// prints nothing, and its bytes are wiped on drop.
pub(crate) struct VaultDataKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for VaultDataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultDataKey(..)")
    }
}

impl VaultDataKey {
    fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    /// `BLAKE3-derive_key("oneiron/vault-key-commitment/v1", vault id ‖ key)`: it
    /// pins which bytes are this vault's key and reveals nothing about them.
    fn commitment(&self, vault_id: &[u8; 32]) -> [u8; 32] {
        self.derive(COMMITMENT_CONTEXT, vault_id)
    }

    /// A key of its own for one use, `BLAKE3-derive_key(context, vault id ‖ key)`.
    fn derive(&self, context: &str, vault_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(vault_id);
        hasher.update(&self.0[..]);
        let out = *hasher.finalize().as_bytes();
        zeroize::Zeroize::zeroize(&mut hasher);
        out
    }
}

/// How one wrap unlocks the vault data key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultKeyWrapKind {
    /// This device's keystore slot, for the install named as hex.
    Device { install: String },
    /// The vault password.
    Password,
    /// One passkey, by the host's credential id.
    Passkey { credential: String },
    /// A hybrid capsule to a recovery or transfer key, by the owner's label.
    Escrow { label: String },
}

impl VaultKeyWrapKind {
    /// The wrap's id: one wrap per device, per passkey and per escrow label, and
    /// one password.
    fn id(&self) -> String {
        match self {
            Self::Device { install } => format!("device:{install}"),
            Self::Password => "password".to_owned(),
            Self::Passkey { credential } => format!("passkey:{credential}"),
            Self::Escrow { label } => format!("escrow:{label}"),
        }
    }

    fn wrap_type(&self) -> WrapType {
        match self {
            Self::Device { .. } => WrapType::DeviceKeystore,
            Self::Password => WrapType::Passphrase,
            Self::Passkey { .. } => WrapType::Passkey,
            Self::Escrow { .. } => WrapType::HybridCapsule,
        }
    }
}

/// One wrap's public facts: never the envelope, never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyWrapInfo {
    pub id: String,
    pub kind: VaultKeyWrapKind,
    /// The vault clock, in seconds, when the wrap was added.
    pub created_at: u64,
}

/// Whether this vault has a data key, and whether this handle holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKeyStatus {
    NoKey,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultKeyState {
    commitment: [u8; 32],
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredWrap {
    info: VaultKeyWrapInfo,
    envelope: Vec<u8>,
}

/// A host-chosen name inside a wrap id: 1 to 64 of `A-Z a-z 0-9 . _ -`.
fn check_name(name: &str) -> Result<()> {
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

/// What unlocks the vault key a sealed artifact carries, on a host that may not
/// hold the vault: the secrets the unlock doors take.
pub enum VaultKeyUnlock<'a> {
    /// This install's keystore, holding the slot of one of the device wraps.
    Device(&'a dyn DeviceKeystore),
    Password(&'a [u8]),
    Passkey {
        credential: &'a str,
        prf: [u8; 32],
    },
    Escrow {
        label: &'a str,
        secret: &'a HybridSecretKey,
    },
}

/// The vault key as it rests: its commitment and every wrap's sealed envelope,
/// never the key. A sealed artifact carries it in the clear, so a host without
/// the vault can unlock the artifact's key from one of the wraps.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedVaultKey {
    commitment: [u8; 32],
    wraps: Vec<StoredWrap>,
}

impl CarriedVaultKey {
    /// The commitment naming the vault key.
    pub(crate) fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// The key for `context` of the vault key a carried wrap opens to under
    /// `unlock`.
    pub(crate) fn subkey(
        &self,
        vault_id: &[u8; 32],
        unlock: &VaultKeyUnlock<'_>,
        context: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let key = self.open(vault_id, unlock)?;
        Ok(Zeroizing::new(key.derive(context, vault_id)))
    }

    fn open(&self, vault_id: &[u8; 32], unlock: &VaultKeyUnlock<'_>) -> Result<VaultDataKey> {
        let wrap = |kind: VaultKeyWrapKind| {
            let id = kind.id();
            self.wraps
                .iter()
                .find(|stored| stored.info.id == id)
                .ok_or_else(|| refused("the vault key has no such wrap"))
        };
        match unlock {
            VaultKeyUnlock::Device(keystore) => {
                for stored in &self.wraps {
                    let VaultKeyWrapKind::Device { install } = &stored.info.kind else {
                        continue;
                    };
                    let Ok(install) = crate::EntityId::from_hex(install) else {
                        continue;
                    };
                    let slot = KeystoreSlot {
                        vault_id: *vault_id,
                        install: *install.as_bytes(),
                        kind: SlotKind::VaultUnlock,
                    };
                    let Some(seed) = keystore
                        .get(&slot)
                        .map_err(super::machine::keystore_error)?
                    else {
                        continue;
                    };
                    return open_wrap(
                        vault_id,
                        &self.commitment,
                        stored,
                        &UnlockSecret::Kek(Kek::from_bytes(*seed)),
                    );
                }
                Err(refused(
                    "this keystore holds no device wrap of the vault key",
                ))
            }
            VaultKeyUnlock::Password(password) => {
                let passphrase = Passphrase::new(password)
                    .map_err(|_| refused("the password is not accepted"))?;
                open_wrap(
                    vault_id,
                    &self.commitment,
                    wrap(VaultKeyWrapKind::Password)?,
                    &UnlockSecret::Passphrase(&passphrase),
                )
            }
            VaultKeyUnlock::Passkey { credential, prf } => {
                check_name(credential)?;
                open_wrap(
                    vault_id,
                    &self.commitment,
                    wrap(VaultKeyWrapKind::Passkey {
                        credential: (*credential).to_owned(),
                    })?,
                    &UnlockSecret::Kek(Kek::from_bytes(*prf)),
                )
            }
            VaultKeyUnlock::Escrow { label, secret } => {
                check_name(label)?;
                open_wrap(
                    vault_id,
                    &self.commitment,
                    wrap(VaultKeyWrapKind::Escrow {
                        label: (*label).to_owned(),
                    })?,
                    &UnlockSecret::Hybrid(secret),
                )
            }
        }
    }
}

/// What unlocks one wrap.
enum UnlockSecret<'a> {
    Kek(Kek),
    Passphrase(&'a Passphrase),
    Hybrid(&'a HybridSecretKey),
}

/// What seals one new wrap.
enum WrapSecret<'a> {
    Kek(Kek),
    Passphrase(&'a Passphrase, Argon2Cost),
    Hybrid(&'a HybridPublicKey),
}

fn seal_wrap(
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
    payload.extend_from_slice(&key.0[..]);
    let envelope = seal(&params, seal_key, &payload, &mut SysRng)
        .map_err(|_| refused("sealing the vault key failed"))?;
    Ok(envelope.to_bytes())
}

fn open_wrap(
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
    let key = VaultDataKey(bytes);
    if key.commitment(vault_id) != *commitment {
        return Err(refused("the vault key wrap opens to another key"));
    }
    Ok(key)
}

impl Vault {
    fn vault_key_slot(&self, install: crate::EntityId) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *install.as_bytes(),
            kind: SlotKind::VaultUnlock,
        }
    }

    /// This install's device KEK, created in its keystore slot on first use, and
    /// the wrap kind it opens.
    fn device_kek(&self) -> Result<(Kek, VaultKeyWrapKind)> {
        let keystore = self.device_keystore()?;
        let install = self.prepare_install_signing()?;
        let seed = super::machine::slot_seed(keystore.as_ref(), &self.vault_key_slot(install))?;
        Ok((
            Kek::from_bytes(*seed),
            VaultKeyWrapKind::Device {
                install: install.to_hex(),
            },
        ))
    }

    fn held_vault_key(&self) -> Option<Arc<VaultDataKey>> {
        self.world_keys
            .vault_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn hold_vault_key(&self, key: VaultDataKey) {
        *self
            .world_keys
            .vault_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(key));
    }

    /// Whether this vault has a data key, and whether this handle holds it.
    pub fn vault_key_status(&self) -> Result<VaultKeyStatus> {
        if self.held_vault_key().is_some() {
            return Ok(VaultKeyStatus::Unlocked);
        }
        let txn = self.store.env.read_txn()?;
        Ok(if STATE.get(&self.store, &txn, &())?.is_some() {
            VaultKeyStatus::Locked
        } else {
            VaultKeyStatus::NoKey
        })
    }

    /// Mints the vault's data key, wraps it to this device's keystore, and holds it
    /// on this handle. Refused when the vault already has one.
    pub fn create_vault_key(&self) -> Result<VaultKeyWrapInfo> {
        let (kek, kind) = self.device_kek()?;
        let key = VaultDataKey::generate()?;
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let envelope = seal_wrap(&vault_id, &commitment, &kind, &WrapSecret::Kek(kek), &key)?;
        let info = self.with_write_txn(|txn| {
            if STATE.get(&self.store, txn, &())?.is_some() {
                return Err(refused("the vault already has a data key"));
            }
            let created_at = self.instant_in_txn(txn)?.secs();
            STATE.put(
                &self.store,
                txn,
                &(),
                &VaultKeyState {
                    commitment,
                    created_at,
                },
            )?;
            let info = VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at,
            };
            WRAPS.put(
                &self.store,
                txn,
                &info.id,
                &StoredWrap {
                    info: info.clone(),
                    envelope,
                },
            )?;
            Ok(info)
        })?;
        self.hold_vault_key(key);
        Ok(info)
    }

    /// Holds the vault data key on this handle, as a sealed artifact needs it:
    /// unlocked with this device's wrap, or minted and wrapped to this device
    /// when the vault has none yet.
    pub fn ensure_vault_key(&self) -> Result<()> {
        if self.vault_key_status()? == VaultKeyStatus::NoKey {
            match self.create_vault_key() {
                Ok(_) => return Ok(()),
                Err(error) if self.vault_key_status()? == VaultKeyStatus::NoKey => {
                    return Err(error);
                }
                // Another handle minted it first.
                Err(_) => {}
            }
        }
        self.unlock_vault_key()
    }

    /// The vault key as it rests, read in `txn` for a sealed artifact to carry,
    /// and the key for `context` of the one this handle holds. Refused while the
    /// key is locked, and when the held key is not the one `txn` reads.
    pub(crate) fn carried_vault_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        context: &str,
    ) -> Result<(CarriedVaultKey, Zeroizing<[u8; 32]>)> {
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is locked"))?;
        let vault_id = *self.vault_id().as_bytes();
        let state = STATE
            .get(&self.store, txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        if state.commitment != key.commitment(&vault_id) {
            return Err(refused("this handle holds another vault key"));
        }
        let wraps = WRAPS
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(_, stored)| stored)
            .collect();
        Ok((
            CarriedVaultKey {
                commitment: state.commitment,
                wraps,
            },
            Zeroizing::new(key.derive(context, &vault_id)),
        ))
    }

    /// Unlocks the vault data key with this device's keystore wrap. A vault
    /// restored as a new machine on this device has no wrap of its own yet: it
    /// unlocks with the device wrap of an install it was copied from whose
    /// slot this keystore holds, then wraps the key to itself.
    pub fn unlock_vault_key(&self) -> Result<()> {
        if self.held_vault_key().is_some() {
            return Ok(());
        }
        let (kek, kind) = self.device_kek()?;
        let id = kind.id();
        let carried = {
            let txn = self.store.env.read_txn()?;
            if WRAPS.get(&self.store, &txn, &id)?.is_some() {
                None
            } else {
                let state = STATE
                    .get(&self.store, &txn, &())?
                    .ok_or_else(|| refused("the vault has no data key"))?;
                let wraps = WRAPS
                    .scan(&self.store, &txn)?
                    .into_iter()
                    .map(|(_, stored)| stored)
                    .collect();
                Some(CarriedVaultKey {
                    commitment: state.commitment,
                    wraps,
                })
            }
        };
        let Some(carried) = carried else {
            return self.unlock_vault_key_with(&id, &UnlockSecret::Kek(kek));
        };
        let keystore = self.device_keystore()?;
        let key = carried.open(
            self.vault_id().as_bytes(),
            &VaultKeyUnlock::Device(keystore.as_ref()),
        )?;
        self.hold_vault_key(key);
        // Held either way; a vault that takes no write (archived) wraps it
        // to itself on a later unlock.
        if let Err(error) = self.add_vault_key_wrap(kind, &WrapSecret::Kek(kek)) {
            tracing::warn!(%error, "the vault key was not wrapped to this install");
        }
        Ok(())
    }

    /// Unlocks the vault data key with the vault password.
    pub fn unlock_vault_key_with_password(&self, password: &[u8]) -> Result<()> {
        let passphrase =
            Passphrase::new(password).map_err(|_| refused("the password is not accepted"))?;
        self.unlock_vault_key_with(
            &VaultKeyWrapKind::Password.id(),
            &UnlockSecret::Passphrase(&passphrase),
        )
    }

    /// Unlocks the vault data key with one passkey's PRF output.
    pub fn unlock_vault_key_with_passkey(&self, credential: &str, prf: [u8; 32]) -> Result<()> {
        check_name(credential)?;
        let kind = VaultKeyWrapKind::Passkey {
            credential: credential.to_owned(),
        };
        self.unlock_vault_key_with(&kind.id(), &UnlockSecret::Kek(Kek::from_bytes(prf)))
    }

    /// Unlocks the vault data key with the secret of an escrow wrap's recipient: a
    /// recovery service's release, or the key a transfer was sealed to.
    pub fn unlock_vault_key_with_escrow(
        &self,
        label: &str,
        secret: &HybridSecretKey,
    ) -> Result<()> {
        check_name(label)?;
        let kind = VaultKeyWrapKind::Escrow {
            label: label.to_owned(),
        };
        self.unlock_vault_key_with(&kind.id(), &UnlockSecret::Hybrid(secret))
    }

    fn unlock_vault_key_with(&self, id: &str, secret: &UnlockSecret<'_>) -> Result<()> {
        let vault_id = *self.vault_id().as_bytes();
        let (state, stored) = {
            let txn = self.store.env.read_txn()?;
            let state = STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            let stored = WRAPS
                .get(&self.store, &txn, &id.to_owned())?
                .ok_or_else(|| refused("the vault key has no such wrap"))?;
            (state, stored)
        };
        let key = open_wrap(&vault_id, &state.commitment, &stored, secret)?;
        self.hold_vault_key(key);
        Ok(())
    }

    /// Drops the vault data key from this handle.
    pub fn lock_vault_key(&self) {
        *self
            .world_keys
            .vault_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Wraps the held vault data key to this device's keystore: the step after an
    /// unlock with a password, passkey or escrow on a new device.
    pub fn add_vault_key_device(&self) -> Result<VaultKeyWrapInfo> {
        let (kek, kind) = self.device_kek()?;
        self.add_vault_key_wrap(kind, &WrapSecret::Kek(kek))
    }

    /// Sets the vault password, replacing an earlier one. `cost` defaults to RFC
    /// 9106's second recommended Argon2id option.
    pub fn set_vault_key_password(
        &self,
        password: &[u8],
        cost: Option<Argon2Cost>,
    ) -> Result<VaultKeyWrapInfo> {
        let passphrase =
            Passphrase::new(password).map_err(|_| refused("the password is not accepted"))?;
        self.add_vault_key_wrap(
            VaultKeyWrapKind::Password,
            &WrapSecret::Passphrase(&passphrase, cost.unwrap_or(Argon2Cost::RFC9106_SECOND)),
        )
    }

    /// Wraps the held vault data key to one passkey, by its PRF output.
    pub fn add_vault_key_passkey(
        &self,
        credential: &str,
        prf: [u8; 32],
    ) -> Result<VaultKeyWrapInfo> {
        check_name(credential)?;
        self.add_vault_key_wrap(
            VaultKeyWrapKind::Passkey {
                credential: credential.to_owned(),
            },
            &WrapSecret::Kek(Kek::from_bytes(prf)),
        )
    }

    /// Seals the held vault data key to a recovery or transfer public key.
    pub fn add_vault_key_escrow(
        &self,
        label: &str,
        recipient: &HybridPublicKey,
    ) -> Result<VaultKeyWrapInfo> {
        check_name(label)?;
        self.add_vault_key_wrap(
            VaultKeyWrapKind::Escrow {
                label: label.to_owned(),
            },
            &WrapSecret::Hybrid(recipient),
        )
    }

    fn add_vault_key_wrap(
        &self,
        kind: VaultKeyWrapKind,
        secret: &WrapSecret<'_>,
    ) -> Result<VaultKeyWrapInfo> {
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("unlock the vault key first"))?;
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let envelope = seal_wrap(&vault_id, &commitment, &kind, secret, &key)?;
        self.with_write_txn(|txn| {
            let state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if state.commitment != commitment {
                return Err(refused("this handle holds another vault key"));
            }
            let info = VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at: self.instant_in_txn(txn)?.secs(),
            };
            WRAPS.put(
                &self.store,
                txn,
                &info.id,
                &StoredWrap {
                    info: info.clone(),
                    envelope,
                },
            )?;
            Ok(info)
        })
    }

    /// Removes one wrap. The last wrap stays: without it the key is lost.
    pub fn remove_vault_key_wrap(&self, id: &str) -> Result<()> {
        self.with_write_txn(|txn| {
            let id = id.to_owned();
            if WRAPS.get(&self.store, txn, &id)?.is_none() {
                return Err(refused("the vault key has no such wrap"));
            }
            if WRAPS.scan(&self.store, txn)?.len() <= 1 {
                return Err(refused("the last vault key wrap stays"));
            }
            WRAPS.delete(&self.store, txn, &id)?;
            Ok(())
        })
    }

    /// The vault key's wraps, public facts only.
    pub fn vault_key_wraps(&self) -> Result<Vec<VaultKeyWrapInfo>> {
        let txn = self.store.env.read_txn()?;
        Ok(WRAPS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, stored)| stored.info)
            .collect())
    }

    /// A key of its own for `context`, derived from the held vault data key:
    /// what a sealed artifact keys itself with. Refused while the key is locked.
    pub(crate) fn vault_subkey(&self, context: &str) -> Result<Zeroizing<[u8; 32]>> {
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is locked"))?;
        Ok(Zeroizing::new(
            key.derive(context, self.vault_id().as_bytes()),
        ))
    }
}
