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
//! A managed node's supervisor unwraps the key itself and hands it to the vault
//! process at boot ([`Vault::admit_vault_key`]); that wrap stays with the node.
//! A passkey is asked for its PRF at one input per vault and credential
//! ([`passkey_prf_input`]), so a host holding only a sealed artifact asks for the
//! same output the wrap was sealed under.
//!
//! The wraps and a commitment to the key live in `vault_meta`; the key itself
//! lives only in this handle's memory once unlocked. A wrap that opens to bytes
//! the commitment does not name is refused. Which wraps a vault keeps is the
//! owner's choice; the engine refuses to drop the last one. The data key unlocks
//! no private world: those keys live apart (`world_keys`).

use std::sync::{Arc, PoisonError};

use getrandom::SysRng;
// The wraps' public facts and the key header's wire form are the shared
// artifact codec's, so a host that never opens a vault reads a sealed
// artifact's key header with the engine's own types. A stored wrap is one
// wrap as it rests: its public facts and its sealed envelope.
use oneiron_crypto::backup::{KeyHeader, KeyHeaderWrap as StoredWrap};
pub use oneiron_crypto::backup::{VaultKeyWrapInfo, VaultKeyWrapKind};
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Passphrase,
    Purpose, SealKey, SealParams, SuiteId, seal,
};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, SlotKind};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::page_seal::{OpenedDataKey, WrapTransition};
use super::{os_fill, refused};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

mod escrow;
pub(super) mod kit;
pub(super) mod restore;
mod storage;
mod vocabulary;

pub use self::escrow::{
    EscrowAddWarning, EscrowAdded, EscrowRetirement, ResealedEscrowCapsule, VaultKeyEscrowCapsule,
    reseal_escrow_capsule,
};
pub use self::vocabulary::{
    NewVaultKeyWrap, VaultKeyStatus, VaultKeyUnlock, escrow_recipient, passkey_prf_input,
};

const PAYLOAD_LABEL: &[u8] = b"oneiron/vault-dek/v1\0";
const PAYLOAD_LEN: usize = PAYLOAD_LABEL.len() + 32;
const COMMITMENT_CONTEXT: &str = "oneiron/vault-key-commitment/v1";
const PASSKEY_PRF_CONTEXT: &str = "oneiron/vault-key-passkey-prf-input/v1";
const ESCROW_SEED_LABEL: &[u8] = b"oneiron/vault-key-escrow-recipient/v1";
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
    pub(super) fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    /// The key a managed node's supervisor delivered, copied into a handle
    /// that wipes it on drop: zero-filled first, then filled, so no plain
    /// copy is made on the way (FIX 6048).
    pub(super) fn delivered(bytes: &[u8; 32]) -> Self {
        let mut guarded = Zeroizing::new([0u8; 32]);
        guarded.copy_from_slice(bytes);
        Self(guarded)
    }

    /// `BLAKE3-derive_key("oneiron/vault-key-commitment/v1", vault id ‖ key)`: it
    /// pins which bytes are this vault's key and reveals nothing about them.
    pub(super) fn commitment(&self, vault_id: &[u8; 32]) -> [u8; 32] {
        // Public: the guard's copy is wiped as it drops.
        *self.derive(COMMITMENT_CONTEXT, vault_id)
    }

    /// A key of its own for one use, `BLAKE3-derive_key(context, vault id ‖ key)`,
    /// derived straight into its guard (FIX 6334).
    pub(super) fn derive(&self, context: &str, vault_id: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        super::derive_guarded(context, &[&vault_id[..], &self.0[..]])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultKeyState {
    commitment: [u8; 32],
    created_at: u64,
}

/// A stored wrap's digest: its id and its envelope's BLAKE3.
fn wrap_digest(stored: &StoredWrap) -> WrapDigest {
    WrapDigest {
        id: stored.info.id.clone(),
        envelope: *blake3::hash(&stored.envelope).as_bytes(),
    }
}

/// An escrow capsule presented from outside the vault's wraps, filed as
/// escrow wrap `label` would be, so it opens under that wrap's id. None
/// of it is stored, so it names no time.
fn presented_escrow(label: &str, capsule: &[u8]) -> Result<StoredWrap> {
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

/// One wrap as a page-seal mirror carries it (OF-570): its id, which names
/// its kind and label, and the BLAKE3 digest of its sealed envelope. A
/// sealed vault admits an unlock from its mirror only while it holds the
/// wrap that opened, envelope for envelope.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct WrapDigest {
    id: String,
    envelope: [u8; 32],
}

/// A passkey's PRF output as a KEK: copied once from the caller's guard into
/// guarded storage (FIX 6048, FIX 6334). The output never travels as a
/// plain array; the caller's guard wipes it.
fn passkey_kek(prf: &Zeroizing<[u8; 32]>) -> Kek {
    Kek::from_bytes_ref(prf)
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

/// The vault key as it rests: its commitment and every wrap's sealed envelope,
/// never the key. A sealed artifact carries it in the clear, so a host without
/// the vault can unlock the artifact's key from one of the wraps. Its wire
/// form is the shared key header's ([`KeyHeader`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct CarriedVaultKey(KeyHeader);

impl CarriedVaultKey {
    fn new(commitment: [u8; 32], wraps: Vec<StoredWrap>) -> Self {
        Self(KeyHeader { commitment, wraps })
    }

    /// The vault key named by `commitment` with no wrap yet: what the mirror
    /// of a vault under a delivered key holds before its first wrap.
    pub(super) fn unwrapped(commitment: [u8; 32]) -> Self {
        Self::new(commitment, Vec::new())
    }

    /// The key header a sealed artifact carries, as its wire form.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.0
            .encode()
            .map_err(|_| refused("the vault key header does not encode"))
    }

    /// The key header a sealed artifact carries, read from its wire form.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        KeyHeader::decode(bytes)
            .map(Self)
            .map_err(|_| crate::Error::CorruptedIndex("sealed checkpoint artifact"))
    }

    /// The commitment naming the vault key.
    pub(crate) fn commitment(&self) -> &[u8; 32] {
        &self.0.commitment
    }

    /// Each carried wrap's public facts: what a host may unlock with.
    pub(crate) fn wrap_infos(&self) -> Vec<VaultKeyWrapInfo> {
        self.0.wrap_infos()
    }

    /// The key for `context` of the vault key a carried wrap opens to under
    /// `unlock`, and that vault key, kept opaque for a sealed vault restored
    /// from the artifact (OF-570).
    pub(crate) fn subkey_opened(
        &self,
        vault_id: &[u8; 32],
        unlock: &VaultKeyUnlock<'_>,
        context: &str,
    ) -> Result<(Zeroizing<[u8; 32]>, OpenedDataKey)> {
        let key = self.open(vault_id, unlock)?;
        let subkey = key.derive(context, vault_id);
        Ok((subkey, OpenedDataKey::new(*vault_id, key)))
    }

    /// The vault key a carried wrap opens to under `unlock`.
    fn open(&self, vault_id: &[u8; 32], unlock: &VaultKeyUnlock<'_>) -> Result<VaultDataKey> {
        self.open_recording(vault_id, unlock).map(|(key, _)| key)
    }

    /// The vault key a carried wrap opens to under `unlock`, and the digest
    /// of every carried wrap that opens. Each wrap `unlock` may open is
    /// tried: while a wrap change commits, a page-seal mirror carries a wrap
    /// and its replacement under one id (OF-570).
    pub(super) fn open_recording(
        &self,
        vault_id: &[u8; 32],
        unlock: &VaultKeyUnlock<'_>,
    ) -> Result<(VaultDataKey, Vec<WrapDigest>)> {
        let mut key = None;
        let mut opened = Vec::new();
        let mut refusal = None;
        let mut attempt = |stored: &StoredWrap, secret: &UnlockSecret<'_>| match open_wrap(
            vault_id,
            &self.0.commitment,
            stored,
            secret,
        ) {
            Ok(unwrapped) => {
                opened.push(wrap_digest(stored));
                if key.is_none() {
                    key = Some(unwrapped);
                }
            }
            Err(error) => refusal = Some(error),
        };
        let named = |kind: VaultKeyWrapKind| {
            let id = kind.id();
            self.0
                .wraps
                .iter()
                .filter(move |stored| stored.info.id == id)
        };
        match unlock {
            VaultKeyUnlock::Device(keystore) => {
                let mut held = false;
                for stored in &self.0.wraps {
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
                    held = true;
                    attempt(stored, &UnlockSecret::Kek(Kek::from_zeroizing(seed)));
                }
                if !held {
                    return Err(refused(
                        "this keystore holds no device wrap of the vault key",
                    ));
                }
            }
            VaultKeyUnlock::Password(password) => {
                let passphrase = Passphrase::new(password)
                    .map_err(|_| refused("the password is not accepted"))?;
                let secret = UnlockSecret::Passphrase(&passphrase);
                for stored in named(VaultKeyWrapKind::Password) {
                    attempt(stored, &secret);
                }
            }
            VaultKeyUnlock::Passkey { credential, prf } => {
                check_name(credential)?;
                let secret = UnlockSecret::Kek(Kek::from_bytes_ref(prf));
                for stored in named(VaultKeyWrapKind::Passkey {
                    credential: (*credential).to_owned(),
                }) {
                    attempt(stored, &secret);
                }
            }
            VaultKeyUnlock::Escrow { label, secret } => {
                check_name(label)?;
                let secret = UnlockSecret::Hybrid(secret);
                for stored in named(VaultKeyWrapKind::Escrow {
                    label: (*label).to_owned(),
                }) {
                    attempt(stored, &secret);
                }
            }
            VaultKeyUnlock::EscrowCapsule {
                label,
                capsule,
                secret,
            } => {
                let presented = presented_escrow(label, capsule)?;
                attempt(&presented, &UnlockSecret::Hybrid(secret));
            }
            VaultKeyUnlock::Kit {
                vault_id: kit_vault,
                pieces,
                passphrase,
            } => {
                let rebuilt =
                    kit::open_kit(vault_id, &self.0.commitment, kit_vault, pieces, *passphrase)?;
                return Ok((rebuilt, Vec::new()));
            }
        }
        match key {
            Some(key) => Ok((key, opened)),
            None => Err(refusal.unwrap_or_else(|| refused("the vault key has no such wrap"))),
        }
    }

    /// Each carried wrap's digest.
    pub(super) fn digests(&self) -> Vec<WrapDigest> {
        self.0.wraps.iter().map(wrap_digest).collect()
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
            Kek::from_zeroizing(seed),
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
        // An unlock opens a new snapshot admission generation, never readiness.
        self.store.inference_snapshots.reopen();
    }

    /// Holds the data key a sealed vault opened with (OF-570 maximum tier).
    /// A vault with a data key holds it only when its commitment names this
    /// key; a new vault takes it as its own, with no wrap yet.
    pub(super) fn admit_page_seal_key(&self, key: &Arc<VaultDataKey>) -> Result<()> {
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let stored = {
            let txn = self.store.env.read_txn()?;
            STATE.get(&self.store, &txn, &())?
        };
        let refused_key = || refused("the page seal's key is not this vault's data key");
        match stored {
            Some(state) if state.commitment != commitment => return Err(refused_key()),
            Some(_) => {}
            None => self.with_write_txn(|txn| {
                if let Some(state) = STATE.get(&self.store, txn, &())? {
                    return if state.commitment == commitment {
                        Ok(())
                    } else {
                        Err(refused_key())
                    };
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
                )
            })?,
        }
        *self
            .world_keys
            .vault_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(key));
        // Its body files are envelopes under keys this one wraps, from the
        // vault's first write (FIX 5348).
        #[cfg(unix)]
        self.store.body_seal.admit(crate::store::BodySeal::new(
            vault_id,
            &key.derive(crate::store::BODY_FILE_WRAP_CONTEXT, &vault_id),
        ));
        Ok(())
    }

    /// The vault key as it rests, for the page-seal mirror: `None` while the
    /// vault has no data key or no wrap.
    pub(super) fn resting_vault_key(&self) -> Result<Option<CarriedVaultKey>> {
        let txn = self.store.env.read_txn()?;
        let Some(state) = STATE.get(&self.store, &txn, &())? else {
            return Ok(None);
        };
        let wraps: Vec<StoredWrap> = WRAPS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, stored)| stored)
            .collect();
        Ok((!wraps.is_empty()).then_some(CarriedVaultKey::new(state.commitment, wraps)))
    }

    /// What a sealed vault's page-seal mirror holds while a wrap change
    /// commits ([`WrapTransition::stage`]): every wrap `txn` reads before the
    /// change touches one, and the wrap it adds.
    fn staged_wraps_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        adding: Option<&StoredWrap>,
    ) -> Result<CarriedVaultKey> {
        let state = STATE
            .get(&self.store, txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        let mut wraps: Vec<StoredWrap> = WRAPS
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(_, stored)| stored)
            .collect();
        wraps.extend(adding.cloned());
        Ok(CarriedVaultKey::new(state.commitment, wraps))
    }

    /// Whether this vault holds one of `wraps` as it is, envelope for
    /// envelope: what admits a page seal unlocked from the mirror (OF-570).
    pub(super) fn holds_any_wrap(&self, wraps: &[WrapDigest]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        for wrap in wraps {
            let held = WRAPS
                .get(&self.store, &txn, &wrap.id)?
                .is_some_and(|stored| wrap_digest(&stored) == *wrap);
            if held {
                return Ok(true);
            }
        }
        Ok(false)
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

    fn add_vault_key_escrow_checked(
        &self,
        label: &str,
        recipient: &HybridPublicKey,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<EscrowAdded> {
        check_name(label)?;
        let (wrap, warnings, transition) = self.commit_vault_key_wrap(
            VaultKeyWrapKind::Escrow {
                label: label.to_owned(),
            },
            &WrapSecret::Hybrid(recipient),
            owner,
        )?;
        transition.finish()?;
        Ok(EscrowAdded { wrap, warnings })
    }

    /// Seals the held vault data key to `recipient` as escrow wrap `label`, in
    /// the caller's transaction, replacing a wrap of that label. `None` when
    /// the vault has no data key; refused when it has one this handle does
    /// not hold, so the old wrap never outlives the change. A sealed vault's
    /// mirror is staged first: the caller begins `transition` before its
    /// transaction and finishes it after the commit ([`WrapTransition`]).
    pub(super) fn put_vault_key_escrow_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        transition: &WrapTransition<'_>,
        label: &str,
        recipient: &HybridPublicKey,
    ) -> Result<Option<VaultKeyWrapInfo>> {
        check_name(label)?;
        let Some(key) = self.held_vault_key() else {
            if STATE.get(&self.store, txn, &())?.is_some() {
                return Err(refused("unlock the vault key first"));
            }
            return Ok(None);
        };
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let state = STATE
            .get(&self.store, txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        if state.commitment != commitment {
            return Err(refused("this handle holds another vault key"));
        }
        let kind = VaultKeyWrapKind::Escrow {
            label: label.to_owned(),
        };
        self.refuse_retired_escrow_in_txn(txn, &kind)?;
        let fingerprint = recipient_fingerprint(recipient);
        let warnings = self.escrow_warnings_in_txn(txn, label, &fingerprint)?;
        ESCROW_RECIPIENT.put(&self.store, txn, &label.to_owned(), &fingerprint)?;
        log_escrow_warnings(label, &warnings);
        let envelope = seal_wrap(
            &vault_id,
            &commitment,
            &kind,
            &WrapSecret::Hybrid(recipient),
            &key,
        )?;
        let info = VaultKeyWrapInfo {
            id: kind.id(),
            kind,
            created_at: self.instant_in_txn(txn)?.secs(),
        };
        let stored = StoredWrap {
            info: info.clone(),
            envelope,
        };
        transition.stage(|| self.staged_wraps_in_txn(txn, Some(&stored)))?;
        WRAPS.put(&self.store, txn, &info.id, &stored)?;
        Ok(Some(info))
    }

    fn add_vault_key_wrap(
        &self,
        kind: VaultKeyWrapKind,
        secret: &WrapSecret<'_>,
    ) -> Result<VaultKeyWrapInfo> {
        self.add_vault_key_wrap_checked(kind, secret, None)
    }

    fn add_vault_key_wrap_checked(
        &self,
        kind: VaultKeyWrapKind,
        secret: &WrapSecret<'_>,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<VaultKeyWrapInfo> {
        let (info, warnings, transition) = self.commit_vault_key_wrap(kind, secret, owner)?;
        transition.finish()?;
        if let VaultKeyWrapKind::Escrow { label } = &info.kind {
            log_escrow_warnings(label, &warnings);
        }
        Ok(info)
    }

    /// Seals one wrap of the held key and commits it, staged first in a
    /// sealed vault's page-seal mirror. The change's last step, the mirror
    /// rewritten from the committed wraps, is the caller's ([`WrapTransition`]).
    /// An escrow wrap records its recipient's fingerprint and answers what
    /// the add warns of (FIX 2857).
    fn commit_vault_key_wrap(
        &self,
        kind: VaultKeyWrapKind,
        secret: &WrapSecret<'_>,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<(VaultKeyWrapInfo, Vec<EscrowAddWarning>, WrapTransition<'_>)> {
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("unlock the vault key first"))?;
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let envelope = seal_wrap(&vault_id, &commitment, &kind, secret, &key)?;
        let transition = self.begin_wrap_transition()?;
        let (info, warnings) = self.with_write_txn(|txn| {
            if let Some(owner) = owner {
                owner.revalidate_in_txn(self, txn)?;
            }
            self.refuse_retired_escrow_in_txn(txn, &kind)?;
            let state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if state.commitment != commitment {
                return Err(refused("this handle holds another vault key"));
            }
            let warnings = match (&kind, secret) {
                (VaultKeyWrapKind::Escrow { label }, WrapSecret::Hybrid(recipient)) => {
                    let fingerprint = recipient_fingerprint(recipient);
                    let warnings = self.escrow_warnings_in_txn(txn, label, &fingerprint)?;
                    ESCROW_RECIPIENT.put(&self.store, txn, label, &fingerprint)?;
                    warnings
                }
                _ => Vec::new(),
            };
            let info = VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at: self.instant_in_txn(txn)?.secs(),
            };
            let stored = StoredWrap {
                info: info.clone(),
                envelope,
            };
            transition.stage(|| self.staged_wraps_in_txn(txn, Some(&stored)))?;
            WRAPS.put(&self.store, txn, &info.id, &stored)?;
            Ok((info, warnings))
        })?;
        Ok((info, warnings, transition))
    }

    fn remove_vault_key_wrap_checked(
        &self,
        id: &str,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<()> {
        let transition = self.begin_wrap_transition()?;
        self.with_write_txn(|txn| {
            if let Some(owner) = owner {
                owner.revalidate_in_txn(self, txn)?;
            }
            let id = id.to_owned();
            if WRAPS.get(&self.store, txn, &id)?.is_none() {
                return Err(refused("the vault key has no such wrap"));
            }
            if WRAPS.scan(&self.store, txn)?.len() <= 1 {
                return Err(refused("the last vault key wrap stays"));
            }
            transition.stage(|| self.staged_wraps_in_txn(txn, None))?;
            WRAPS.delete(&self.store, txn, &id)?;
            Ok(())
        })?;
        transition.finish()
    }

    /// What sealing an escrow wrap `label` to the recipient whose fingerprint
    /// is `fingerprint` warns of, read in `txn` (FIX 2857): each label
    /// retired after its recipient was released that named this same key,
    /// by the fingerprint recorded when it was sealed, or by the fingerprint
    /// a managed label carries. A released recipient is never meant to be
    /// reused (CROSS-ARCH-0022), but only its label is refused; a new label
    /// on the same key warns and still seals.
    fn escrow_warnings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        label: &str,
        fingerprint: &[u8; 32],
    ) -> Result<Vec<EscrowAddWarning>> {
        let hex = blake3::Hash::from(*fingerprint).to_hex();
        let mut warnings = Vec::new();
        for (retired, _) in ESCROW_RETIRED.scan(&self.store, txn)? {
            if retired == label {
                continue;
            }
            let reused = ESCROW_RECIPIENT
                .get(&self.store, txn, &retired)?
                .is_some_and(|sealed| sealed == *fingerprint)
                || restore::label_prefix_of(&retired).is_some_and(|prefix| prefix == &hex[..16]);
            if reused {
                warnings.push(EscrowAddWarning::RetiredRecipient {
                    retired_label: retired,
                });
            }
        }
        Ok(warnings)
    }

    /// Refuses a wrap of `kind` sealed to a retired escrow label.
    fn refuse_retired_escrow_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: &VaultKeyWrapKind,
    ) -> Result<()> {
        if let VaultKeyWrapKind::Escrow { label } = kind
            && ESCROW_RETIRED.get(&self.store, txn, label)?.is_some()
        {
            return Err(refused(
                "this escrow recipient was released and retired; seal to a new one",
            ));
        }
        Ok(())
    }
}

/// Which escrow capsule each escrow wrap last handed to the host's outbound
/// spool, by the blake3 of its envelope.
const ESCROW_SPOOLED: SideTable<String, [u8; 32], Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_SPOOLED);

/// The escrow labels retired after their recipients were released, by label.
const ESCROW_RETIRED: SideTable<String, EscrowRetirement, Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_RETIRED);

/// The fingerprint of the recipient each escrow label was sealed to, kept
/// once the label retires, so a later add of the same key under another
/// label warns (FIX 2857). Public facts only.
const ESCROW_RECIPIENT: SideTable<String, [u8; 32], Named> =
    SideTable::new(&side_table::VAULT_KEY_ESCROW_RECIPIENT);

/// An escrow recipient's fingerprint: the BLAKE3 of its public key's wire
/// form, as a managed label and a restore's recipient facts name it.
fn recipient_fingerprint(recipient: &HybridPublicKey) -> [u8; 32] {
    *blake3::hash(&recipient.to_bytes()).as_bytes()
}

/// Logs what an escrow add warned of, by label only.
fn log_escrow_warnings(label: &str, warnings: &[EscrowAddWarning]) {
    for warning in warnings {
        let EscrowAddWarning::RetiredRecipient { retired_label } = warning;
        tracing::warn!(
            label,
            retired_label = %retired_label,
            "an escrow wrap was sealed to a recipient released and retired under another label"
        );
    }
}
