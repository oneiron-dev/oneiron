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
use self::state::{
    AEAD, ARGON2_MAX, ESCROW_RECIPIENT, ESCROW_RETIRED, ESCROW_SEED_LABEL, ESCROW_SPOOLED, KEM,
    PASSKEY_PRF_CONTEXT, PAYLOAD_LABEL, PAYLOAD_LEN, STATE, UnlockSecret, VAULT_KEY_EPOCH,
    VaultKeyState, WRAPS, WrapSecret, check_name, log_escrow_warnings, open_wrap, passkey_kek,
    presented_escrow, recipient_fingerprint, seal_wrap, wrap_digest,
};
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
use super::refused;
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
pub(crate) use oneiron_store::vault_page_seal::VaultDataKey;
pub(super) use oneiron_store::vault_page_seal::WrapDigest;

mod escrow;
pub(super) mod kit;
pub(super) mod restore;
mod state;
mod storage;
mod vocabulary;

pub use self::escrow::{
    EscrowAddWarning, EscrowAdded, EscrowRetirement, ResealedEscrowCapsule, VaultKeyEscrowCapsule,
    reseal_escrow_capsule,
};
pub use self::vocabulary::{
    NewVaultKeyWrap, VaultKeyStatus, VaultKeyUnlock, escrow_recipient, passkey_prf_input,
};

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
            VaultKeyUnlock::Kit { .. } => {
                return kit::open_kit(vault_id, self, unlock).map(|key| (key, Vec::new()));
            }
            VaultKeyUnlock::WorldKit { .. } => {
                let hybrid = kit::open_world_kit(vault_id, self, unlock)?;
                let secret = UnlockSecret::Hybrid(&hybrid);
                for stored in named(VaultKeyWrapKind::Escrow {
                    label: crate::world_keys::WORLD_KIT_ESCROW.to_owned(),
                }) {
                    attempt(stored, &secret);
                }
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
                .get(&self.store, &txn, wrap.id())?
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
