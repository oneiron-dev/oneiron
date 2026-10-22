//! Vault-key storage doors for unlocking and changing wraps.
//! The entry point is `Vault::create_vault_key`.
//! `super` owns private key state, wrap codecs and shared transaction helpers.

use super::*;

impl Vault {
    /// The vault id its data key, wraps and sealed artifacts are bound to.
    pub fn vault_key_vault_id(&self) -> [u8; 32] {
        *self.vault_id().as_bytes()
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
        let transition = self.begin_wrap_transition()?;
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
            let stored = StoredWrap {
                info: info.clone(),
                envelope,
            };
            transition.stage(|| self.staged_wraps_in_txn(txn, Some(&stored)))?;
            WRAPS.put(&self.store, txn, &info.id, &stored)?;
            Ok(info)
        })?;
        self.hold_vault_key(key);
        transition.finish()?;
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

    /// Holds the vault data key a managed node delivered. Its supervisor unwraps
    /// the key with the node key at boot and hands it over the inherited pipe
    /// (CROSS-ARCH-0022 #ov-custody), so the vault's sealed artifacts derive
    /// from that very key. A vault with a data key holds it only when its
    /// commitment names these bytes. A vault without one takes it as its own,
    /// with no wrap: the node's wrap stays with the supervisor, and a restore
    /// elsewhere opens through an escrow wrap ([`Self::add_vault_key_escrow`]).
    /// True when the vault took it as new.
    pub fn admit_vault_key(&self, delivered: &[u8; 32]) -> Result<bool> {
        let key = VaultDataKey(Zeroizing::new(*delivered));
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let created = self.with_write_txn(|txn| {
            if let Some(state) = STATE.get(&self.store, txn, &())? {
                return if state.commitment == commitment {
                    Ok(false)
                } else {
                    Err(refused("the delivered key is not this vault's data key"))
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
            )?;
            Ok(true)
        })?;
        self.hold_vault_key(key);
        Ok(created)
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
            CarriedVaultKey::new(state.commitment, wraps),
            key.derive(context, &vault_id),
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
                Some(CarriedVaultKey::new(state.commitment, wraps))
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
        // to itself on a later unlock. A wrap that committed on a sealed
        // vault rewrites its mirror, or says it did not.
        match self.commit_vault_key_wrap(kind, &WrapSecret::Kek(kek), None) {
            Ok((_, _, transition)) => transition.finish()?,
            Err(error) => tracing::warn!(%error, "the vault key was not wrapped to this install"),
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

    /// Unlocks the vault data key with one passkey's PRF output, borrowed
    /// from the guard that wipes it.
    pub fn unlock_vault_key_with_passkey(
        &self,
        credential: &str,
        prf: &Zeroizing<[u8; 32]>,
    ) -> Result<()> {
        let kek = passkey_kek(prf);
        check_name(credential)?;
        let kind = VaultKeyWrapKind::Passkey {
            credential: credential.to_owned(),
        };
        self.unlock_vault_key_with(&kind.id(), &UnlockSecret::Kek(kek))
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

    /// Unlocks the vault data key with an escrow capsule presented from
    /// outside its wraps ([`VaultKeyUnlock::EscrowCapsule`]): a registry's,
    /// opened with its recipient's released secret, for a vault restored from
    /// an artifact that predates or lacks that wrap. It opens only to the key
    /// the vault's commitment names, bound to its id and the wrap id `label`
    /// makes.
    pub fn unlock_vault_key_with_escrow_capsule(
        &self,
        label: &str,
        capsule: &[u8],
        secret: &HybridSecretKey,
    ) -> Result<()> {
        let presented = presented_escrow(label, capsule)?;
        let state = {
            let txn = self.store.env.read_txn()?;
            STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?
        };
        let key = open_wrap(
            self.vault_id().as_bytes(),
            &state.commitment,
            &presented,
            &UnlockSecret::Hybrid(secret),
        )?;
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

    /// Wraps the held vault data key to one passkey, by its PRF output,
    /// borrowed from the guard that wipes it.
    pub fn add_vault_key_passkey(
        &self,
        credential: &str,
        prf: &Zeroizing<[u8; 32]>,
    ) -> Result<VaultKeyWrapInfo> {
        let kek = passkey_kek(prf);
        check_name(credential)?;
        self.add_vault_key_wrap(
            VaultKeyWrapKind::Passkey {
                credential: credential.to_owned(),
            },
            &WrapSecret::Kek(kek),
        )
    }

    /// Seals the held vault data key to a recovery or transfer public key.
    /// The answer warns, value-free, when the key is one a retired label
    /// was released to (FIX 2857); the wrap is sealed either way.
    pub fn add_vault_key_escrow(
        &self,
        label: &str,
        recipient: &HybridPublicKey,
    ) -> Result<EscrowAdded> {
        self.add_vault_key_escrow_checked(label, recipient, None)
    }

    /// [`Self::add_vault_key_escrow`] on an owner's request, rechecked in
    /// the transaction that stores it.
    pub fn add_vault_key_escrow_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        label: &str,
        recipient: &HybridPublicKey,
    ) -> Result<EscrowAdded> {
        self.add_vault_key_escrow_checked(label, recipient, Some(owner))
    }

    /// The vault key's passkey PRF input for `credential` ([`passkey_prf_input`]).
    pub fn vault_key_passkey_prf_input(&self, credential: &str) -> Result<[u8; 32]> {
        passkey_prf_input(self.vault_id().as_bytes(), credential)
    }

    /// Adds one wrap on an owner's request: the owner is rechecked in the
    /// transaction that stores it, so a request whose slip or ownership went
    /// away while it waited adds nothing.
    pub fn add_vault_key_wrap_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        wrap: NewVaultKeyWrap<'_>,
    ) -> Result<VaultKeyWrapInfo> {
        match wrap {
            NewVaultKeyWrap::Device => {
                let (kek, kind) = self.device_kek()?;
                self.add_vault_key_wrap_checked(kind, &WrapSecret::Kek(kek), Some(owner))
            }
            NewVaultKeyWrap::Password { password, cost } => {
                let passphrase = Passphrase::new(password)
                    .map_err(|_| refused("the password is not accepted"))?;
                self.add_vault_key_wrap_checked(
                    VaultKeyWrapKind::Password,
                    &WrapSecret::Passphrase(
                        &passphrase,
                        cost.unwrap_or(Argon2Cost::RFC9106_SECOND),
                    ),
                    Some(owner),
                )
            }
            NewVaultKeyWrap::Passkey { credential, prf } => {
                let kek = passkey_kek(prf);
                check_name(credential)?;
                self.add_vault_key_wrap_checked(
                    VaultKeyWrapKind::Passkey {
                        credential: credential.to_owned(),
                    },
                    &WrapSecret::Kek(kek),
                    Some(owner),
                )
            }
            NewVaultKeyWrap::Escrow { label, recipient } => {
                check_name(label)?;
                self.add_vault_key_wrap_checked(
                    VaultKeyWrapKind::Escrow {
                        label: label.to_owned(),
                    },
                    &WrapSecret::Hybrid(recipient),
                    Some(owner),
                )
            }
        }
    }

    /// Removes one wrap. The last wrap stays: without it the key is lost.
    pub fn remove_vault_key_wrap(&self, id: &str) -> Result<()> {
        self.remove_vault_key_wrap_checked(id, None)
    }

    /// [`Self::remove_vault_key_wrap`] on an owner's request, rechecked in the
    /// transaction that removes it.
    pub fn remove_vault_key_wrap_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: &str,
    ) -> Result<()> {
        self.remove_vault_key_wrap_checked(id, Some(owner))
    }

    /// Retires the escrow recipient `label` once its secret was released (a
    /// restore by its capsule; CROSS-ARCH-0022 #ov-custody-backend: a
    /// released recipient is never reused). The vault drops the wrap
    /// `escrow:<label>` if it still carries it, and records the label as
    /// retired, so no wrap is sealed to it again; the record is the owner's
    /// receipt. On an owner's request, rechecked in the transaction. A sealed
    /// vault's page-seal mirror follows as for any wrap change. Refused for
    /// the world kit's wrap, which a new kit's confirm replaces, and when the
    /// wrap is the key's last. A label already retired returns its receipt.
    pub fn retire_vault_key_escrow_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        label: &str,
    ) -> Result<EscrowRetirement> {
        check_name(label)?;
        if label == crate::world_keys::WORLD_KIT_ESCROW {
            return Err(refused(
                "the world kit's escrow wrap is replaced by confirming a new kit, not retired",
            ));
        }
        let label = label.to_owned();
        let id = VaultKeyWrapKind::Escrow {
            label: label.clone(),
        }
        .id();
        let transition = self.begin_wrap_transition()?;
        let retirement = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if let Some(retired) = ESCROW_RETIRED.get(&self.store, txn, &label)? {
                return Ok(retired);
            }
            let held = WRAPS.get(&self.store, txn, &id)?.is_some();
            if held {
                if WRAPS.scan(&self.store, txn)?.len() <= 1 {
                    return Err(refused(
                        "the last vault key wrap stays: add another before retiring this one",
                    ));
                }
                transition.stage(|| self.staged_wraps_in_txn(txn, None))?;
                WRAPS.delete(&self.store, txn, &id)?;
                ESCROW_SPOOLED.delete(&self.store, txn, &id)?;
            }
            let retirement = EscrowRetirement {
                receipt_id: self.store.clock.entity_id()?.to_hex(),
                label: label.clone(),
                removed_wrap: held,
                retired_at: self.instant_in_txn(txn)?.secs(),
            };
            ESCROW_RETIRED.put(&self.store, txn, &label, &retirement)?;
            Ok(retirement)
        })?;
        transition.finish()?;
        Ok(retirement)
    }

    /// Every escrow label retired here, with its receipt.
    pub fn vault_key_escrow_retirements(&self) -> Result<Vec<EscrowRetirement>> {
        let txn = self.store.env.read_txn()?;
        Ok(ESCROW_RETIRED
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, retired)| retired)
            .collect())
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
        Ok(key.derive(context, self.vault_id().as_bytes()))
    }
}
