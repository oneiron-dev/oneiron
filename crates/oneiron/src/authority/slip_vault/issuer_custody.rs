//! Where a vault's host issuer seed is kept (FIX-LIST 3018): this install's
//! own `HostIssuerSeed` slot for the vault, in the this-device-only keystore
//! the host installed. The seed is drawn once, independently
//! ([`new_host_issuer_seed`]), when this install roots a vault no root,
//! replica or restore has reached; never from auth_secret, the DEK or the
//! vault id, which name the slot and take no part in the key.
//!
//! Five operations, never one load-or-create on every open: a load reads
//! the slot and writes nothing; a bootstrap fills an empty slot only for an
//! unstarted vault, before its signed genesis; an explicit re-root draws its
//! successor; a kit recovery draws one for a root this install lost (L1-07);
//! a validated replacement is written in place. A missing seed is
//! key unavailability: nothing falls back to a key derived from a configured
//! secret, and nothing mints a successor silently.
//!
//! The SAME seed reaches a new install through the vault's protected key
//! custody (FIX-LIST 10770; `store::host_issuer_custody`). Each act that
//! makes a seed stand (a bootstrap, a re-root, a validated replacement)
//! escrows it there after it succeeds, and a host that installs its
//! keystore escrows a held seed of the live root that custody lacks: best
//! effort, a fault warned and the act kept. A new install's empty slot
//! takes back an escrowed seed only when its issuer is the vault's live
//! root in the current fold, create-only, before any issuer loads
//! ([`Vault::prepare_host_issuer_custody_logged`]). Neither ever refuses,
//! replaces a filled slot or mints a seed: an install with no seed of the
//! live root stays rootless, as before.

use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, SlotKind};

use super::issuer_seed::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, new_host_issuer_seed};
use super::require_host;
use crate::Vault;
use crate::error::{Error, Result, SecretError};
use crate::world_keys::keystore_error;

use crate::authority::{HostIssuerSeedSlot, HostReRoot, authority_refused};
use crate::store::recovery_kit::RestoredKitSecret;

/// This install holds no host issuer seed for this vault: it never rooted
/// it, its keystore lost the slot, or the host installed no keystore.
const HOST_ISSUER_SEED_ABSENT: &str = "this install holds no host issuer seed for this vault";

/// The slot an explicit re-root keeps its successor in emptied before the
/// root moved: nothing was re-rooted, and no seed was kept.
const HOST_ISSUER_SEED_SLOT_EMPTIED: &str =
    "this install's host issuer seed slot emptied before the re-root; nothing moved";

/// The issuer a re-root names is not the one this install's slot holds the
/// seed of: nothing moved, and the slot keeps its own seed.
const HOST_ISSUER_SEED_NOT_CURRENT: &str =
    "this install's host issuer seed is not the issuer the re-root names; nothing moved";

/// This install's slot holds the seed of the vault's live root, so the root
/// is not lost here: a kit recovery moves nothing (L1-07).
const HOST_ROOT_HELD: &str =
    "this install holds the vault's live root; move it with `oneiron host re-root`";

/// Typed reason: this install's host issuer seed is not escrowed in the
/// vault's key custody yet. The act that drew or kept it stands; the next
/// keystore install escrows it again.
const HOST_ISSUER_ESCROW_PENDING: &str = "host_issuer_escrow_pending";

/// Typed reason: the vault's key custody holds host issuer seeds, but none
/// is the vault's live root in the current fold, so this install's empty
/// slot stays empty and the vault stays rootless here.
const HOST_ISSUER_RECOVERY_MISMATCH: &str = "host_issuer_recovery_mismatch";

fn seed_absent() -> Error {
    Error::Secret(SecretError::KeystoreUnavailable(HOST_ISSUER_SEED_ABSENT))
}

/// One host root move at a time in this process. A move reads this
/// install's slot, writes its successor seed there, moves the root, and on a
/// failure puts back the slot it read; two moves interleaved would let the
/// losing one's put-back delete or overwrite the winner's live seed. Across
/// processes, the vault's writer lease admits one opener at a time.
static HOST_ROOT_MOVES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes [`HOST_ROOT_MOVES`] for one move. A move that panicked while
/// holding it left the slot in an unknown state, so the next one refuses.
fn lock_host_root_moves() -> Result<std::sync::MutexGuard<'static, ()>> {
    HOST_ROOT_MOVES
        .lock()
        .map_err(|_| Error::InvariantViolation("host root move lock poisoned"))
}

/// Puts this install's `slot` back as a root move read it (`kept`: its
/// seed, or `None` for an empty slot) after the move, or the keystore write
/// of its successor seed, failed. A keystore can fault after the successor's
/// bytes became visible (a directory sync after the rename), so a failed
/// write is put back too. Only a slot holding the successor (`staged`) is
/// changed: a write that faulted before it published leaves the slot as it
/// was, and a slot holding any other seed is not this move's. A put-back that
/// fails is the error, never a report of an unchanged slot.
fn put_back_host_issuer_slot(
    keystore: &dyn DeviceKeystore,
    slot: &KeystoreSlot,
    kept: Option<&[u8; HOST_ISSUER_SEED_BYTES]>,
    staged: &HostSlipIssuer,
) -> Result<()> {
    let held = keystore.get(slot).map_err(keystore_error)?;
    let Some(held) = held else {
        return match kept {
            None => Ok(()),
            Some(_) => Err(Error::InvariantViolation(HOST_ISSUER_SEED_SLOT_EMPTIED)),
        };
    };
    if HostSlipIssuer::from_seed(&held)?.binding_key() != staged.binding_key() {
        return Ok(());
    }
    match kept {
        None => keystore.delete(slot).map_err(keystore_error),
        Some(seed) => match keystore.replace(slot, seed) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::InvariantViolation(HOST_ISSUER_SEED_SLOT_EMPTIED)),
            Err(restore) => Err(keystore_error(restore)),
        },
    }
}

/// What [`Vault::recover_host_issuer_seed`] found in this install's slot.
enum HostIssuerSeedRecovery {
    /// The slot holds a seed, read and left as it is: its issuer.
    Present(HostSlipIssuer),
    /// The slot was empty and took the escrowed seed of the live root.
    Recovered,
    /// The slot is empty, and the vault's custody holds no seed.
    Missing,
    /// The slot is empty, and no seed the custody holds is the live root.
    RootMismatch,
}

impl Vault {
    /// This install's host issuer for this vault, from its `HostIssuerSeed`
    /// slot. Read-only: an empty slot, an install with no machine identity,
    /// or a host with no keystore is key unavailability, never a new seed.
    pub fn load_host_slip_issuer(&self) -> Result<HostSlipIssuer> {
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        let seed = keystore
            .get(&slot)
            .map_err(keystore_error)?
            .ok_or_else(seed_absent)?;
        HostSlipIssuer::from_seed(&seed)
    }

    /// The issuer a start that may root this vault signs with. On a vault
    /// whose authority no root, replica or restore has reached (no log row,
    /// no pin, no adopted checkpoint), this install's empty slot takes one
    /// fresh independent seed first, before the genesis it signs; the slot
    /// is create-only, so a concurrent first use keeps the first seed. On
    /// any other vault it only loads ([`Self::load_host_slip_issuer`]): an
    /// established root is never reminted here.
    pub fn bootstrap_host_slip_issuer(&self) -> Result<HostSlipIssuer> {
        if !self.authority_is_unstarted()? {
            return self.load_host_slip_issuer();
        }
        let keystore = self.device_keystore()?;
        self.prepare_install_signing()?;
        let slot = self.host_issuer_slot()?;
        if keystore.get(&slot).map_err(keystore_error)?.is_none() {
            let seed = new_host_issuer_seed()?;
            match keystore.create(&slot, &seed) {
                Ok(()) | Err(KeystoreError::AlreadyExists) => {}
                Err(error) => return Err(keystore_error(error)),
            }
        }
        let issuer = self.load_host_slip_issuer()?;
        // The slot's winning seed, never a losing concurrent draw, is
        // escrowed (FIX-LIST 10770); a fault leaves the bootstrap as it is.
        self.escrow_host_slip_issuer_logged(&issuer);
        Ok(issuer)
    }

    /// Moves this vault's root from `current`, this install's loaded issuer,
    /// to a successor seed drawn here (OF-455 through
    /// [`Self::re_root_host`]): the owner's explicit act, never a repair.
    /// The slot's own seed is read first, and a `current` that seed does not
    /// make is refused before anything moves. The successor then takes the
    /// slot in place, so a root that moved always has its seed kept; a
    /// re-root that then fails, or a successor write the keystore faulted
    /// on, puts the seed read back (`put_back_host_issuer_slot`). A
    /// keystore with no in-place replace keeps nothing and moves nothing.
    pub fn re_root_host_to_new_seed(&self, current: &HostSlipIssuer) -> Result<HostReRoot> {
        let _moving = lock_host_root_moves()?;
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        let kept = keystore
            .get(&slot)
            .map_err(keystore_error)?
            .ok_or_else(seed_absent)?;
        if HostSlipIssuer::from_seed(&kept)?.binding_key() != current.binding_key() {
            return Err(authority_refused(HOST_ISSUER_SEED_NOT_CURRENT));
        }
        let next_seed = new_host_issuer_seed()?;
        let next = HostSlipIssuer::from_seed(&next_seed)?;
        let staged = match keystore.replace(&slot, &next_seed) {
            Ok(true) => Ok(()),
            Ok(false) => return Err(seed_absent()),
            Err(error) => Err(keystore_error(error)),
        };
        match staged.and_then(|()| self.re_root_host(current, &next)) {
            Ok(moved) => Ok(moved),
            Err(error) => {
                put_back_host_issuer_slot(&*keystore, &slot, Some(&*kept), &next)?;
                Err(error)
            }
        }
    }

    /// Recovers this vault's root on this install after its seed is lost
    /// (L1-07; OF-570): a successor seed drawn here takes this install's
    /// slot, and the restored kit's enrolled authority key moves the root to
    /// it (`Self::recover_host_root_from_kit`). Refused before any draw
    /// when the slot holds the live root's seed, one the escrow gave back at
    /// keystore install included: that root moves by re-root. An empty slot
    /// is filled create-only; a slot holding a retired seed is replaced in
    /// place. A recovery that then fails, or whose successor write the
    /// keystore faulted on, leaves the slot as it was: emptied again, or its
    /// retired seed put back (`put_back_host_issuer_slot`); a slot another
    /// seed filled first is left to it. One root move runs at a time in this
    /// process, this and a re-root alike.
    pub fn recover_host_root_to_new_seed(&self, secret: RestoredKitSecret) -> Result<HostReRoot> {
        let _moving = lock_host_root_moves()?;
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        let kept = keystore.get(&slot).map_err(keystore_error)?;
        if let Some(seed) = &kept
            && self.is_live_root(&HostSlipIssuer::from_seed(seed)?)?
        {
            return Err(authority_refused(HOST_ROOT_HELD));
        }
        let next_seed = new_host_issuer_seed()?;
        let next = HostSlipIssuer::from_seed(&next_seed)?;
        let staged = if kept.is_some() {
            match keystore.replace(&slot, &next_seed) {
                Ok(true) => Ok(()),
                Ok(false) => return Err(seed_absent()),
                Err(error) => Err(keystore_error(error)),
            }
        } else {
            keystore.create(&slot, &next_seed).map_err(keystore_error)
        };
        match staged.and_then(|()| self.recover_host_root_from_kit(secret, &next)) {
            Ok(moved) => Ok(moved),
            Err(error) => {
                put_back_host_issuer_slot(&*keystore, &slot, kept.as_deref(), &next)?;
                Err(error)
            }
        }
    }

    /// Writes `seed`, already validated as a live owner key of the settled
    /// root, over this install's filled `HostIssuerSeed` slot in place.
    /// `Ok(false)` when the slot is empty: a replace never fills one.
    pub(in crate::authority) fn replace_host_issuer_seed(
        &self,
        install: crate::EntityId,
        seed: &[u8; HOST_ISSUER_SEED_BYTES],
    ) -> std::result::Result<bool, KeystoreError> {
        let keystore = self
            .device_keystore()
            .map_err(|_| KeystoreError::Unavailable("the host installed no keystore"))?;
        keystore.replace(&self.issuer_slot_for(install), seed)
    }

    /// Whether this install's `HostIssuerSeed` slot for this vault, the one
    /// [`Self::load_host_slip_issuer`] reads and a validated re-key replaces
    /// in place ([`Self::replace_retained_host_root_secret`]), holds a seed
    /// now (FIX-LIST 11108). Read-only, and no byte leaves it: an install
    /// with no machine identity names no slot, so it is empty. A host with
    /// no keystore, or a keystore fault, is the error.
    pub fn host_issuer_seed_slot(&self) -> Result<HostIssuerSeedSlot> {
        let keystore = self.device_keystore()?;
        let txn = self.store.env.read_txn()?;
        let install = crate::identity::read_machine_id_in_txn(self, &txn)?;
        drop(txn);
        let Some(install) = install else {
            return Ok(HostIssuerSeedSlot::Empty);
        };
        let held = keystore
            .get(&self.issuer_slot_for(install))
            .map_err(keystore_error)?;
        Ok(if held.is_some() {
            HostIssuerSeedSlot::Filled
        } else {
            HostIssuerSeedSlot::Empty
        })
    }

    /// Empties this install's `HostIssuerSeed` slot for this vault and
    /// retires every escrowed generation of the seed, for the integration
    /// tests' door (L1-07): the install has lost its seed, and the vault's
    /// key custody can give none back, as a dead keystore beside a pending
    /// or unreadable escrow leaves it.
    #[cfg(oneiron_test_support)]
    pub(crate) fn lose_host_issuer_seed_for_test(&self) -> Result<()> {
        let keystore = self.device_keystore()?;
        let slot = self.host_issuer_slot()?;
        keystore.delete(&slot).map_err(keystore_error)?;
        self.store.retire_host_issuer_seed_escrow_for_test()
    }

    /// This install's `HostIssuerSeed` slot for this vault, by the machine
    /// id it holds; none before it holds one.
    fn host_issuer_slot(&self) -> Result<KeystoreSlot> {
        let txn = self.store.env.read_txn()?;
        let install =
            crate::identity::read_machine_id_in_txn(self, &txn)?.ok_or_else(seed_absent)?;
        Ok(self.issuer_slot_for(install))
    }

    fn issuer_slot_for(&self, install: crate::EntityId) -> KeystoreSlot {
        KeystoreSlot {
            vault_id: *self.vault_id().as_bytes(),
            install: *install.as_bytes(),
            kind: SlotKind::HostIssuerSeed,
        }
    }

    /// Escrows `issuer`'s seed, the one this install's slot holds for this
    /// vault, in the vault's protected key custody (FIX-LIST 10770), after
    /// the act that made it stand. Best effort: a fault is warned by its
    /// typed reason and the error's kind, never a byte, and the act stands
    /// as it was. An issuer whose retained bytes are not the seed that
    /// makes it (one a configured secret derives) has no seed to escrow.
    pub(in crate::authority) fn escrow_host_slip_issuer_logged(&self, issuer: &HostSlipIssuer) {
        let Ok(seed) = <&[u8; HOST_ISSUER_SEED_BYTES]>::try_from(issuer.secret()) else {
            return;
        };
        if !HostSlipIssuer::from_seed(seed)
            .is_ok_and(|made| made.binding_key() == issuer.binding_key())
        {
            return;
        }
        if let Err(error) = self.store.escrow_host_issuer_seed(seed) {
            tracing::warn!(
                reason = HOST_ISSUER_ESCROW_PENDING,
                kind = ?error.kind(),
                "this install's host issuer seed was not escrowed in the vault's key custody; \
                 the seed stands here, and a later keystore install escrows it"
            );
        }
    }

    /// Keeps this install's host issuer seed for this vault and its escrow
    /// in the vault's protected key custody in step (FIX-LIST 10770), for a
    /// host that just installed its keystore and loaded its signing keys,
    /// or opens the vault with its host root, before any issuer loads. An
    /// empty slot takes back the escrowed seed whose issuer is the vault's
    /// live root in the current fold, create-only; a filled slot is only
    /// read, and its seed escrowed when it is that root and custody lacks
    /// it. Never refuses, never replaces a filled slot, never draws a seed:
    /// no seed of the live root, or a fault, is warned by its typed reason,
    /// and the host goes on as an install holding no issuer does.
    pub fn prepare_host_issuer_custody_logged(&self) {
        if self.device_keystore_assurance().is_none() {
            return;
        }
        match self.recover_host_issuer_seed() {
            Ok(HostIssuerSeedRecovery::Present(issuer)) => match self.is_live_root(&issuer) {
                Ok(true) => self.escrow_host_slip_issuer_logged(&issuer),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    reason = HOST_ISSUER_ESCROW_PENDING,
                    kind = ?error.kind(),
                    "this install's host issuer seed was not checked against the vault's root, \
                     so it was not escrowed this time"
                ),
            },
            Ok(HostIssuerSeedRecovery::Recovered) => tracing::info!(
                "this install's empty host issuer seed slot took back the vault's escrowed seed \
                 of its live root"
            ),
            Ok(HostIssuerSeedRecovery::Missing) => tracing::debug!(
                reason = HOST_ISSUER_SEED_ABSENT,
                "the vault's key custody holds no host issuer seed for this install to take back"
            ),
            Ok(HostIssuerSeedRecovery::RootMismatch) => tracing::warn!(
                reason = HOST_ISSUER_RECOVERY_MISMATCH,
                "no host issuer seed the vault's key custody holds is its live root, so this \
                 install's slot stays empty and it signs nothing as the root"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "this install's host issuer seed slot was not recovered from the vault's key \
                 custody; nothing was written to it"
            ),
        }
    }

    /// [`Self::prepare_host_issuer_custody_logged`]'s one keystore act. This
    /// install's signing keys load first, so the slot is named by its own
    /// machine id, never a restored install's. A filled slot is read and
    /// left. For an empty one, the custody's live seeds are read, newest
    /// first; then, under an LMDB writer that commits nothing, so no root
    /// move lands between the check and the create, the first whose issuer
    /// is a live owner key of the vault's one settled root
    /// ([`require_host`]) fills the slot, create-only. A slot a concurrent
    /// first use filled keeps its seed.
    fn recover_host_issuer_seed(&self) -> Result<HostIssuerSeedRecovery> {
        let keystore = self.device_keystore()?;
        let install = self.prepare_install_signing()?;
        let slot = self.issuer_slot_for(install);
        if let Some(seed) = keystore.get(&slot).map_err(keystore_error)? {
            return HostSlipIssuer::from_seed(&seed).map(HostIssuerSeedRecovery::Present);
        }
        let candidates = self.store.host_issuer_seed_candidates()?;
        if candidates.is_empty() {
            return Ok(HostIssuerSeedRecovery::Missing);
        }
        let wtxn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&wtxn)?;
        let Some(seed) = candidates.iter().find(|seed| {
            HostSlipIssuer::from_seed(seed).is_ok_and(|issuer| require_host(&fold, &issuer).is_ok())
        }) else {
            return Ok(HostIssuerSeedRecovery::RootMismatch);
        };
        let created = keystore.create(&slot, seed);
        drop(wtxn);
        match created {
            Ok(()) => Ok(HostIssuerSeedRecovery::Recovered),
            Err(KeystoreError::AlreadyExists) => {
                let seed = keystore
                    .get(&slot)
                    .map_err(keystore_error)?
                    .ok_or_else(seed_absent)?;
                HostSlipIssuer::from_seed(&seed).map(HostIssuerSeedRecovery::Present)
            }
            Err(error) => Err(keystore_error(error)),
        }
    }

    /// Whether `issuer` is a live owner key of the vault's one settled root
    /// now ([`require_host`]).
    fn is_live_root(&self, issuer: &HostSlipIssuer) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(require_host(&fold, issuer).is_ok())
    }
}

impl Vault {
    /// Keeps a transferred candidate only when its issuer is this vault's
    /// live root now. The owner and fold are checked in the escrow writer,
    /// before any destination binding or secret is published.
    pub(crate) fn escrow_transferred_host_issuer_seed_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        seed: &[u8; HOST_ISSUER_SEED_BYTES],
    ) -> Result<Option<bool>> {
        let issuer = HostSlipIssuer::from_seed(seed)?;
        self.store.escrow_host_issuer_seed_checked(seed, |txn| {
            owner.revalidate_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            Ok(require_host(&fold, &issuer).is_ok())
        })
    }
}
