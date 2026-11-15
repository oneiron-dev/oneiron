//! A sealed-file ruling on every install of the vault (Engine RULING
//! PLAN-SEALED-FILE-RULING-CARRY, 14 Nov 16:48; row 22 E
//! [SEALED-FILE-RULING-LOCAL]). The owner's not a secret on a file the
//! write door sealed whole lives on the bytes' mark, a row of the install
//! he answered on. His other installs get the file by sync, which runs no
//! write door, so they hold no mark of it: their masked readers were
//! refused it, and a put of the same bytes there sealed it again.
//!
//! The ruling now travels as his own owner act, an owner work request of
//! kind `file_ruling` that names the file by one digest: keyed BLAKE3 under
//! the vault's screen key, which every install derives from the vault's
//! one data key ([`super::ruled_screen`]), over [`RULED_FILE_DOMAIN`] and
//! the file's BLAKE3. The digest holds no value and is never the file's
//! plain hash, which would let anyone who reads the main log test a guess
//! of a small, structured file. Every install's owner work drain keeps the
//! digest from the fold ([`RULED`]); a store that holds no screen key tests
//! no digest, so its doors withhold and seal as they did before (fail
//! closed). The write door and the masked read test the bytes they hold
//! against it, and the drain settles an open seal the install made itself
//! of the same bytes, on its own mark.
//!
//! The ruling is carried only for a file whose mark holds no key the door
//! placed: another install holds no mark that says where such a key sits
//! (FIX SEALED-FILE-RULING-MIXED-FILE-LOCAL). It never waits on the vault
//! key (the Engine, 16:48: "do not refuse the owner while the vault key is
//! locked"): the ruling stands here at once, and its carry is owed
//! ([`OWED`], by the file's plain hash, a row of this install alone) until
//! this install holds the screen key and can sign an owner act: the next
//! unlock, or the next owner work drain. It is carried once.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::ruled_screen::RuledScreenKey;
use crate::authority::{
    ActBy, ActSurface, FILE_RULING_SEEN, FileRulingWork, OwnerAct, OwnerWorkBody, OwnerWorkOutcome,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::masked_files::masked_file_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::Vault;

/// What a ruled file's digest is keyed over ahead of the file's BLAKE3, so
/// that it never stands for a ruled value's digest.
const RULED_FILE_DOMAIN: &[u8] = b"oneiron/found-key-ruled-file/v1";

/// The files the owner ruled no secret on any install, by their keyed
/// digest, as the fold's sealed-file rulings name them.
const RULED: SideTable<[u8; 32], RuledFile, Named> = SideTable::new(&side_table::SECRET_RULED_FILE);

/// The sealed-file rulings this install made and has not carried yet, by
/// the file's BLAKE3. Never carried itself.
const OWED: SideTable<[u8; 32], OwedFileRuling, Named> =
    SideTable::new(&side_table::SECRET_RULED_FILE_OWED);

/// One ruled file as this install holds it. It holds no value and names no
/// person.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuledFile {
    /// This install's own seals of the file were settled by a drain that
    /// held the screen key; until then a drain that holds it settles them.
    seals_settled: bool,
}

/// A ruling made here, owed to the owner's other installs: the file's
/// ASSET, the owner whose act it is, and where he decided (audit only).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwedFileRuling {
    record: EntityId,
    owner: EntityId,
    surface: ActSurface,
}

/// The keyed digest of the file whose BLAKE3 is `hash`.
pub(super) fn ruled_file_digest(key: &RuledScreenKey, hash: &[u8; 32]) -> [u8; 32] {
    let mut keyed = Vec::with_capacity(RULED_FILE_DOMAIN.len() + hash.len());
    keyed.extend_from_slice(RULED_FILE_DOMAIN);
    keyed.extend_from_slice(hash);
    key.digest(&keyed)
}

/// Whether the mark of the file whose BLAKE3 is `hash` places a key the
/// write door found in it, in its bytes or a member's. Another install
/// holds no mark that says where such a key sits, so a ruling of the file
/// stays on this install (FIX SEALED-FILE-RULING-MIXED-FILE-LOCAL).
pub(super) fn mark_places_key_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<bool> {
    Ok(masked_file_in_txn(store, txn, hash)?
        .is_some_and(|file| !file.keys.is_empty() || !file.members.is_empty()))
}

/// Whether a carried sealed-file ruling holds the file whose BLAKE3 is
/// `hash` no secret here, read in `txn`: `false` while the store holds no
/// screen key, which tests no digest (fail closed).
///
/// # Errors
/// The store's.
pub(crate) fn carried_file_ruling_holds_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<bool> {
    let Some(key) = store.ruled_screen.get() else {
        return Ok(false);
    };
    Ok(RULED
        .get(store, txn, &ruled_file_digest(&key, hash))?
        .is_some())
}

/// Keeps `owner`'s ruling of the file whose BLAKE3 is `hash`, answered in
/// ASSET `record` from `surface`, owed to the owner's other installs, in
/// the ruling's own transaction.
pub(super) fn owe_file_ruling_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    hash: &[u8; 32],
    record: EntityId,
    owner: EntityId,
    surface: ActSurface,
) -> Result<()> {
    OWED.put(
        store,
        txn,
        hash,
        &OwedFileRuling {
            record,
            owner,
            surface,
        },
    )
}

/// Drops each ruling owed by `actor`, whose erase takes them (FIX 11883's
/// side-row scrub): an act no live owner made is never carried.
///
/// # Errors
/// The store's.
pub(crate) fn erase_owed_file_ruling_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (hash, owed) in OWED.scan(&vault.store, wtxn)? {
        if owed.owner == *actor {
            OWED.delete(&vault.store, wtxn, &hash)?;
        }
    }
    Ok(())
}

impl Vault {
    /// Carries the ruling owed for the file whose BLAKE3 is `hash`, in
    /// `txn`, as its owner's own act: the request and its enacted result,
    /// signed by this install, which executes it. The owed row goes with
    /// the carry, so the ruling is carried once; it goes too when the fold
    /// holds the ruling already, when its owner is no longer a live vault
    /// owner, or when the file's mark here places a key by now (a put of
    /// the same bytes marked a value custody learned since the ruling),
    /// which keeps the ruling on this install (REVIEW-7912 F3). `false`,
    /// still owed, while this install holds no screen key or cannot carry
    /// an act now.
    pub(super) fn carry_owed_file_ruling_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        hash: &[u8; 32],
    ) -> Result<bool> {
        let Some(owed) = OWED.get(&self.store, txn, hash)? else {
            return Ok(false);
        };
        if mark_places_key_in_txn(&self.store, txn, hash)? {
            OWED.delete(&self.store, txn, hash)?;
            return Ok(false);
        }
        let Some(key) = self.store.ruled_screen.get() else {
            return Ok(false);
        };
        let digest = ruled_file_digest(&key, hash);
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.ruled_files().any(|(held, _)| held == digest)
            || !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &owed.owner)?
        {
            OWED.delete(&self.store, txn, hash)?;
            return Ok(false);
        }
        if !crate::secret_custody::control::can_carry_in_txn(self, txn, &fold)? {
            return Ok(false);
        }
        let work = OwnerWorkBody::FileRuling(FileRulingWork { digest });
        let act = OwnerAct {
            owner: owed.owner,
            by: ActBy::Owner,
            surface: owed.surface,
            act: work.kind().act(),
            target: owed.record,
            seen: FILE_RULING_SEEN,
            answer: None,
        };
        let receipt = self.record_owner_work_with_act_in_txn(txn, act, work)?;
        // The carrier executes its own ruling: a request with no executor
        // is refused with its transaction, so the ruling stays owed
        // (REVIEW-7912 F6).
        let (Some(request), Some(executor)) = (receipt.request_entry(), receipt.executor) else {
            return Err(Error::InvariantViolation(
                "a carried sealed-file ruling names no executor",
            ));
        };
        self.append_owner_work_result_in_txn(
            txn,
            request,
            executor,
            OwnerWorkOutcome::Enacted { detail: None },
        )?;
        OWED.delete(&self.store, txn, hash)?;
        Ok(true)
    }

    /// What the sealed-file rulings wait on the vault data key for, done as
    /// this install holds it again, by any unlock: each ruled file's seals
    /// are due again (a put while the key was locked tested no digest, so
    /// it sealed bytes a ruling names: REVIEW-7912 F2), and each ruling
    /// owed is carried.
    pub(crate) fn resume_file_rulings_at_unlock(&self) {
        if let Err(error) = self.unsettle_ruled_file_seals() {
            tracing::warn!(
                kind = ?error.kind(),
                "the ruled files' seals were not left due on this install"
            );
        }
        self.carry_owed_file_rulings();
    }

    /// Leaves the seals of each ruled file this install settled due again,
    /// so the next drain that holds the screen key settles a seal a put
    /// made while the key was locked, in one writer transaction; none while
    /// no ruled file's seals were settled.
    fn unsettle_ruled_file_seals(&self) -> Result<()> {
        let settled: Vec<[u8; 32]> = {
            let txn = self.store.env.read_txn()?;
            RULED
                .scan(&self.store, &txn)?
                .into_iter()
                .filter(|(_, held)| held.seals_settled)
                .map(|(digest, _)| digest)
                .collect()
        };
        if settled.is_empty() {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            let due = RuledFile {
                seals_settled: false,
            };
            for digest in &settled {
                RULED.put(&self.store, txn, digest, &due)?;
            }
            Ok(())
        })
    }

    /// Carries each sealed-file ruling this install owes the owner's other
    /// installs, once it holds the screen key and can sign: as the vault
    /// data key is held again, and on the owner work drain. Each is carried
    /// in a writer transaction of its own; one that fails stays owed.
    /// Nothing is read from the keystore while none is owed.
    pub(crate) fn carry_owed_file_rulings(&self) {
        let owed = match self.owed_file_rulings() {
            Ok(owed) if owed.is_empty() => return,
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed sealed-file rulings were not read on this install"
                );
                return;
            }
        };
        if self.store.ruled_screen.get().is_none() {
            return;
        }
        // A key that loads now signs them; this pass signs them with a key
        // loaded before.
        let _ = self.load_install_signing_if_minted();
        for hash in owed {
            if let Err(error) =
                self.with_write_txn(|txn| self.carry_owed_file_ruling_in_txn(txn, &hash))
            {
                tracing::warn!(
                    kind = ?error.kind(),
                    "an owed sealed-file ruling was not carried from this install"
                );
            }
        }
    }

    /// The files whose ruling this install still owes, by their BLAKE3.
    fn owed_file_rulings(&self) -> Result<Vec<[u8; 32]>> {
        let txn = self.store.env.read_txn()?;
        Ok(OWED
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(hash, _)| hash)
            .collect())
    }

    /// Keeps each sealed-file ruling the fold holds that this install has
    /// not met yet, byte-free, in one writer transaction: its digest stands
    /// in [`RULED`], and, with the screen key held, each open seal this
    /// install made of the bytes it names is settled not a secret as its
    /// owner's answer, with its Gate receipt, on this install's own mark,
    /// whose placed keys stay. Without the screen key the digests stand and
    /// the seals wait for a drain that holds it. The owner work drain runs
    /// it; the fold is its only input. Returns how many seals it settled.
    pub(crate) fn settle_ruled_files(&self) -> Result<usize> {
        let key = self.store.ruled_screen.get();
        let due = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let mut due = Vec::new();
            for (digest, owner) in fold.ruled_files() {
                let waits = match RULED.get(&self.store, &txn, &digest)? {
                    None => true,
                    Some(held) => !held.seals_settled && key.is_some(),
                };
                if waits {
                    due.push((digest, owner));
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            let settled = match &key {
                Some(key) => super::sealed_file::settle_ruled_seals_in_txn(self, txn, key, &due)?,
                None => 0,
            };
            let held = RuledFile {
                seals_settled: key.is_some(),
            };
            for (digest, _) in &due {
                RULED.put(&self.store, txn, digest, &held)?;
            }
            Ok(settled)
        })
    }
}
