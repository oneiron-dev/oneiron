//! A revoke this install could not carry for the owner when he made it (FIX
//! 4851). The revoke door, and a ruling that a found key is no secret,
//! revoke the record here and erase its value in their own commit, whether
//! or not this install can carry the owner's act. When it cannot, because
//! it has no live machine profile in the roster or its install key is not
//! loaded, the same commit keeps a value-free intent under the record's id:
//! the owner the revoke is by, the surface he decided on (audit only), the
//! second it was made at and the generation it revoked. No proof and no
//! value is kept.
//!
//! The next pass on which this install can sign carries it, with no other
//! step from the owner (CALLS CUSTODY_REVOKE_PENDING_CARRY): the owner work
//! pickup after an authority catch-up and on the served tick, and the moment
//! this install's key loads. Each intent is judged again in a writer
//! transaction of its own, and carried exactly as the door carries a revoke
//! it can carry at once.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::super::doors::read_secret_custody_in_txn;
use super::super::transition::custody_portable;
use super::super::types::SecretCustodyStatus;
use super::{CustodyKeptHere, SecretCustodyWork};
use crate::authority::{ActSurface, AuthorityFold};
use crate::error::{Error, Result, SecretError};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// How a portable secret's revoke reaches the owner's other machines when
/// the install he revoked it on cannot carry his act yet (CALLS
/// CUSTODY_REVOKE_PENDING_CARRY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRevokePendingCarry {
    /// The revoke and its erase commit here at once, and the reply says the
    /// carry is pending. The carry waits, value-free, under the record's id,
    /// until a pass on which this install can sign: the owner work pickup
    /// after an authority catch-up and on the served tick, or the moment its
    /// install key loads. That pass checks the owner is still a live vault
    /// owner and records the ordinary byte-free revoke request, its enacted
    /// result and its revoked transition, as of the second he revoked it,
    /// dropping the intent in the same commit. A record superseded or gone,
    /// an id an admitted revoke already ended, or an owner no longer live
    /// drops it; an install that still cannot sign keeps it. A record that
    /// stays on its device is never carried.
    CarryWhenSignerLoads,
}

const CUSTODY_REVOKE_PENDING_CARRY: CustodyRevokePendingCarry =
    CustodyRevokePendingCarry::CarryWhenSignerLoads;

/// Each revoke this install still owes the owner's other machines, by
/// custody record id.
const PENDING: SideTable<EntityId, PendingRevoke, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_PENDING_REVOKE);

/// One revoke this install has not carried yet. It holds no value and no
/// proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PendingRevoke {
    /// The owner PERSON the revoke is by.
    owner: EntityId,
    /// Where he decided it: audit only.
    surface: ActSurface,
    /// The second the revoke was made at: its transition's.
    at: u64,
    /// The generation it revoked.
    generation: u32,
}

/// Whether `error` says this install's signing keys are not loaded here:
/// the one failure a revoke's carry waits out.
fn signing_unavailable(error: &Error) -> bool {
    matches!(error, Error::Secret(SecretError::KeystoreUnavailable(_)))
}

/// Whether this install can carry an owner act in `txn` now: a live machine
/// profile under its loaded install key. Keys not loaded here are a "not
/// yet", never a failure.
pub(super) fn can_carry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<bool> {
    match vault.owner_work_carrier_in_txn(txn, fold) {
        Ok(carrier) => Ok(carrier.is_some()),
        Err(error) if signing_unavailable(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Keeps the carry of `owner`'s revoke of record `id`, at `generation`,
/// pending in the revoke's own transaction (CALLS
/// CUSTODY_REVOKE_PENDING_CARRY), and returns the work that says so.
pub(super) fn defer_revoke_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    owner: EntityId,
    surface: ActSurface,
    generation: u32,
    at: u64,
) -> Result<SecretCustodyWork> {
    match CUSTODY_REVOKE_PENDING_CARRY {
        CustodyRevokePendingCarry::CarryWhenSignerLoads => {
            let pending = PendingRevoke {
                owner,
                surface,
                at,
                generation,
            };
            PENDING.put(&vault.store, txn, &id, &pending)?;
            Ok(SecretCustodyWork::kept(CustodyKeptHere::CarryPending))
        }
    }
}

/// Erasing `actor` (FIX 3520): a revoke still owed for him is dropped, so
/// no act is carried in his name. One-way, in the erase's own transaction.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_pending_revoke_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let named: Vec<EntityId> = PENDING
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, pending)| pending.owner == *actor)
        .map(|(id, _)| id)
        .collect();
    for id in &named {
        PENDING.delete(&vault.store, wtxn, id)?;
    }
    Ok(())
}

impl Vault {
    /// The revoke door's key load before its transaction: keys that are not
    /// available here leave the revoke to stand here with its carry pending
    /// (CALLS CUSTODY_REVOKE_PENDING_CARRY), never refuse it.
    ///
    /// # Errors
    /// A load that fails for any other reason.
    pub(crate) fn load_signing_for_revoke(&self) -> Result<()> {
        match self.load_install_signing_if_minted() {
            Err(error) if !signing_unavailable(&error) => Err(error),
            _ => Ok(()),
        }
    }

    /// Carries every revoke this install still owes the owner's other
    /// machines (CALLS CUSTODY_REVOKE_PENDING_CARRY), each in a writer
    /// transaction of its own. The caller loads the install key first; what
    /// it records reaches the live windows on their next refresh or open.
    /// Returns how many it carried.
    ///
    /// # Errors
    /// The first carry that failed for a reason other than keys not loaded
    /// here; the others are still tried, and each that failed stays owed.
    fn carry_pending_revokes(&self) -> Result<usize> {
        let owed: Vec<EntityId> = {
            let txn = self.store.env.read_txn()?;
            PENDING
                .scan(&self.store, &txn)?
                .into_iter()
                .map(|(id, _)| id)
                .collect()
        };
        let mut carried = 0;
        let mut failed = None;
        for id in owed {
            match self.with_write_txn(|txn| self.carry_pending_revoke_in_txn(txn, id)) {
                Ok(true) => carried += 1,
                Ok(false) => {}
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        failed.map_or(Ok(carried), Err)
    }

    /// [`Self::carry_pending_revokes`] for a pass that goes on without it,
    /// such as the install key's load: a failure is logged by kind, never
    /// with a value.
    pub(crate) fn carry_pending_revokes_logged(&self) {
        match self.carry_pending_revokes() {
            Ok(carried) if carried > 0 => {
                tracing::debug!(carried, "pending custody revokes carried");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending custody revokes were not carried on this install"
                );
            }
        }
    }

    /// The owner work pickup's arm (CALLS CUSTODY_REVOKE_PENDING_CARRY):
    /// with a revoke owed, loads this install's key, carries what it can,
    /// and mirrors what it carried into the live windows. Nothing is read
    /// from the keystore while none is owed.
    pub(crate) fn carry_owed_revokes(&self) {
        let before = match self.owed_revokes() {
            Ok(0) => return,
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "pending custody revokes were not read on this install"
                );
                return;
            }
        };
        // A key that loads now carries them as it loads; this pass carries
        // them with a key loaded before.
        let _ = self.load_install_signing_if_minted();
        self.carry_pending_revokes_logged();
        #[cfg(feature = "sync")]
        if self.owed_revokes().is_ok_and(|after| after < before) {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = before;
    }

    /// How many revokes this install still owes.
    fn owed_revokes(&self) -> Result<usize> {
        let txn = self.store.env.read_txn()?;
        Ok(PENDING.scan(&self.store, &txn)?.len())
    }

    /// Carries the revoke owed for record `id` in `txn`, judged again here:
    /// dropped when the record is gone, no longer revoked at the generation
    /// the owner revoked, ended by an admitted revoke already, or its owner
    /// is no longer a live vault owner; kept while this install cannot sign.
    fn carry_pending_revoke_in_txn(&self, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<bool> {
        let Some(pending) = PENDING.get(&self.store, txn, &id)? else {
            return Ok(false);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let record = read_secret_custody_in_txn(&self.store, txn, &id)?
            .map(|mut record| {
                record.value_bytes.zeroize();
                record
            })
            .filter(|record| {
                custody_portable(record)
                    && record.status == SecretCustodyStatus::Revoked
                    && record.rotation_generation == pending.generation
                    && !fold.custody_revoked(&id)
            });
        let live = crate::policy_model::is_live_vault_owner_in_txn(self, txn, &pending.owner)?;
        let (Some(record), true) = (record, live) else {
            PENDING.delete(&self.store, txn, &id)?;
            return Ok(false);
        };
        let carried = self
            .carry_revoke_for_in_txn(txn, pending.owner, pending.surface, id, &record, pending.at)?
            .is_some();
        if carried {
            PENDING.delete(&self.store, txn, &id)?;
        }
        Ok(carried)
    }
}
