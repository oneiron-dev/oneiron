//! The holder's own rewrap when the roster gains one of the owner's machines
//! (WILL L04 row 04, CALLS CUSTODY_ROSTER_REWRAP).
//!
//! Before custody changes became requests, every portable value was sealed
//! again to each machine mine here after that machine's admission and on
//! the sync upkeep (FIX 1780), so a machine the owner made his got his
//! secrets with no step of his. That stays, as a request: an install that
//! holds a secret's current bytes, itself mine here, records the rewrap as
//! its own holder and enacts it in the same commit, its permits the ones
//! sealed now plus each such machine's exact permit. The act is the owner's
//! whose answer made the machine his; he never acts again. The machines are
//! exactly the ones that reseal sealed to (mine under this install's pin,
//! with a key that imports), and the installs that record are exactly the
//! ones that resealed, so nothing widens or narrows. A linked machine that is
//! not his still gets nothing without an explicit rewrap (CALLS
//! CUSTODY_PERMITS).
//!
//! It never rotates: a rewrap keeps the generation and status. A secret the
//! permits already name the machine for, at its current generation, sealed
//! or pending, is left alone, so a second pass writes nothing. Two holders
//! that rewrap at once each record a counted request at the same revision;
//! both are same-generation reseals, and every receiver settles on one
//! carrier. A record that stays on its device, a terminal id and a machine
//! whose key does not import get nothing, as before.

use oneiron_crypto::HybridPublicKey;

use super::super::read_secret_custody_meta_in_txn;
use super::super::transition::{CustodyPieces, custody_portable, held_transitions_in_txn};
use super::super::types::SecretCustodyStatus;
use super::permits::{permit_for, permitted_keys};
use super::{ActiveChange, CustodyPlan, Material};
use crate::authority::{
    ActSurface, AuthorityFold, CustodyChange, CustodyRecipientPermit, OwnerWorkBody,
};
use crate::error::Result;
use crate::world_keys::OwnerWorkStatus;
use crate::{EntityId, Vault};

/// How a holder meets a machine the roster gains (CALLS
/// CUSTODY_ROSTER_REWRAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRosterRewrap {
    /// A holder mine here records the rewrap to each machine main's
    /// automatic reseal sealed to, as its own holder, in one commit.
    HolderRecordsOnOwnMachineGain,
}

const CUSTODY_ROSTER_REWRAP: CustodyRosterRewrap =
    CustodyRosterRewrap::HolderRecordsOnOwnMachineGain;

/// The machines the retired automatic reseal sealed a portable value to:
/// each machine mine under this install's pin whose encryption key imports.
/// The predicate is that reseal's, verbatim.
fn own_machines(fold: &AuthorityFold) -> Vec<EntityId> {
    fold.machines
        .keys()
        .filter_map(|machine| {
            let trusted = fold.trusted_machine(*machine)?;
            // A profile whose key does not import could open nothing.
            HybridPublicKey::from_bytes(&trusted.profile.encryption_key.key).ok()?;
            Some(*machine)
        })
        .collect()
}

/// One rewrap a pass records.
struct Due {
    id: EntityId,
    generation: u32,
    permits: Vec<CustodyRecipientPermit>,
    /// The owner whose answer made the first machine it adds his.
    actor: EntityId,
}

/// Whether `permits` name `permit`'s machine under the very key it has.
fn names(permits: &[CustodyRecipientPermit], permit: &CustodyRecipientPermit) -> bool {
    permits
        .iter()
        .any(|held| held.machine == permit.machine && held.encryption_key == permit.encryption_key)
}

impl Vault {
    /// Seals each portable secret this install holds the current bytes of
    /// again for every machine mine here its permits do not name yet (CALLS
    /// CUSTODY_ROSTER_REWRAP): one custody rewrap request per secret, this
    /// install its holder, enacted in the same commit. Nothing is recorded
    /// when this install is not itself mine under its pin, as before. A
    /// committed machine admission (`reseal_after_machine_admission`, FIX
    /// 1780) and the sync lane's upkeep tick run it, as they ran the reseal it
    /// replaces. Returns how many it enacted; one that fails is logged, and
    /// the next pass tries again.
    pub(crate) fn reseal_custody_for_roster(&self) -> Result<usize> {
        // The install key loads before any transaction opens; with none,
        // this install reseals nothing, as before.
        let _ = self.load_install_signing_if_minted();
        let due = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
                return Ok(0);
            };
            let Ok(Some(signing)) = crate::identity::read_machine_signing_key_in_txn(self, &txn)
            else {
                return Ok(0);
            };
            let reseals = match CUSTODY_ROSTER_REWRAP {
                CustodyRosterRewrap::HolderRecordsOnOwnMachineGain => {
                    fold.pinned_root.is_some()
                        && fold.trusted_machine(machine).is_some_and(|trusted| {
                            trusted.profile.machine_key == signing.verifying_key().to_bytes()
                        })
                }
            };
            if !reseals {
                return Ok(0);
            }
            let own = own_machines(&fold);
            let mut due = Vec::new();
            for held in held_transitions_in_txn(self, &txn)? {
                if let Some(rewrap) = self.rewrap_due_in_txn(&txn, &fold, &own, &held)? {
                    due.push(rewrap);
                }
            }
            due
        };
        let at = self.now_recorded_at();
        let mut enacted = 0;
        for rewrap in &due {
            match self.with_write_txn(|txn| self.record_roster_rewrap_in_txn(txn, rewrap, at)) {
                Ok(true) => enacted += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a portable secret was not rewrapped to the owner's new machine; the next \
                         pass tries again"
                    );
                }
            }
        }
        if enacted > 0 {
            self.refresh_custody_in_live_windows();
        }
        Ok(enacted)
    }

    /// The rewrap a held transition is due, read in `txn`: this install
    /// holds the record at the transition's generation and status, live and
    /// portable, its id is not terminal, and some machine of `own` is named
    /// neither by the permits still standing nor by a pending request at
    /// that generation. Its permits are the standing ones, with each added
    /// machine's fresh permit in place of one whose key changed, however
    /// many (FIX 7951: never skipped; its writer measures them). A transition whose pieces
    /// are not all here yet, or do not carry its whole set
    /// ([`CustodyPieces::whole`]), waits for them: its standing set is not
    /// whole, and the next pass judges it again.
    fn rewrap_due_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        own: &[EntityId],
        held: &CustodyPieces,
    ) -> Result<Option<Due>> {
        let pieces = held;
        let held = pieces.lead();
        if held.status == SecretCustodyStatus::Revoked
            || fold.custody_revoked(&held.id)
            || !pieces.whole()
        {
            return Ok(None);
        }
        let Some(record) = read_secret_custody_meta_in_txn(&self.store, txn, &held.id)? else {
            return Ok(None);
        };
        if !custody_portable(&record)
            || record.rotation_generation != held.generation
            || record.status != held.status
        {
            return Ok(None);
        }
        let standing: Vec<CustodyRecipientPermit> = pieces
            .permits()
            .copied()
            .filter(|permit| permitted_keys(fold, std::slice::from_ref(permit)).is_some())
            .collect();
        let pending: Vec<&[CustodyRecipientPermit]> = fold
            .custody_heads(held.id)
            .into_iter()
            .filter(|(hash, _)| fold.owner_work_result(hash).is_none())
            .filter_map(|(_, request)| match &request.work {
                OwnerWorkBody::Custody {
                    change: CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap,
                    generation,
                    recipients,
                    ..
                } if *generation == held.generation => Some(recipients.as_slice()),
                _ => None,
            })
            .collect();
        let added: Vec<CustodyRecipientPermit> = own
            .iter()
            .filter_map(|machine| permit_for(fold, *machine))
            .filter(|permit| {
                !names(&standing, permit) && !pending.iter().any(|named| names(named, permit))
            })
            .collect();
        let Some(actor) = added
            .first()
            .and_then(|first| fold.trusted_machine(first.machine))
            .map(|trusted| trusted.profile.owner)
        else {
            return Ok(None);
        };
        let mut permits = standing;
        permits.retain(|permit| !added.iter().any(|fresh| fresh.machine == permit.machine));
        permits.extend(added);
        permits.sort_unstable_by_key(|permit| permit.machine);
        Ok(Some(Due {
            id: held.id,
            generation: held.generation,
            permits,
            actor,
        }))
    }

    /// Records and enacts one rewrap a pass found due, rechecked in `txn`:
    /// the id is not terminal, the record still stands at its generation,
    /// and the act's owner is still a live vault owner. Returns whether it
    /// was enacted here.
    fn record_roster_rewrap_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        rewrap: &Due,
        at: u64,
    ) -> Result<bool> {
        if self
            .authority_view_readonly_in_txn(txn)?
            .custody_revoked(&rewrap.id)
            || !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &rewrap.actor)?
        {
            return Ok(false);
        }
        let Some(record) = read_secret_custody_meta_in_txn(&self.store, txn, &rewrap.id)? else {
            return Ok(false);
        };
        if record.rotation_generation != rewrap.generation
            || record.status == SecretCustodyStatus::Revoked
        {
            return Ok(false);
        }
        let plan = CustodyPlan::default();
        let recorded = self.record_custody_change_in_txn(
            txn,
            rewrap.actor,
            // Audit only: the upkeep on this install recorded it.
            ActSurface::ThisInstall,
            ActiveChange {
                change: CustodyChange::Rewrap,
                id: rewrap.id,
                generation: rewrap.generation,
                plan: &plan,
                material: Material::Held,
                sealed: None,
                seen: None,
                permits: Some(&rewrap.permits),
            },
            at,
        )?;
        Ok(recorded
            .custody
            .work
            .is_some_and(|work| work.status == OwnerWorkStatus::Enacted))
    }
}
