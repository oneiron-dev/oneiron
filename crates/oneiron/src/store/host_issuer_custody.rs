//! The host issuer seed's custody client (FIX-LIST 10770, the remainder of
//! FIX-LIST 3018): the escrow of a vault's host issuer seed, the same bytes
//! an install's this-device-only `HostIssuerSeed` keystore slot holds.
//!
//! The seed is one subject per vault: kind `HostIssuerSeed`, an empty item.
//! Each seed the vault's root signs with takes one generation: 0 for the
//! first, one more for each seed after it (a re-root's successor, a
//! validated replacement); a seed the newest live generation already holds
//! is not published again. It is published with the bytes its caller
//! supplies, never minted here, in a writer of its own that pins the
//! binding, after the act that made the seed stand: an escrow that fails
//! undoes nothing. It rides the custody head's compartment the head's
//! `HOST_ISSUER_SEED_CUSTODY_SCOPE` names, so a restore that lands the head
//! brings it back; a side restore carries every live generation it can
//! read, never required. No row names a generation and nothing retires
//! one: a new install's empty slot takes a live generation only when its
//! issuer is the vault's live root in the current fold
//! (`authority::slip_vault::issuer_custody`), so an older seed kept here
//! authorizes nothing. No seed leaves this crate but into that slot.

use zeroize::Zeroizing;

use crate::authority::HOST_ISSUER_SEED_BYTES;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySecret, CustodySubject, EntryState,
    LocalCustody, custody_present,
};

/// Hook (CALLS "L02 FIX 10770 side-restore copy carries the issuer seed",
/// open): a side restore plans the seed's live generations, optional, so
/// its copy's install may take the same seed back and sign as the vault's
/// live root, as a restore in the vault's place does. `false` leaves every
/// seed in its source's custody, and the copy serves rootless.
const SIDE_RESTORE_CARRIES_HOST_ISSUER_SEED: bool = true;

/// The seed's subject in `binding`'s custody: a singleton, its item empty.
pub(in crate::store) fn issuer_seed_subject(binding: &CustodyBinding) -> Result<CustodySubject> {
    binding.subject(CustodyKind::HostIssuerSeed, &[])
}

/// Plans every live generation of the seed in `bound`, the custody a
/// restore's image binds, through `plan` as optional, so a side restore
/// copies what it can read and its copy's install may take the seed back.
/// Never a requirement: a seed custody lacks or cannot read is warned by
/// the error's kind, and the restore goes on without it.
pub(in crate::store) fn plan_host_issuer_seed_custody(
    plan: &mut CustodyPlan,
    bound: &CustodyBinding,
) {
    if !SIDE_RESTORE_CARRIES_HOST_ISSUER_SEED {
        return;
    }
    if let Err(error) = plan_live_seeds(plan, bound) {
        tracing::warn!(
            kind = ?error.kind(),
            "the host issuer seed's custody did not read for this restore's plan; \
             the copy carries no seed from it"
        );
    }
}

fn plan_live_seeds(plan: &mut CustodyPlan, bound: &CustodyBinding) -> Result<()> {
    if !custody_present(bound.root())? {
        return Ok(());
    }
    let custody = LocalCustody::at(bound);
    let subject = issuer_seed_subject(bound)?;
    let Some(newest) = custody.newest_generation(&subject)? else {
        return Ok(());
    };
    for generation in 0..=newest {
        let id = subject.at(generation);
        if custody.state(&id)? == EntryState::Live {
            plan.require_present(&id)?;
        }
    }
    Ok(())
}

/// A seed's bytes, copied out of a custody secret: exactly 32.
fn copy_seed(secret: &[u8]) -> Result<Zeroizing<[u8; HOST_ISSUER_SEED_BYTES]>> {
    let mut seed = Zeroizing::new([0; HOST_ISSUER_SEED_BYTES]);
    if secret.len() != seed.len() {
        return Err(CustodyKind::HostIssuerSeed.corrupt());
    }
    seed.copy_from_slice(secret);
    Ok(seed)
}

impl Store {
    /// Escrows `seed`, the host issuer seed an install's slot holds for this
    /// vault, as the newest generation of its custody subject, in a writer
    /// of its own that pins the binding: the entry synced and its Mint
    /// journaled before the writer commits. A seed the newest live
    /// generation already holds is not published again; any other takes the
    /// generation past every one the subject has. The bytes are the
    /// caller's, never minted. True when it published one; false for one
    /// already held, or an archived vault, whose custody is its
    /// replacement's.
    ///
    /// # Errors
    ///
    /// Custody and storage faults. The caller warns; nothing it did is
    /// undone.
    pub(crate) fn escrow_host_issuer_seed(
        &self,
        seed: &[u8; HOST_ISSUER_SEED_BYTES],
    ) -> Result<bool> {
        if self.core.gate_custody_archived() {
            return Ok(false);
        }
        let mut wtxn = self.env.write_txn()?;
        self.core.key_custody.pin_in_txn(self, &mut wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, &wtxn)?;
        let subject = issuer_seed_subject(custody.binding())?;
        let newest = custody.newest_generation(&subject)?;
        if let Some(newest) = newest {
            let id = subject.at(newest);
            if custody.state(&id)? == EntryState::Live
                && custody
                    .read(&id)
                    .is_ok_and(|held| held.expose() == seed.as_slice())
            {
                return Ok(false);
            }
        }
        let generation = match newest {
            None => 0,
            Some(newest) => newest.checked_add(1).ok_or(Error::ArithmeticOverflow(
                "host issuer seed custody generation",
            ))?,
        };
        let secret = CustodySecret::from_bytes(Zeroizing::new(seed.to_vec()));
        custody.publish_minted(&subject.at(generation), &secret)?;
        wtxn.commit()?;
        Ok(true)
    }

    /// Every live host issuer seed this vault's custody holds, newest
    /// generation first, read under the custody read guard: what an
    /// install's empty slot may take back. A generation that does not read
    /// is left out, warned by the error's kind; no custody bound here, or
    /// none beside the vault, holds none.
    ///
    /// # Errors
    ///
    /// Custody faults before any generation is read.
    pub(crate) fn host_issuer_seed_candidates(
        &self,
    ) -> Result<Vec<Zeroizing<[u8; HOST_ISSUER_SEED_BYTES]>>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        if !custody_present(custody.binding().root())? {
            return Ok(Vec::new());
        }
        let _guard = self.core.key_custody.read_guard()?;
        let subject = issuer_seed_subject(custody.binding())?;
        let Some(newest) = custody.newest_generation(&subject)? else {
            return Ok(Vec::new());
        };
        let mut seeds = Vec::new();
        for generation in (0..=newest).rev() {
            let id = subject.at(generation);
            let read = match custody.state(&id) {
                Ok(EntryState::Live) => custody
                    .read(&id)
                    .and_then(|secret| copy_seed(secret.expose())),
                Ok(EntryState::Retired | EntryState::Missing) => continue,
                Err(error) => Err(error),
            };
            match read {
                Ok(seed) => seeds.push(seed),
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a host issuer seed the vault's custody holds did not read; it is no candidate"
                ),
            }
        }
        Ok(seeds)
    }
}
