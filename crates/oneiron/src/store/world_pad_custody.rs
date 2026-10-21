//! The world key pad's custody client (KS-5, FIX 346; KEY STORE = A): the
//! exterior custody a world key's erasable half moves into.
//!
//! A pad is one subject per key: kind `WorldPad`, item the key's full id
//! (`WorldKeyId::envelope_key_id`: world (16) | generation (8, big-endian) |
//! mint (16); CALLS `FIX 5686 pad custody item codec`), generation 0, the
//! pad's 32 bytes its secret. Every put of a pad row publishes its pad here
//! (KS-5, `world_keys::pad_custody`), the binding pinned in the same
//! transaction, synced and its Mint journaled before the row commits; the
//! row then rests as a reference to its entry with its own pad beside it,
//! which every read takes first. The pad sits in the custody head's
//! host-readable compartment (CALLS WORLD_PAD_HEAD_SCOPE).
//!
//! A world erase stages one erase intent for every pad of the world custody
//! holds here, a row or none, in the purge's own transaction, and the
//! finisher retires them after the commit once the world's destroyed fact
//! stands. A hard erase of one pad row alone stages that key's (FIX 7192).
//! A world delete retires nothing. A restore plans each pad its image names
//! through the restore's one plan ([`plan_world_pad`], FIX 5686 part 2).

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySecret, CustodySubject, EntryState,
    Requirement, RetireCause, RetirementIntent, custody_present, stage_retirement_in_txn,
};

/// A pad's custody item: its key's full id, world (16) | generation (8,
/// big-endian) | mint (16).
pub(crate) type WorldPadItem = [u8; 40];

/// What current custody holds for one pad item, as the pad client's put door
/// reads it (KS-5, FIX 5686).
pub(crate) enum WorldPadCustody {
    /// No pad may be published here: an archived vault, whose custody is its
    /// replacement's.
    Closed,
    /// No entry yet: a publication takes it.
    Missing,
    /// The live entry's pad.
    Live(Zeroizing<[u8; 32]>),
    /// A retirement reached it: it is never published again.
    Retired,
}

/// What a restore's plan finds for a pad its image names (KS-5, FIX 5686
/// part 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlannedPad {
    /// The custody the restore takes holds it: a fork copies it.
    Live,
    /// Destroyed there, or committed to be: the erase stands.
    Retired,
    /// No custody the restore takes holds it.
    Missing,
}

/// Plans `item`'s pad through `plan`, the restore's one plan with its claim
/// keys, bodies and history, so one fork copies them all. A missing pad is
/// never refused here: what its row needs decides.
///
/// # Errors
///
/// Custody faults.
pub(crate) fn plan_world_pad(plan: &mut CustodyPlan, item: &WorldPadItem) -> Result<PlannedPad> {
    let id = match plan.source() {
        Some(source) => pad_subject(source, item)?.at(0),
        None => return Ok(PlannedPad::Missing),
    };
    Ok(match plan.require_present(&id)? {
        Some(Requirement::Live) => PlannedPad::Live,
        Some(Requirement::Retired) => PlannedPad::Retired,
        None => PlannedPad::Missing,
    })
}

fn pad_subject(binding: &CustodyBinding, item: &WorldPadItem) -> Result<CustodySubject> {
    binding.subject(CustodyKind::WorldPad, item)
}

/// A pad's bytes, copied out of a custody secret: exactly 32.
fn copy_pad(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut pad = Zeroizing::new([0; 32]);
    if secret.len() != pad.len() {
        return Err(CustodyKind::WorldPad.corrupt());
    }
    pad.copy_from_slice(secret);
    Ok(pad)
}

/// The world a pad item files under.
fn item_world(item: &[u8]) -> Result<EntityId> {
    item.get(..16)
        .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
        .and_then(|raw| EntityId::from_bytes(raw).ok())
        .ok_or_else(|| CustodyKind::WorldPad.corrupt())
}

impl Store {
    /// Publishes `pad` as the custody entry `item`, in `wtxn`'s writer, the
    /// binding pinned in the same transaction: synced, and its Mint
    /// journaled, before the row it mirrors commits. An entry already live
    /// there must hold the same bytes; a retired one is never published
    /// again. An archived vault publishes none: its custody is its
    /// replacement's.
    ///
    /// # Errors
    ///
    /// A retired or different entry, and custody faults.
    pub(crate) fn publish_world_pad_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        item: &WorldPadItem,
        pad: &[u8; 32],
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = pad_subject(custody.binding(), item)?.at(0);
        let secret = CustodySecret::from_bytes(Zeroizing::new(pad.to_vec()));
        match custody.state(&id)? {
            EntryState::Missing => custody.publish_minted(&id, &secret),
            EntryState::Live => custody.publish(&id, &secret),
            EntryState::Retired => Err(CustodyKind::WorldPad.corrupt()),
        }
    }

    /// The pad `item` names, from current custody: `None` when no custody
    /// is bound here, or its entry is retired or missing. A damaged entry is
    /// an error. It takes no custody guard, so a writer may ask; a
    /// retirement that races the read reads as retired.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn world_pad_in_custody(
        &self,
        item: &WorldPadItem,
    ) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        if !custody_present(custody.binding().root())? {
            return Ok(None);
        }
        let id = pad_subject(custody.binding(), item)?.at(0);
        if custody.state(&id)? != EntryState::Live {
            return Ok(None);
        }
        match custody.read(&id) {
            Ok(secret) => copy_pad(secret.expose()).map(Some),
            Err(_) if custody.state(&id)? != EntryState::Live => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// [`WorldPadCustody`] for `item`. It takes no custody guard, as
    /// [`Self::world_pad_in_custody`] does not.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn world_pad_custody_entry(&self, item: &WorldPadItem) -> Result<WorldPadCustody> {
        if self.core.gate_custody_archived() {
            return Ok(WorldPadCustody::Closed);
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(WorldPadCustody::Missing);
        };
        if !custody_present(custody.binding().root())? {
            return Ok(WorldPadCustody::Missing);
        }
        let id = pad_subject(custody.binding(), item)?.at(0);
        Ok(match custody.state(&id)? {
            EntryState::Missing => WorldPadCustody::Missing,
            EntryState::Retired => WorldPadCustody::Retired,
            EntryState::Live => match custody.read(&id) {
                Ok(secret) => WorldPadCustody::Live(copy_pad(secret.expose())?),
                Err(_) if custody.state(&id)? == EntryState::Retired => WorldPadCustody::Retired,
                Err(error) => return Err(error),
            },
        })
    }

    /// The namespace this store's pads are published under, once a binding
    /// is held and the vault is not archived: what a pad row's reference
    /// names.
    pub(crate) fn world_pad_namespace(&self) -> Option<[u8; 16]> {
        if self.core.gate_custody_archived() {
            return None;
        }
        self.core
            .key_custody
            .local()
            .map(|custody| *custody.binding().namespace().as_bytes())
    }

    /// Every pad custody holds here under `prefix` (a world's id, or one
    /// key's full item) with its state, one no row names included. None when
    /// no custody is bound.
    fn world_pad_subjects(&self, prefix: &[u8]) -> Result<Vec<(CustodySubject, EntryState)>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        if !custody_present(custody.binding().root())? {
            return Ok(Vec::new());
        }
        custody
            .subjects_with_prefix(CustodyKind::WorldPad, prefix)?
            .into_iter()
            .map(|subject| {
                let state = custody.state(&subject.at(0))?;
                Ok((subject, state))
            })
            .collect()
    }

    /// Whether custody here still holds a pad of `world` no retirement
    /// reached: part of the world's delete scope, with or without a row
    /// (FIX 349).
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn world_pad_custody_held(&self, world: &EntityId) -> Result<bool> {
        Ok(self
            .world_pad_subjects(world.as_bytes())?
            .iter()
            .any(|(_, state)| *state != EntryState::Retired))
    }

    /// Stages an erase's retirement of every pad of `world` custody holds
    /// here that no marker retires yet, in `wtxn`, the purge's own
    /// transaction: a row or none, a pad an aborted writer published
    /// included. [`Self::finish_world_pad_retirements`] carries them out
    /// after the commit. An archived vault stages none: its custody is its
    /// replacement's.
    ///
    /// # Errors
    ///
    /// Custody and storage faults.
    pub(crate) fn stage_world_pad_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        world: &EntityId,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        for (subject, state) in self.world_pad_subjects(world.as_bytes())? {
            if state == EntryState::Retired {
                continue;
            }
            let intent = RetirementIntent {
                subject,
                through: 0,
                cause: RetireCause::Erase,
            };
            stage_retirement_in_txn(self, wtxn, &intent)?;
        }
        Ok(())
    }

    /// [`Self::stage_world_pad_erase_in_txn`] for one key's pad alone,
    /// `item`: a peer's hard tombstone of that key's pad row (KS-5). The
    /// world's other pads stay.
    ///
    /// # Errors
    ///
    /// Custody and storage faults.
    pub(crate) fn stage_world_pad_key_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        item: &WorldPadItem,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        for (subject, state) in self.world_pad_subjects(item)? {
            if state != EntryState::Retired {
                let intent = RetirementIntent {
                    subject,
                    through: 0,
                    cause: RetireCause::Erase,
                };
                stage_retirement_in_txn(self, wtxn, &intent)?;
            }
        }
        Ok(())
    }

    /// [`Self::stage_world_pad_key_erase_in_txn`] for the pad row `row`
    /// whose body names no key: a soft-erased pad's header-only shell, hard
    /// erased (FIX 7192). The one pad custody holds whose key derives that
    /// row id is staged, never another of its world's.
    ///
    /// # Errors
    ///
    /// Custody and storage faults.
    pub(crate) fn stage_world_pad_row_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        row: &EntityId,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        for (subject, state) in self.world_pad_subjects(&[])? {
            if state == EntryState::Retired
                || crate::world_keys::pad_row_of_item(subject.item())? != Some(*row)
            {
                continue;
            }
            let intent = RetirementIntent {
                subject,
                through: 0,
                cause: RetireCause::Erase,
            };
            stage_retirement_in_txn(self, wtxn, &intent)?;
        }
        Ok(())
    }

    /// Carries out every staged world pad retirement, an interrupted
    /// process's included, in the custody finisher's order (marker, unlink,
    /// directory sync), then hands each to the custody journal. Only an
    /// erase's intent runs, for a world whose keys were destroyed here or a
    /// pad row hard-erased here; anything else is refused by name.
    ///
    /// # Errors
    ///
    /// An archived vault with a retirement standing, the rule's refusals,
    /// and custody faults.
    pub(crate) fn finish_world_pad_retirements(&self) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::WorldPad, |txn, intent| {
            world_pad_retirement_ready(self, txn, intent)
        })
    }
}

/// The pad client's rule for the custody finisher: see
/// [`Store::finish_world_pad_retirements`].
fn world_pad_retirement_ready(
    store: &Store,
    txn: &RoTxn<'_>,
    intent: &RetirementIntent,
) -> Result<bool> {
    if intent.cause != RetireCause::Erase {
        return Err(Error::CorruptedIndex(
            "world key pads retire for an erase only",
        ));
    }
    let world = item_world(intent.subject.item())?;
    // A world's erase, or a hard erase of the one pad row (KS-5).
    if !crate::world_keys::world_keys_destroyed_in_txn(store, txn, world)?
        && !crate::world_keys::pad_row_erased_in_txn(store, txn, intent.subject.item())?
    {
        return Err(Error::CorruptedIndex(
            "retiring world key pads have no erase",
        ));
    }
    Ok(true)
}
