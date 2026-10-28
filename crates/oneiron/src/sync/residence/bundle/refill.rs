//! A kept pad object's bytes filled again from a machine's upload (FIX 9362,
//! L03 half). A machine of the owner's whose read of a kept pad object came
//! back unavailable stages the same object it holds through the pad object
//! stage ([`super::stage_sealed_bundle_part`]); [`sealed_bundle_refill`] then
//! decodes it whole, refills the kept object under the index the machine
//! listed (`refill_pad_object`, its `Reupload` source), and reads that one
//! generation back. It writes no new generation, parent, grant, bundle part
//! or commit order, never brings back an object an erase rewrote since or a
//! generation the home retired, and waits on no erase. A current provider's
//! refill on a replacement or an activation is L02's (`CurrentProvider`).

use super::{
    Asked, BundlePartRead, CurrentPadObjects, PadObjectInstall, PadObjectRefillSource,
    PadObjectUnavailable, STAGES, SealedBundleEntry, SealedBundleObject, decode_stage, denied,
    drop_stage_in, entry_in, index_in, owner_machine, read_part_in, refill_pad_object, stage_key,
    staged_whole,
};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::world_keys::{SealedBundleGeneration, SealedKeyPads};

/// What a refill did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PadObjectRefill {
    /// The kept object is whole again, read back: its generation's entry.
    Refilled(SealedBundleEntry),
    /// The home's index moved since the machine listed it, or it keeps
    /// another object for the generation by now: nothing was written. List
    /// again.
    CurrentChanged,
    /// What the machine staged is not the whole object: nothing was written.
    Unavailable(PadObjectUnavailable),
}

impl PadObjectRefill {
    /// The outcome a reply names for [`Self::Refilled`].
    pub const REFILLED: &'static str = "REFILLED";
    /// The outcome a reply names for [`Self::CurrentChanged`].
    pub const CURRENT_CHANGED: &'static str = "CURRENT_CHANGED";

    /// The outcome a reply names for each.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Refilled(_) => Self::REFILLED,
            Self::CurrentChanged => Self::CURRENT_CHANGED,
            Self::Unavailable(_) => BundlePartRead::PAD_OBJECT_UNAVAILABLE,
        }
    }
}

/// The pad object of `entry` read whole from the stored parts `txn` holds:
/// its length and digest, a sealed pad object of its generation. `None` when
/// a part is missing or short, or the bytes are another object.
fn whole_pads_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entry: &SealedBundleEntry,
) -> Result<Option<SealedKeyPads>> {
    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        match read_part_in(vault, txn, entry, SealedBundleObject::Pads, offset)? {
            BundlePartRead::Part(part) => bytes.extend_from_slice(&part),
            BundlePartRead::End => break,
            BundlePartRead::PadObjectUnavailable(_) => return Ok(None),
        }
    }
    if bytes.len() as u64 != entry.pads_len || *blake3::hash(&bytes).as_bytes() != entry.pads_digest
    {
        return Ok(None);
    }
    Ok(SealedKeyPads::from_bytes(&bytes)
        .ok()
        .filter(|pads| pads.generation() == entry.generation))
}

/// The entry of `generation` when the home holds its pad object whole in
/// `txn`, a read after the refill committed, at the revision `after` names.
/// Only that generation is read: another kept object whose bytes are missing
/// stays as it is, and does not fail this refill. A restore's current
/// provider refill reads its generation back the same way (PAD-1).
pub(crate) fn read_back_generation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: &CurrentPadObjects,
    generation: SealedBundleGeneration,
) -> Result<Option<SealedBundleEntry>> {
    let held = index_in(vault, txn)?;
    if held.retained_revision != after.retained_revision {
        return Ok(None);
    }
    let Some(entry) = held
        .entries
        .iter()
        .map(|meta| meta.entry)
        .find(|entry| entry.generation == generation)
    else {
        return Ok(None);
    };
    Ok(whole_pads_in(vault, txn, &entry)?.map(|_| entry))
}

/// Fills `generation`'s kept pad object again from the pad object the
/// machine `peer` proved staged whole for it, with `digest`, while the home's
/// index is still the one the machine listed at `revision`. The machine is
/// one of the owner's whose proof stands here, as for erase's replace. The
/// staged object is decoded whole and must be the one the home keeps: its
/// generation, its length and its digest. Once written, that generation
/// alone is read back. The stage is spent whatever came of it.
///
/// # Errors
///
/// A refused peer; no whole stage of a pad object of that generation and
/// digest, or one that does not decode; storage errors.
pub fn sealed_bundle_refill(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
    digest: &[u8; 32],
    revision: &[u8; 32],
) -> Result<PadObjectRefill> {
    let machine = owner_machine(vault, peer, false, Asked::No)?;
    let staged = {
        let txn = vault.store.env.read_txn()?;
        staged_whole(vault, &txn, machine, SealedBundleObject::Pads)?
    };
    let Some((stage, bytes)) =
        staged.filter(|(stage, _)| stage.generation == generation && stage.digest == *digest)
    else {
        return Err(denied());
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| denied())?;
    drop(bytes);
    let expected = {
        let txn = vault.store.env.read_txn()?;
        index_in(vault, &txn)?
    };
    let install = if expected.retained_revision == *revision {
        refill_pad_object(
            vault,
            &expected,
            generation,
            PadObjectRefillSource::Reupload { peer, pads: &pads },
        )?
    } else {
        PadObjectInstall::CurrentChanged
    };
    let refill = match install {
        PadObjectInstall::Installed(after) => {
            let txn = vault.store.env.read_txn()?;
            read_back_generation_in(vault, &txn, &after, generation)?
                .map_or(PadObjectRefill::CurrentChanged, PadObjectRefill::Refilled)
        }
        PadObjectInstall::CurrentChanged => PadObjectRefill::CurrentChanged,
        PadObjectInstall::Unavailable(unavailable) => PadObjectRefill::Unavailable(unavailable),
    };
    let key = stage_key(machine, SealedBundleObject::Pads);
    vault.with_write_txn_grouped(|wtxn| {
        // A stage the machine started over since is its own.
        let same = STAGES
            .get_bytes(&vault.store, wtxn, &key)?
            .and_then(|raw| decode_stage(&raw, SealedBundleObject::Pads).ok())
            .is_some_and(|(_, held, _)| held == stage);
        if same {
            drop_stage_in(vault, wtxn, &key)?;
        }
        Ok(())
    })?;
    Ok(refill)
}

/// The pad object of `generation` this machine's own store keeps whole, with
/// `digest`: what it offers a home whose copy lacks the object's bytes. `None`
/// when it keeps no such object, or not whole.
///
/// # Errors
///
/// An entry that does not decode; storage errors.
pub(crate) fn held_pad_object(
    vault: &Vault,
    generation: SealedBundleGeneration,
    digest: &[u8; 32],
) -> Result<Option<SealedKeyPads>> {
    let txn = vault.store.env.read_txn()?;
    let Some(entry) =
        entry_in(vault, &txn, &generation)?.filter(|entry| entry.pads_digest == *digest)
    else {
        return Ok(None);
    };
    whole_pads_in(vault, &txn, &entry)
}
