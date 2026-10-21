//! A restore's world key pads (KS-5, FIX 5686 part 2; CALLS: KS-5 restore
//! outcomes). An image names each pad by its row's bare reference, never the
//! pad (`world_keys` `pad_image`), and the restore takes the pad from
//! current scoped custody through the one plan its claim keys, bodies and
//! known-value history go through, so one fork copies them all.
//!
//! Before the destination exists, a pad its custody retired after the image
//! was taken (an erase, here or at the source a side copy forks) takes its
//! row out, whatever form the row has: ErasedUnavailable. A live one is
//! planned, so a fork copies it. Once the rows landed and the vault reopened
//! under its own custody, each bare reference rests again with the pad that
//! custody holds beside it. One that custody lacks is Withheld when the
//! world's sealed copies keep its pads off a custody head: its row waits as
//! a reference, pending, for the pad from one of the owner's machines over
//! its live routes. One a restore over a live vault carried from that vault
//! stays Pending as it is there. Any other missing or unreadable pad refuses
//! the restore before it is kept, `custody_key_missing`: pending until it
//! runs where the vault's custody is, beside its custody head, or once a
//! machine of the vault's holds the pad; never a falsely complete restore,
//! and never a pad from the historical image. A row that brings its own pad
//! (a carrier an image kept where custody could not take it, or a live row
//! a restore over a vault carried) lands as before unless its custody
//! retired it. Beside a source, one the forked custody lacks or cannot read
//! lands with the pad the source's live row keeps (`side_pads`).

use std::collections::BTreeSet;

use heed::types::Bytes;
use zeroize::Zeroizing;

use super::{CheckpointImage, Custody, Rejected, RestoreAdmissionReason as R, codec_error};
use crate::store::{CustodyPlan, PlannedPad, plan_world_pad};
use crate::world_keys::WorldKeyId;
use crate::{Error, Vault};

/// What a restore says of a world key pad its image names that it did not
/// land at rest (CALLS: KS-5 restore outcomes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PadRestoreNote {
    /// The custody the restore took retired the pad after the image was
    /// taken: its row stayed out, as the erase left it.
    ErasedUnavailable { world: String, generation: u64 },
    /// The world's sealed copies keep its pads off a custody head, and the
    /// custody this restore took does not hold this one: its row waits as a
    /// reference for the pad from one of the owner's machines.
    Withheld { world: String, generation: u64 },
    /// The live vault the restore carried this row from holds it only as a
    /// reference, its pad not there yet: it stays so here, pending.
    Pending { world: String, generation: u64 },
}

impl PadRestoreNote {
    pub(super) fn erased(key: &WorldKeyId) -> Self {
        Self::ErasedUnavailable {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }

    fn withheld(key: &WorldKeyId) -> Self {
        Self::Withheld {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }

    fn pending(key: &WorldKeyId) -> Self {
        Self::Pending {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }
}

impl std::fmt::Display for PadRestoreNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErasedUnavailable { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad erased since the image, unavailable"
            ),
            Self::Withheld { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad withheld by the world's sealed \
                 copies setting, pending from the owner's machines"
            ),
            Self::Pending { world, generation } => write!(
                f,
                "world {world} key generation {generation}: pad pending, as in the vault restored \
                 over"
            ),
        }
    }
}

/// What a restore does with a pad its rows name by reference that no
/// custody it took holds (CALLS: KS-5 pad restore withheld).
enum MissingPad {
    /// Pending as it is there, for a row a restore over a live vault carried
    /// from it; else Withheld, its row kept as a reference pending the pad
    /// from one of the owner's machines, when the world's sealed copies keep
    /// its pads off a custody head (`Vault::pad_worlds_kept_local`, hosted);
    /// else refused, `custody_key_missing`, before the vault is kept.
    PendingIfCarriedElseWithheldByPolicyElseRefused,
}

const MISSING_PAD: MissingPad = MissingPad::PendingIfCarriedElseWithheldByPolicyElseRefused;

/// Where a restore takes its pads' custody from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PadSource {
    /// The image's own custody, on this host or landed from its head: a pad
    /// the world's sealed copies keep off a head may be absent by choice.
    Kept,
    /// None on this host and no head found: every pad is absent.
    Absent,
    /// A live source's, forked for a copy of the image's rows.
    Forked,
    /// A live vault's, with its rows, carried over it: a restore in its
    /// place or one keeping its authority.
    Carried,
}

impl PadSource {
    fn of(custody: Custody<'_>) -> Self {
        match custody {
            Custody::Keep => Self::Kept,
            Custody::NewHost => Self::Absent,
            Custody::Fork(Some(_)) => Self::Forked,
            Custody::Replace(..) | Custody::Fork(None) => Self::Carried,
        }
    }
}

/// The pads a restore owes once its rows landed.
pub(super) struct PadLanding {
    source: PadSource,
    /// Each bare reference row the image keeps, by row key, with its key
    /// and the carrier a side restore's source's live row gives it.
    referenced: Vec<(Vec<u8>, WorldKeyId, Option<Zeroizing<Vec<u8>>>)>,
    notes: Vec<PadRestoreNote>,
}

/// Before the destination exists: plans each pad row of `image` through
/// `plan`, the restore's one plan, under the custody `custody` names. A row
/// whose pad that custody retired goes; a bare reference waits for
/// [`land`]. A fault reading custody refuses for a bare reference with no
/// pad else, and leaves a row that brings its own, or that its side
/// restore's source keeps, as it is.
pub(super) fn require(
    image: &mut CheckpointImage,
    plan: &mut CustodyPlan,
    custody: Custody<'_>,
) -> std::result::Result<PadLanding, Rejected> {
    let source = PadSource::of(custody);
    let side = match custody {
        Custody::Fork(Some((_, side))) => Some(side),
        _ => None,
    };
    let rows = image
        .databases
        .get_mut("entities")
        .ok_or_else(codec_error)?;
    let mut landing = PadLanding {
        source,
        referenced: Vec::new(),
        notes: Vec::new(),
    };
    let mut gone = BTreeSet::new();
    for (row_key, raw) in rows.iter() {
        let Some(row) = crate::world_keys::image_pad_row_of(raw) else {
            continue;
        };
        let carrier = side.and_then(|side| side.carrier(row_key)).cloned();
        let planned = match source {
            PadSource::Absent => PlannedPad::Missing,
            PadSource::Kept | PadSource::Forked | PadSource::Carried => {
                match plan_world_pad(plan, &row.item) {
                    Ok(planned) => planned,
                    Err(_) if row.held || carrier.is_some() => PlannedPad::Missing,
                    Err(error) => return Err(Rejected::from(error)),
                }
            }
        };
        match planned {
            PlannedPad::Retired => {
                gone.insert(row_key.clone());
                landing.notes.push(PadRestoreNote::erased(&row.key));
            }
            PlannedPad::Live | PlannedPad::Missing if !row.held => {
                landing.referenced.push((row_key.clone(), row.key, carrier));
            }
            PlannedPad::Live | PlannedPad::Missing => {}
        }
    }
    rows.retain(|(row_key, _)| !gone.contains(row_key));
    Ok(landing)
}

/// Once the rows landed and `vault` reopened under its own custody: each
/// bare reference rests again with the pad that custody holds beside it, or
/// else lands as the carrier its side restore's source gave it. Returns
/// what the restore says of the pads it did not land; a pad neither held
/// nor withheld refuses the restore, `custody_key_missing`.
pub(super) fn land(
    vault: &Vault,
    landing: PadLanding,
) -> std::result::Result<Vec<PadRestoreNote>, Rejected> {
    let PadLanding {
        source,
        referenced,
        mut notes,
    } = landing;
    if referenced.is_empty() {
        return Ok(notes);
    }
    let mut rested = Vec::new();
    let mut unheld = Vec::new();
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let entities = vault
            .store
            .env
            .open_database::<Bytes, Bytes>(&txn, Some("entities"))
            .map_err(Error::from)?
            .ok_or_else(codec_error)?;
        for (row_key, key, carrier) in &referenced {
            let Some(raw) = entities.get(&txn, row_key).map_err(Error::from)? else {
                continue;
            };
            match (
                crate::world_keys::rested_pad_row(&vault.store, raw),
                carrier,
            ) {
                (Ok(Some(row)), _) => rested.push((row_key, row)),
                (Ok(None) | Err(_), Some(carrier)) => rested.push((row_key, carrier.clone())),
                (Ok(None), None) => unheld.push(key),
                (Err(error), None) => return Err(error.into()),
            }
        }
    }
    let mut missing = 0_usize;
    if !unheld.is_empty() {
        match MISSING_PAD {
            MissingPad::PendingIfCarriedElseWithheldByPolicyElseRefused
                if source == PadSource::Carried =>
            {
                notes.extend(unheld.into_iter().map(PadRestoreNote::pending));
            }
            MissingPad::PendingIfCarriedElseWithheldByPolicyElseRefused => {
                // The worlds whose sealed copies keep their pads off a
                // custody head.
                let withheld = vault.pad_worlds_kept_local(true)?;
                for key in unheld {
                    if withheld.contains(key.world.as_bytes()) {
                        notes.push(PadRestoreNote::withheld(key));
                    } else {
                        missing += 1;
                    }
                }
            }
        }
    }
    if missing > 0 {
        return Err(Rejected::new(
            R::CustodyKeyMissing,
            Error::InvalidConfig(format!(
                "{missing} world key pad(s) this image names are in no custody this restore can \
                 read: restore where the vault's custody is, beside its custody head, or once a \
                 machine of the vault's holds them"
            )),
        ));
    }
    if !rested.is_empty() {
        vault.with_write_txn_grouped(|txn| {
            let entities = vault
                .store
                .env
                .open_database::<Bytes, Bytes>(txn, Some("entities"))?
                .ok_or_else(codec_error)?;
            for (row_key, row) in &rested {
                entities.put(txn, row_key, row)?;
            }
            Ok(())
        })?;
    }
    Ok(notes)
}
