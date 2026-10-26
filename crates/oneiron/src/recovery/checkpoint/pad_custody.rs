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
//! stays Pending as it is there. One a custody head this restore opened did
//! not give it (its world's compartment opens only with the kit or a machine
//! that world admits, FIX 9178) leaves its world Locked: its rows wait as
//! references, named, never readable and never dropped, for the kit or an
//! admitted machine (Engine 10-22 15:1x). Any other missing or unreadable
//! pad refuses the restore before it is kept, `custody_key_missing`: pending
//! until it runs where the vault's custody is, beside its custody head, or
//! once a machine of the vault's holds the pad; never a falsely complete
//! restore, and never a pad from the historical image. A row that brings its
//! own pad (a carrier an image kept where custody could not take it, or a
//! live row a restore over a vault carried) lands as before unless its
//! custody retired it. Beside a source, one the forked custody lacks or cannot read
//! lands with the pad the source's live row keeps (`side_pads`).

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use heed::types::Bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    CheckpointImage, Custody, Rejected, RestoreAdmissionReason as R, RestorePadState, codec_error,
};
use crate::entity_id::EntityId;
use crate::store::{CustodyPlan, PlannedPad, plan_world_pad};
use crate::world_keys::WorldKeyId;
use crate::{Error, Vault};

/// What a restore says of a world key pad its image names that it did not
/// land at rest (CALLS: KS-5 restore outcomes); its epoch keeps it
/// (`RestorePadState`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
    /// The custody head this restore opened did not give it the world's
    /// pads: their compartment opens only with the recovery kit or a machine
    /// the world admits (FIX 9178). The world's rows wait as references,
    /// locked, never readable and never dropped, until one opens them or a
    /// machine of the owner's hydrates them. One note per world.
    Locked { world: String },
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

    fn locked(world: EntityId) -> Self {
        Self::Locked {
            world: world.to_hex(),
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
            Self::Locked { world } => write!(
                f,
                "world {world}: pads locked, pending: opens with the kit or an admitted machine"
            ),
        }
    }
}

/// What a restore does with a pad its rows name by reference that no
/// custody it took holds (CALLS: KS-5 pad restore withheld; Engine 10-22
/// 15:1x for a landed head).
enum MissingPad {
    /// Pending as it is there, for a row a restore over a live vault carried
    /// from it; else Withheld, its row kept as a reference pending the pad
    /// from one of the owner's machines, when the world's sealed copies keep
    /// its pads off a custody head (`Vault::pad_worlds_kept_local`, hosted);
    /// else Locked, its row kept as a reference and its world named, when
    /// the restore landed a custody head it opened (with the data key alone,
    /// or a kit or machine that world does not admit); else refused,
    /// `custody_key_missing`, before the vault is kept: no head was opened.
    PendingIfCarriedElseWithheldByPolicyElseLockedIfLandedElseRefused,
}

const MISSING_PAD: MissingPad =
    MissingPad::PendingIfCarriedElseWithheldByPolicyElseLockedIfLandedElseRefused;

/// What one missing pad comes to ([`missing_pad_outcome`]).
enum PadOutcome {
    Pending,
    Withheld,
    Locked,
    Refused,
}

/// The one place a missing pad's outcome is decided ([`MISSING_PAD`]): from
/// where the restore takes its pads' custody, and whether the world's
/// sealed copies keep its pads off a custody head (`withheld`). The same on
/// every entry point: a managed restore, an owner's restore with the data
/// key alone, and one with a kit or machine a world does not admit.
fn missing_pad_outcome(source: PadSource, withheld: bool) -> PadOutcome {
    match MISSING_PAD {
        MissingPad::PendingIfCarriedElseWithheldByPolicyElseLockedIfLandedElseRefused => {
            match source {
                PadSource::Carried => PadOutcome::Pending,
                _ if withheld => PadOutcome::Withheld,
                PadSource::Landed => PadOutcome::Locked,
                PadSource::Kept | PadSource::Absent | PadSource::Forked => PadOutcome::Refused,
            }
        }
    }
}

/// Where a restore takes its pads' custody from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PadSource {
    /// The image's own custody, on this host: a pad the world's sealed
    /// copies keep off a head may be absent by choice.
    Kept,
    /// As `Kept`, landed from a custody head this restore opened: a world
    /// whose compartment it did not open is absent too (FIX 9178).
    Landed,
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
            Custody::Landed => Self::Landed,
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
            PadSource::Kept | PadSource::Landed | PadSource::Forked | PadSource::Carried => {
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
/// what the restore says of the pads it did not land, with each bare
/// reference it left owed (Pending, Withheld or Locked) by its key: what
/// the restore's epoch records (PAD-2). A pad neither held nor withheld
/// refuses the restore, `custody_key_missing`.
pub(super) fn land(
    vault: &Vault,
    landing: PadLanding,
) -> std::result::Result<RestorePadState, Rejected> {
    let PadLanding {
        source,
        referenced,
        mut notes,
    } = landing;
    let mut owed = Vec::new();
    if referenced.is_empty() {
        return Ok(RestorePadState {
            required_refs: owed,
            remaining: notes,
        });
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
        // The worlds whose sealed copies keep their pads off a custody head;
        // a carried row never asks.
        let withheld = match source {
            PadSource::Carried => BTreeSet::new(),
            _ => vault.pad_worlds_kept_local(true)?,
        };
        let mut locked = BTreeMap::new();
        for key in unheld {
            let outcome = missing_pad_outcome(source, withheld.contains(key.world.as_bytes()));
            if !matches!(outcome, PadOutcome::Refused) {
                owed.push(*key);
            }
            match outcome {
                PadOutcome::Pending => notes.push(PadRestoreNote::pending(key)),
                PadOutcome::Withheld => notes.push(PadRestoreNote::withheld(key)),
                PadOutcome::Locked => {
                    locked.insert(key.world, PadRestoreNote::locked(key.world));
                }
                PadOutcome::Refused => missing += 1,
            }
        }
        notes.extend(locked.into_values());
    }
    if missing > 0 {
        return Err(Rejected::new(
            R::CustodyKeyMissing,
            Error::InvalidConfig(format!(
                "{missing} world key pad(s) this image names are in no custody this restore can \
                 read: restore where the vault's custody is; beside its custody head, whose \
                 world pads open with the recovery kit (--unlock kit) or the key of a machine \
                 their world admits; or once a machine of the vault's holds them"
            )),
        ));
    }
    if !rested.is_empty() {
        let rows: Vec<(&[u8], &[u8])> = rested
            .iter()
            .map(|(row_key, row)| (row_key.as_slice(), row.as_slice()))
            .collect();
        vault.with_write_txn_grouped(|txn| put_rows_in_txn(vault, txn, &rows))?;
    }
    Ok(RestorePadState {
        required_refs: owed,
        remaining: notes,
    })
}

/// Puts each pad row of `rows` under its key in `txn`: the one write a
/// restore's landing and a pad reopen's rest share (PAD-2).
pub(super) fn put_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: &[(&[u8], &[u8])],
) -> crate::Result<()> {
    let entities = vault
        .store
        .env
        .open_database::<Bytes, Bytes>(txn, Some("entities"))?
        .ok_or_else(codec_error)?;
    for (row_key, row) in rows {
        entities.put(txn, row_key, row)?;
    }
    Ok(())
}
