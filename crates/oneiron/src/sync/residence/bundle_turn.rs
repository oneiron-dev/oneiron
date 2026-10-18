//! The publisher turn of the vault's sealed cloud bundle on the home (FIX
//! 3351). First commit no longer wins: a machine of the owner's asks the home
//! for the turn before it assembles a generation, and the home keeps one queue
//! of the machines that asked, across slots ([`SEALED_BUNDLE_PUBLISH_ORDER`]).
//! The first machine in it holds the turn; only the holder stages a bundle or
//! commits, and its parts renew the turn. A machine that published leaves the
//! queue and asks again behind every machine still waiting, so a slower
//! publisher, maybe the only reader of a world, gets its slot. A turn not used
//! lapses ([`SEALED_BUNDLE_PUBLISH_LEASE_SECS`]), and the next machine waiting
//! holds it; the machine whose turn lapsed holds the next slot first
//! ([`SEALED_BUNDLE_PUBLISH_FALLBACK_SECS`]).

use super::bundle::{entries_in, owner_machine};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{SEALED_BUNDLE_UPLOAD_INTERVAL_SECS, sealed_bundle_slot};

/// How the home orders the machines waiting for the turn (CALLS:
/// SEALED_BUNDLE_PUBLISH_ORDER).
enum PublishOrder {
    /// First asked, first served: a machine that published asks again behind
    /// every machine already waiting.
    Fifo,
}

const SEALED_BUNDLE_PUBLISH_ORDER: PublishOrder = PublishOrder::Fifo;

/// How long the holder may go without asking again or staging a part, in a
/// slot that has no generation yet, before its turn lapses (CALLS:
/// SEALED_BUNDLE_PUBLISH_LEASE_SECS). It counts from the slot's start at the
/// earliest, so a machine that came to hold the turn as the last slot was won
/// has the first hour of the next one. A lapsed holder leaves the queue, and
/// holds the next slot first.
pub(crate) const SEALED_BUNDLE_PUBLISH_LEASE_SECS: u64 = 60 * 60;

/// How far into the next slot the lease of a machine whose turn lapsed starts
/// at the latest (FIX 4272; CALLS: SEALED_BUNDLE_PUBLISH_FALLBACK_SECS). That
/// machine holds the slot first, its lease from its first ask there rather
/// than from the slot's start, so a publisher offline for the first hour of
/// every slot still gets its turn. Once a lease started here runs out, the
/// next machine waiting holds the turn, so the slot still has its upload. One
/// machine is carried at a time, and only once: a machine whose turn lapses
/// in the slot it held first leaves the queue.
const SEALED_BUNDLE_PUBLISH_FALLBACK_SECS: u64 = 6 * 60 * 60;

/// The queue: the vault second the holder's turn runs from, the slot the
/// machine whose turn lapsed holds first (0 for none) and that machine, then
/// each machine that asked, the holder first.
const TURN: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_TURN);

struct Turns {
    /// When the holder's turn began, or it last renewed it.
    since: u64,
    /// The machine whose turn lapsed in a slot with no generation, and the
    /// next slot, which it holds first.
    carried: Option<(EntityId, u64)>,
    queue: Vec<EntityId>,
}

impl Turns {
    fn holder(&self) -> Option<EntityId> {
        self.queue.first().copied()
    }

    /// Takes `machine` out of the queue at `now`.
    fn leave(&mut self, machine: EntityId, now: u64) {
        let holder = self.holder();
        self.queue.retain(|waiting| *waiting != machine);
        if self.carried.is_some_and(|(carried, _)| carried == machine) {
            self.carried = None;
        }
        if self.holder() != holder {
            self.since = now;
        }
    }
}

fn load_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Turns> {
    let Some(raw) = TURN.get(&vault.store, txn, &())? else {
        return Ok(Turns {
            since: 0,
            carried: None,
            queue: Vec::new(),
        });
    };
    let (head, machines) = raw.split_at_checked(32).ok_or(Error::InvalidKey)?;
    if machines.len() % 16 != 0 {
        return Err(Error::InvalidKey);
    }
    let machine = |bytes: &[u8]| {
        bytes
            .try_into()
            .ok()
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            .ok_or(Error::InvalidKey)
    };
    let second = |bytes: &[u8]| {
        bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::InvalidKey)
    };
    let queue = machines
        .chunks(16)
        .map(machine)
        .collect::<Result<Vec<_>>>()?;
    let carried = match second(&head[8..16])? {
        0 => None,
        slot => Some((machine(&head[16..])?, slot)),
    };
    Ok(Turns {
        since: second(&head[..8])?,
        carried,
        queue,
    })
}

fn store_in(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, turns: &Turns) -> Result<()> {
    let (carried, slot) = turns
        .carried
        .map_or(([0; 16], 0), |(machine, slot)| (*machine.as_bytes(), slot));
    let mut raw = turns.since.to_be_bytes().to_vec();
    raw.extend_from_slice(&slot.to_be_bytes());
    raw.extend_from_slice(&carried);
    for machine in &turns.queue {
        raw.extend_from_slice(machine.as_bytes());
    }
    TURN.put(&vault.store, wtxn, &(), &raw)
}

/// The queue as it stands at `now`: without the machines no longer trusted as
/// the owner's here, with the machine whose turn lapsed last slot first, and
/// without a holder whose turn lapsed in a slot that has no generation yet. A
/// machine that comes to hold the turn holds it from `now`; the one carried
/// to the front from its first ask, and from
/// [`SEALED_BUNDLE_PUBLISH_FALLBACK_SECS`] into the slot at the latest.
fn settle_in(vault: &Vault, wtxn: &heed::RwTxn<'_>, now: u64) -> Result<Turns> {
    let mut turns = load_in(vault, wtxn)?;
    let fold = vault.authority_fold_readonly_in_txn(wtxn)?;
    let now_slot = sealed_bundle_slot(now);
    let start = now_slot.saturating_mul(SEALED_BUNDLE_UPLOAD_INTERVAL_SECS);
    turns.carried = turns
        .carried
        .filter(|(machine, slot)| *slot >= now_slot && fold.trusted_machine(*machine).is_some());
    // The carried machine goes first at the slot's first settle, before any
    // turn ran from inside it.
    if let Some((machine, slot)) = turns.carried
        && slot == now_slot
        && turns.since < start
    {
        turns.queue.retain(|waiting| *waiting != machine);
        turns.queue.insert(0, machine);
        turns.since = start.saturating_add(SEALED_BUNDLE_PUBLISH_FALLBACK_SECS);
    }
    let holder = turns.holder();
    turns
        .queue
        .retain(|machine| fold.trusted_machine(*machine).is_some());
    let open = entries_in(vault, wtxn)?
        .last()
        .is_none_or(|latest| latest.generation.slot < now_slot);
    let from = turns.since.max(start);
    if open
        && turns.holder().is_some()
        && turns.holder() == holder
        && from.saturating_add(SEALED_BUNDLE_PUBLISH_LEASE_SECS) < now
    {
        let lapsed = turns.queue.remove(0);
        turns.carried = match turns.carried {
            Some(carried) if carried == (lapsed, now_slot) => None,
            None => Some((lapsed, now_slot.saturating_add(1))),
            kept => kept,
        };
    }
    if turns.holder() != holder {
        turns.since = now;
    }
    Ok(turns)
}

/// Asks for the publisher turn for the machine `peer` proved, or, with
/// `leave`, gives its place up. A machine not in the queue joins it at its
/// back, even in a slot already won, so it waits its turn for the next one;
/// the holder's asking renews its turn. Returns whether that machine holds the
/// turn now.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn ask_sealed_bundle_turn(vault: &Vault, peer: PeerMachine, leave: bool) -> Result<bool> {
    let machine = owner_machine(vault, peer, true)?;
    vault.with_write_txn_grouped(|wtxn| {
        let now = vault.instant_in_txn(wtxn)?.secs();
        let mut turns = settle_in(vault, wtxn, now)?;
        if leave {
            turns.leave(machine, now);
        } else if turns.holder() == Some(machine) {
            turns.since = now;
        } else if !turns.queue.contains(&machine) {
            match SEALED_BUNDLE_PUBLISH_ORDER {
                PublishOrder::Fifo => turns.queue.push(machine),
            }
            if turns.queue.len() == 1 {
                turns.since = now;
            }
        }
        store_in(vault, wtxn, &turns)?;
        Ok(turns.holder() == Some(machine))
    })
}

/// Whether `machine` holds the turn at `now`, in its stage or commit; holding
/// it renews it.
pub(super) fn hold_turn_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    machine: EntityId,
    now: u64,
) -> Result<bool> {
    let mut turns = settle_in(vault, wtxn, now)?;
    let holds = turns.holder() == Some(machine);
    if holds {
        turns.since = now;
    }
    store_in(vault, wtxn, &turns)?;
    Ok(holds)
}

/// After `machine`'s commit at `now`: it leaves the queue, and asks again
/// behind every machine waiting.
pub(super) fn published_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    machine: EntityId,
    now: u64,
) -> Result<()> {
    let mut turns = load_in(vault, wtxn)?;
    match SEALED_BUNDLE_PUBLISH_ORDER {
        PublishOrder::Fifo => turns.leave(machine, now),
    }
    store_in(vault, wtxn, &turns)
}
