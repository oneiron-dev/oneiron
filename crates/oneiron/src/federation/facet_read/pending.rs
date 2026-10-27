//! Held facet stamps as retained work (FIX 8890, 8566, 8731).
//!
//! Every stamp a sender sends ahead of its row is kept, with the grant it
//! came under and when it arrived. The per-row and per-sender counts refuse
//! nothing: passing one is a typed observation. A stamp leaves when its row's
//! birth releases it, when a writer places the pair itself, or when it
//! retires. A peer's stamp retires past its wait (the owner's wait for held
//! stamps, 30 days unless he sets another) or once the grant it came under no
//! longer confers; a staged one once its receipt leaves Pending. Retirement
//! takes the senders in turn, and each retired stamp keeps a typed,
//! content-free receipt.

#[cfg(feature = "sync")]
use std::collections::BTreeSet;

#[cfg(feature = "sync")]
use super::{
    HeldLane, MAX_HELD_BYTES_PER_SENDER, MAX_HELD_PER_ROW, MAX_HELD_PER_SENDER, held_value,
    lane_usage, put_lane_usage, read_held, row_bytes,
};
use super::{PARKED_STAMP, remove_held, stamp_prefix};
use crate::EntityId;
#[cfg(feature = "sync")]
use crate::Vault;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::side_table::{self, Raw, SideTable};
use crate::side_table::{HexId, SideTableDbs};
#[cfg(feature = "sync")]
use crate::sync::federation_burst::schedule::{self, RetainedWorkQueue, Waiting};

/// The receipt a retired stamp keeps under its held key: why it retired (a
/// byte, [`Ended`]), when it was held and when it retired (u64 big-endian
/// each), then the grant it was held under (a flag byte, then its 16 raw
/// bytes when set). No edge value.
#[cfg(feature = "sync")]
const RECEIPT: SideTable<(HexId, HexId, String), Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_PARKED_FACET_RECEIPT);

/// What holding one stamp came to. The stamp is held in every case; the
/// counts it passed are typed observations, never a refusal (FIX 8731).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hold {
    Held,
    /// The sender held [`MAX_HELD_PER_ROW`] stamps on the row already.
    PastRowCount,
    /// The sender held [`MAX_HELD_PER_SENDER`] stamps, or
    /// [`MAX_HELD_BYTES_PER_SENDER`] bytes of them, already.
    PastSenderCount,
}

/// Why a held stamp retired.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Its wait ended before its row came.
    Expired = 1,
    /// The grant it came under no longer confers, or its staged receipt left
    /// Pending.
    AuthorityEnded = 2,
}

/// Holds the stamp `src -FacetOf-> facet`, with its edge `value`, under the
/// sender's `lane` and the `grant` it sent it under, as of `now`. Only a
/// `capped` sender, a federation peer, is observed against the counts: the
/// owner's own staged import never is.
#[cfg(feature = "sync")]
pub(crate) fn park_stamp(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    (src, facet): (EntityId, EntityId),
    (lane, grant): (&str, Option<EntityId>),
    value: &[u8],
    (now, capped): (u64, bool),
) -> Result<Hold> {
    let key = (HexId(src), HexId(facet), lane.to_owned());
    let prior = PARKED_STAMP.get(dbs, wtxn, &key)?;
    let mut hold = Hold::Held;
    if capped
        && prior.is_none()
        && PARKED_STAMP
            .scan_keys(dbs, wtxn, src.to_hex().as_bytes())?
            .into_iter()
            .filter(|held| held.2 == lane)
            .count()
            >= MAX_HELD_PER_ROW
    {
        hold = Hold::PastRowCount;
    }
    let row = held_value(now, grant, value);
    let (rows, bytes) = lane_usage(dbs, wtxn, lane)?;
    let freed = prior.as_deref().map_or(0, |prior| row_bytes(lane, prior));
    let rows = rows.saturating_add(u64::from(prior.is_none()));
    let bytes = bytes
        .saturating_sub(freed)
        .saturating_add(row_bytes(lane, &row));
    if capped && (rows > MAX_HELD_PER_SENDER || bytes > MAX_HELD_BYTES_PER_SENDER) {
        hold = Hold::PastSenderCount;
    }
    PARKED_STAMP.put(dbs, wtxn, &key, &row)?;
    put_lane_usage(dbs, wtxn, lane, (rows, bytes))?;
    // A stamp held again waits afresh; an earlier retirement no longer
    // speaks for it.
    RECEIPT.delete(dbs, wtxn, &key)?;
    Ok(hold)
}

/// Discards every held copy of the stamp `src -FacetOf-> facet`.
pub(crate) fn unpark_stamp(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    src: EntityId,
    facet: EntityId,
) -> Result<()> {
    for key in PARKED_STAMP.scan_keys(dbs, wtxn, stamp_prefix(src, facet).as_bytes())? {
        remove_held(dbs, wtxn, &key)?;
    }
    Ok(())
}

/// Discards the copy of the stamp `src -FacetOf-> facet` held under `lane`,
/// once it is released.
#[cfg(feature = "sync")]
pub(crate) fn unpark_released(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    (src, facet): (EntityId, EntityId),
    lane: &str,
) -> Result<()> {
    remove_held(dbs, wtxn, &(HexId(src), HexId(facet), lane.to_owned()))?;
    Ok(())
}

/// Retires each held stamp that [`retiring`] names by `now`, keeping its
/// receipt; returns how many went. Each is judged again, with its grant, in
/// the transaction that removes it, so a hold renewed since the scan under a
/// grant that confers again stays (Sol R10 F3 on #1432).
#[cfg(feature = "sync")]
pub(crate) fn retire_held_stamps(
    vault: &Vault,
    now: u64,
    conferring: impl Fn(&heed::RoTxn<'_>, &BTreeSet<EntityId>) -> Result<BTreeSet<EntityId>>,
) -> Result<u64> {
    let candidates = {
        let txn = vault.store.env.read_txn()?;
        retiring(
            &vault.store,
            &txn,
            now,
            PARKED_STAMP.scan(&vault.store, &txn)?,
            &conferring,
        )?
    };
    if candidates.is_empty() {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|wtxn| {
        let mut rows = Vec::new();
        for (key, _) in candidates {
            if let Some(value) = PARKED_STAMP.get(&vault.store, wtxn, &key)? {
                rows.push((key, value));
            }
        }
        let mut count = 0;
        for (key, ended) in retiring(&vault.store, wtxn, now, rows, &conferring)? {
            let held = PARKED_STAMP.get(&vault.store, wtxn, &key)?;
            if !remove_held(&vault.store, wtxn, &key)? {
                continue;
            }
            count += 1;
            // A row that does not decode is no stamp: it leaves no receipt.
            if let (Some(ended), Some((held_at, grant, _))) =
                (ended, held.as_deref().and_then(read_held))
            {
                let receipt = receipt_value(ended, held_at, now, grant);
                RECEIPT.put(&vault.store, wtxn, &key, &receipt)?;
            }
        }
        Ok(count)
    })
}

/// A retired stamp's receipt value.
#[cfg(feature = "sync")]
fn receipt_value(ended: Ended, held_at: u64, now: u64, grant: Option<EntityId>) -> Vec<u8> {
    let mut value = vec![ended as u8];
    value.extend_from_slice(&held_at.to_be_bytes());
    value.extend_from_slice(&now.to_be_bytes());
    match grant {
        Some(grant) => {
            value.push(1);
            value.extend_from_slice(grant.as_bytes());
        }
        None => value.push(0),
    }
    value
}

/// The keys among `rows` that retire by `now`, judged in `txn`, each with
/// why, in the senders' turns. A peer's stamp retires once it has waited the
/// owner's wait for held stamps, or once its grant `conferring` no longer
/// returns; a staged stamp once its receipt keeps no record of it any more
/// (it left Pending), whatever its age. A row whose lane or value does not
/// decode goes, with no reason.
#[cfg(feature = "sync")]
fn retiring(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    now: u64,
    rows: Vec<((HexId, HexId, String), Vec<u8>)>,
    conferring: &impl Fn(&heed::RoTxn<'_>, &BTreeSet<EntityId>) -> Result<BTreeSet<EntityId>>,
) -> Result<Vec<((HexId, HexId, String), Option<Ended>)>> {
    let wait = schedule::wait_secs_in(dbs, txn, RetainedWorkQueue::FacetStamp)?;
    let grants = rows
        .iter()
        .filter_map(|(_, value)| read_held(value)?.1)
        .collect();
    let live = conferring(txn, &grants)?;
    let mut retire = Vec::new();
    let mut waiting = Vec::new();
    for (key, value) in rows {
        let Some((held_at, grant, _)) = read_held(&value) else {
            retire.push((key, None));
            continue;
        };
        let (deadline, ended) = match HeldLane::parse(&key.2) {
            None => {
                retire.push((key, None));
                continue;
            }
            Some(HeldLane::Peer(_)) => (
                held_at.saturating_add(wait),
                grant.is_some_and(|grant| !live.contains(&grant)),
            ),
            Some(HeldLane::Staged(receipt)) => (
                u64::MAX,
                !crate::batch::export::vault_import_keeps_stamps_in(dbs, txn, &receipt)?,
            ),
        };
        let mut arrival = [0; 16];
        arrival[..8].copy_from_slice(&held_at.to_be_bytes());
        waiting.push(Waiting {
            caller: key.2.as_bytes().to_vec(),
            arrival,
            deadline,
            ready: ended,
            item: key,
        });
    }
    let turns = schedule::turns(waiting, None, now);
    retire.extend(
        turns
            .expired
            .into_iter()
            .map(|key| (key, Some(Ended::Expired))),
    );
    retire.extend(
        turns
            .due
            .into_iter()
            .map(|(_, key)| (key, Some(Ended::AuthorityEnded))),
    );
    Ok(retire)
}
