//! The one facet rule (owner ruling FACET-READ = A). A facet is an opt-in
//! limit on what an agent's or a room's credential reads, never the owner's:
//! a credential narrowed to a set of facets reads a row only when the row sits
//! in one of them. MCP and every read lane judge a row here, so the two never
//! disagree.

#[cfg(feature = "sync")]
use std::collections::BTreeSet;

use super::record_scope::{MachineHistoryScope, scope_for_blob};
use super::{ScopeAxis, ScopeId};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
};
use crate::side_table::{self, HexId, Raw, SideTable, SideTableDbs};
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};

/// A federated `FacetOf` stamp sent ahead of its source row, held out of the
/// window document under the lane of the sender that brought it, with when it
/// was held, the grant it was held under and its edge value. It enters the
/// document only once that sender's birth of the row has applied here; a
/// writer that may place the row and writes the pair itself discards it.
const PARKED_STAMP: SideTable<(HexId, HexId, String), Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_PARKED_FACET_STAMP);

/// The rows and bytes each sender's lane holds in [`PARKED_STAMP`].
const PARKED_BY_LANE: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_PARKED_FACET_LANE);

/// The most stamps one federation peer holds on one row ahead of it. Every
/// birth of the row releases them all, so the bound is the work one small
/// update can make the release do (Astra R5 F2 on #1432); a row sits in a few
/// facets. An owner's staged artifact meets no count: once confirmed, its
/// stamps are the owner's own work (rule 5).
#[cfg(feature = "sync")]
pub(crate) const MAX_HELD_PER_ROW: usize = 16;

/// The most stamps one sender holds across every row, and the most bytes
/// their rows take, so a sender that never brings its rows grows this vault
/// no further (Astra-b F2 on #1432).
#[cfg(feature = "sync")]
pub(crate) const MAX_HELD_PER_SENDER: u64 = 4096;
#[cfg(feature = "sync")]
pub(crate) const MAX_HELD_BYTES_PER_SENDER: u64 = 1 << 20;

/// How long a peer's stamp stays held while its row does not come: 30 days.
#[cfg(feature = "sync")]
pub(crate) const HELD_STAMP_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Whose stamps a lane of [`PARKED_STAMP`] holds, which decides what retires
/// them (Astra-c F1 on #1432).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldLane {
    /// A federation peer's, untrusted until it brings their rows: they go
    /// after [`HELD_STAMP_TTL_SECS`] or with the grant they came under.
    Peer(EntityId),
    /// An owner's foreign artifact staged under this receipt: they stay while
    /// the receipt is Pending, whatever their age (rule 5), and go with it.
    Staged([u8; 32]),
}

#[cfg(feature = "sync")]
impl HeldLane {
    /// The lane's key in the held tables.
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Peer(peer) => format!("p{}", peer.to_hex()),
            Self::Staged(receipt) => {
                format!("s{}", crate::entity_id::bytes_to_hex_lower(receipt))
            }
        }
    }

    /// The lane a key names, or `None` for one no lane spells.
    fn parse(key: &str) -> Option<Self> {
        let lane = match key.split_at_checked(1)? {
            ("p", peer) => Self::Peer(EntityId::from_hex(peer).ok()?),
            ("s", receipt) if receipt.len() == 64 => {
                let mut id = [0_u8; 32];
                for (index, byte) in id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(receipt.get(index * 2..index * 2 + 2)?, 16).ok()?;
                }
                Self::Staged(id)
            }
            _ => return None,
        };
        (lane.key() == key).then_some(lane)
    }
}

/// Whether the stored row `id`, with header and body `raw` as `view` holds
/// it, sits in one of `facets`. A TASK sits in the facet its birth stamp
/// names; any row sits in each facet a `FacetOf` edge of its names, and, for a room and
/// each MESSAGE or TURN said there, in each facet of the room. A row with
/// several facets is readable when any one is in the set; a row that names
/// none sits in no facet. A whole axis reads every row and an empty one reads
/// none.
pub(crate) fn facets_admit_in(
    vault: &Vault,
    view: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    facets: &ScopeAxis<ScopeId>,
) -> Result<bool> {
    let set = match facets {
        ScopeAxis::All => return Ok(true),
        ScopeAxis::Some(set) if !set.is_empty() => set,
        _ => return Ok(false),
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
    if header.entity_type == ENTITY_TYPE_TASK
        && scope_for_blob(view, txn, id, raw)?
            .is_some_and(|scope| !scope.facets.meet(facets).is_bottom())
    {
        return Ok(true);
    }
    for edge in view.port_edges(txn, &id, EdgeDirection::Out, Some(EdgeKind::FacetOf), None)? {
        if set.contains(&ScopeId(edge?.target)) {
            return Ok(true);
        }
    }
    let room = match header.entity_type {
        ENTITY_TYPE_CONVERSATION => Some(id),
        ENTITY_TYPE_TURN => out_targets(view, txn, id, EdgeKind::ChildOf)?
            .first()
            .copied(),
        // A MESSAGE names its room directly and through its TURN. It sits in
        // a room only when the two agree, as the deletion resolver reads it:
        // a room edge added to a row someone else said only withholds it.
        ENTITY_TYPE_MESSAGE => {
            let mut rooms = out_targets(view, txn, id, EdgeKind::BelongsTo)?;
            for part in out_targets(view, txn, id, EdgeKind::PartOf)? {
                if crate::ports::EntityStoreRead::port_entity_with_raw(view, txn, &part, |raw| {
                    Ok(raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
                })?
                .unwrap_or(false)
                {
                    rooms.push(part);
                } else {
                    rooms.extend(out_targets(view, txn, part, EdgeKind::ChildOf)?);
                }
            }
            let first = rooms.first().copied();
            first.filter(|first| rooms.iter().all(|room| room == first))
        }
        _ => None,
    };
    let Some(room) = room else {
        return Ok(false);
    };
    Ok(crate::workspace_roster::room_facets_in(vault, txn, room)?
        .is_some_and(|room| !room.meet(facets).is_bottom()))
}

/// The targets of `id`'s outgoing `kind` edges.
fn out_targets(
    view: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    view.port_edges(txn, &id, EdgeDirection::Out, Some(kind), None)?
        .map(|edge| edge.map(|edge| edge.target))
        .collect()
}

/// The key every parked copy of the stamp `src -FacetOf-> facet` starts with.
fn stamp_prefix(src: EntityId, facet: EntityId) -> String {
    format!("{}{}", src.to_hex(), facet.to_hex())
}

/// A held row's value: when it was held, the grant it was held under (a flag
/// byte, then the id when there is one), then the edge value.
#[cfg(feature = "sync")]
fn held_value(held_at: u64, grant: Option<EntityId>, edge: &[u8]) -> Vec<u8> {
    let mut value = held_at.to_be_bytes().to_vec();
    match grant {
        Some(grant) => {
            value.push(1);
            value.extend_from_slice(grant.as_bytes());
        }
        None => value.push(0),
    }
    value.extend_from_slice(edge);
    value
}

/// [`held_value`] read back, or `None` for a row that does not decode.
#[cfg(feature = "sync")]
fn read_held(value: &[u8]) -> Option<(u64, Option<EntityId>, &[u8])> {
    let (held_at, rest) = value.split_first_chunk::<8>()?;
    let (grant, edge) = match rest.split_first()? {
        (0, edge) => (None, edge),
        (1, rest) => {
            let (grant, edge) = rest.split_first_chunk::<16>()?;
            (Some(EntityId::from_bytes(*grant).ok()?), edge)
        }
        _ => return None,
    };
    Some((u64::from_be_bytes(*held_at), grant, edge))
}

/// The bytes one held row takes: its whole stored key, the table's prefix
/// included, and its value (Sol R10 F1 on #1432).
fn row_bytes(lane: &str, value: &[u8]) -> u64 {
    (PARKED_STAMP.decl().prefix.len() + 64 + lane.len() + value.len()) as u64
}

/// The rows `lane` holds and the bytes they take.
fn lane_usage(dbs: &impl SideTableDbs, txn: &heed::RoTxn<'_>, lane: &str) -> Result<(u64, u64)> {
    let Some(usage) = PARKED_BY_LANE.get(dbs, txn, &lane.to_owned())? else {
        return Ok((0, 0));
    };
    let (rows, bytes) = usage
        .split_first_chunk::<8>()
        .and_then(|(rows, bytes)| Some((*rows, <[u8; 8]>::try_from(bytes).ok()?)))
        .ok_or(Error::CorruptedIndex("held facet stamp lane"))?;
    Ok((u64::from_be_bytes(rows), u64::from_be_bytes(bytes)))
}

fn put_lane_usage(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    lane: &str,
    (rows, bytes): (u64, u64),
) -> Result<()> {
    if rows == 0 {
        PARKED_BY_LANE.delete(dbs, wtxn, &lane.to_owned())?;
        return Ok(());
    }
    let mut usage = rows.to_be_bytes().to_vec();
    usage.extend_from_slice(&bytes.to_be_bytes());
    PARKED_BY_LANE.put(dbs, wtxn, &lane.to_owned(), &usage)
}

/// Removes one held row, and its share of its lane's usage; `true` when it
/// was there.
fn remove_held(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &(HexId, HexId, String),
) -> Result<bool> {
    let Some(value) = PARKED_STAMP.get(dbs, wtxn, key)? else {
        return Ok(false);
    };
    PARKED_STAMP.delete(dbs, wtxn, key)?;
    let (rows, bytes) = lane_usage(dbs, wtxn, &key.2)?;
    let freed = row_bytes(&key.2, &value);
    put_lane_usage(
        dbs,
        wtxn,
        &key.2,
        (rows.saturating_sub(1), bytes.saturating_sub(freed)),
    )?;
    Ok(true)
}

/// What holding one stamp came to.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hold {
    Held,
    /// The peer holds [`MAX_HELD_PER_ROW`] stamps on the row already: the
    /// stamp is not held, so it never counts (fail-closed).
    RowFull,
    /// The sender holds [`MAX_HELD_PER_SENDER`] stamps, or
    /// [`MAX_HELD_BYTES_PER_SENDER`] bytes of them, already: the stamp is
    /// refused.
    SenderFull,
}

/// Holds the stamp `src -FacetOf-> facet`, with its edge `value`, under the
/// sender's `lane` and the `grant` it sent it under, as of `now`. Only a
/// `capped` sender, a federation peer, meets the caps: the owner's own staged
/// import never does.
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
    if capped
        && prior.is_none()
        && PARKED_STAMP
            .scan_keys(dbs, wtxn, src.to_hex().as_bytes())?
            .into_iter()
            .filter(|held| held.2 == lane)
            .count()
            >= MAX_HELD_PER_ROW
    {
        return Ok(Hold::RowFull);
    }
    let row = held_value(now, grant, value);
    let (rows, bytes) = lane_usage(dbs, wtxn, lane)?;
    let freed = prior.as_deref().map_or(0, |prior| row_bytes(lane, prior));
    let rows = rows.saturating_add(u64::from(prior.is_none()));
    let bytes = bytes
        .saturating_sub(freed)
        .saturating_add(row_bytes(lane, &row));
    if capped && (rows > MAX_HELD_PER_SENDER || bytes > MAX_HELD_BYTES_PER_SENDER) {
        return Ok(Hold::SenderFull);
    }
    PARKED_STAMP.put(dbs, wtxn, &key, &row)?;
    put_lane_usage(dbs, wtxn, lane, (rows, bytes))?;
    Ok(Hold::Held)
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

/// The stamps on `src` held under `lane`: each facet with its edge value.
#[cfg(feature = "sync")]
pub(crate) fn parked_under(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    lane: &str,
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let mut stamps = Vec::new();
    for key in PARKED_STAMP.scan_keys(dbs, txn, src.to_hex().as_bytes())? {
        if key.2 == lane
            && let Some(value) = PARKED_STAMP.get(dbs, txn, &key)?
            && let Some((_, _, edge)) = read_held(&value)
        {
            stamps.push((key.1.0, edge.to_vec()));
        }
    }
    Ok(stamps)
}

/// The rows `lane` holds and the bytes they take, by its usage row.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn held_by(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    lane: &str,
) -> Result<(u64, u64)> {
    lane_usage(dbs, txn, lane)
}

/// Every held row under `lane`, counted one by one, and the bytes their
/// stored keys and values take.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn held_rows_under(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    lane: &str,
) -> Result<(u64, u64)> {
    Ok(PARKED_STAMP
        .scan(dbs, txn)?
        .into_iter()
        .filter(|(key, _)| key.2 == lane)
        .fold((0, 0), |(rows, bytes), (key, value)| {
            let stored = PARKED_STAMP.key_bytes(&key).len() + value.len();
            (rows + 1, bytes + stored as u64)
        }))
}

/// Retires each held stamp that [`retiring`] names by `now`; returns how
/// many went. Each is judged again, with its grant, in the transaction that
/// removes it, so a hold renewed since the scan under a grant that confers
/// again stays (Sol R10 F3 on #1432).
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
        for key in candidates {
            if let Some(value) = PARKED_STAMP.get(&vault.store, wtxn, &key)? {
                rows.push((key, value));
            }
        }
        let mut count = 0;
        for key in retiring(&vault.store, wtxn, now, rows, &conferring)? {
            if remove_held(&vault.store, wtxn, &key)? {
                count += 1;
            }
        }
        Ok(count)
    })
}

/// The keys among `rows` that retire by `now`, judged in `txn`: a peer's
/// stamp held [`HELD_STAMP_TTL_SECS`] or longer or under a grant `conferring`
/// no longer returns, a staged stamp whose receipt keeps no record of it any
/// more (it left Pending), and a row whose lane or value does not decode.
#[cfg(feature = "sync")]
fn retiring(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    now: u64,
    rows: Vec<((HexId, HexId, String), Vec<u8>)>,
    conferring: &impl Fn(&heed::RoTxn<'_>, &BTreeSet<EntityId>) -> Result<BTreeSet<EntityId>>,
) -> Result<Vec<(HexId, HexId, String)>> {
    let grants = rows
        .iter()
        .filter_map(|(_, value)| read_held(value)?.1)
        .collect();
    let live = conferring(txn, &grants)?;
    let mut retire = Vec::new();
    for (key, value) in rows {
        let gone = match (HeldLane::parse(&key.2), read_held(&value)) {
            (None, _) | (_, None) => true,
            (Some(HeldLane::Peer(_)), Some((held_at, grant, _))) => {
                now.saturating_sub(held_at) >= HELD_STAMP_TTL_SECS
                    || grant.is_some_and(|grant| !live.contains(&grant))
            }
            (Some(HeldLane::Staged(receipt)), Some(_)) => {
                !crate::batch::export::vault_import_keeps_stamps_in(dbs, txn, &receipt)?
            }
        };
        if gone {
            retire.push(key);
        }
    }
    Ok(retire)
}

impl Vault {
    /// Whether the row `id` sits in one of `facets`, by the rule every read
    /// lane applies (`facets_admit_in`). A row that is not stored sits in
    /// none.
    pub fn row_in_facets(&self, id: &EntityId, facets: &ScopeAxis<ScopeId>) -> Result<bool> {
        if matches!(facets, ScopeAxis::All) {
            return Ok(true);
        }
        let txn = self.store.env.read_txn()?;
        let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw_wiped(&self.store, &txn, id)?
        else {
            return Ok(false);
        };
        facets_admit_in(self, &self.store, &txn, *id, &raw, facets)
    }
}
