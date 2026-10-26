//! The carrier's four side tables and their typed access. The head is this
//! node's place in the lineage; parts hold the sealed bytes of a frozen
//! handoff, or on its target the parts staged so far; receipts hold the ack
//! of an adopted one; a transfer row is one handoff's status on this node.
//! All four stand as the live vault holds them through a restore.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::envelope::SignedHeader;
use super::routes::RouteCatalog;
use super::{
    HOME_HANDOFF_PART_BYTES, HandoffId, HandoffStatus, HomeAck, HomeMove, IncompleteReason, refused,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// This node's place in the home-state lineage. Key: ().
const HEAD: SideTable<(), HandoffHead, Named> = SideTable::new(&side_table::HOME_HANDOFF_HEAD);
/// One part of a handoff's sealed bytes. Key: id32 + u32be part index.
const PART: SideTable<(HandoffId, [u8; 4]), HandoffPart, Named> =
    SideTable::new(&side_table::HOME_HANDOFF_PART);
/// The signed ack of one handoff: the one this node signed as its target,
/// or the one its target returned. Key: id32.
const RECEIPT: SideTable<HandoffId, HomeAck, Named> =
    SideTable::new(&side_table::HOME_HANDOFF_RECEIPT);
/// One handoff's status on this node. Key: id32.
const TRANSFER: SideTable<HandoffId, HandoffTransfer, Named> =
    SideTable::new(&side_table::HOME_HANDOFF_TRANSFER);

/// Which end of a handoff this node was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum HandoffRole {
    Source,
    Target,
}

/// The newest generation this node froze or adopted. A move at or below it
/// is stale here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HeadFloor {
    pub(super) serial: u64,
    pub(super) handoff: HandoffId,
    pub(super) role: HandoffRole,
}

/// A home move this node's election recorded, by sync node id, that no
/// export or adoption has answered yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MoveRequest {
    pub(super) from: Option<u64>,
    pub(super) to: Option<u64>,
}

/// The endpoint a home move's target was captured at when the move came
/// (FIX 5661 C2a): the move's own target, never whatever home a route names
/// later. `endpoint` is `None` when nothing named one for that node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HandoffRoute {
    /// The target's sync node id.
    pub(super) to: u64,
    pub(super) endpoint: Option<String>,
}

/// The handoff a target stages, as its parts named it (FIX 5661 C2b): its
/// sealed bytes' digest, how many parts hold them, and the machine its
/// socket proved. Ready once every part is staged, so the new home can adopt
/// it before its first free-time pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StagedHandoff {
    pub(super) id: HandoffId,
    pub(super) digest: [u8; 32],
    pub(super) count: u32,
    pub(super) source: EntityId,
}

/// This node's place in the home-state lineage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HandoffHead {
    pub(super) floor: Option<HeadFloor>,
    pub(super) request: Option<MoveRequest>,
    /// Why the last move that named this node carried nothing, if it did not.
    pub(super) incomplete: Option<IncompleteReason>,
    /// The route captured for `request`'s target, with the move (FIX 6459).
    pub(super) route: Option<HandoffRoute>,
    /// The handoff this node last staged as a target, until it lands.
    pub(super) staged: Option<StagedHandoff>,
    /// FIX 5931: the handoffs whose sources cancelled them here before they
    /// landed; none of them ever lands here.
    #[serde(default)]
    pub(super) fenced: Vec<HandoffId>,
    /// FIX 6459: the routes this node's host last fed, which each move the
    /// election records captures its route from; `None` until a feed.
    #[serde(default)]
    pub(super) routes: Option<RouteCatalog>,
}

impl HandoffHead {
    /// Whether this node holds its managed state: it froze none for a move,
    /// or it adopted the state after it last froze it.
    pub(super) fn holds_state(&self) -> bool {
        self.floor
            .is_none_or(|floor| floor.role == HandoffRole::Target)
    }

    /// Whether handoff `id`'s source cancelled it here (FIX 5931).
    pub(super) fn fenced(&self, id: &HandoffId) -> bool {
        self.fenced.contains(id)
    }
}

/// One handoff's status on this node, with the signed header a later move
/// carries as its lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HandoffTransfer {
    pub(super) role: HandoffRole,
    pub(super) status: HandoffStatus,
    pub(super) movement: HomeMove,
    pub(super) signed: SignedHeader,
    pub(super) digest: [u8; 32],
    /// How many parts hold the sealed bytes here; none on a target.
    pub(super) parts: u32,
    /// The route the source delivers to, captured with the move; none on a
    /// target.
    pub(super) route: Option<HandoffRoute>,
}

/// One part of a handoff's sealed bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HandoffPart(#[serde(with = "super::bin")] Vec<u8>);

/// This node's head; the default when it never took part in a move.
pub(super) fn head_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<HandoffHead> {
    Ok(HEAD.get(dbs, txn, &())?.unwrap_or_default())
}

pub(super) fn put_head_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    head: &HandoffHead,
) -> Result<()> {
    HEAD.put(dbs, txn, &(), head)
}

pub(super) fn transfer_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
) -> Result<Option<HandoffTransfer>> {
    TRANSFER.get(dbs, txn, id)
}

pub(super) fn put_transfer_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &HandoffId,
    transfer: &HandoffTransfer,
) -> Result<()> {
    TRANSFER.put(dbs, txn, id, transfer)
}

pub(super) fn receipt_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
) -> Result<Option<HomeAck>> {
    RECEIPT.get(dbs, txn, id)
}

pub(super) fn put_receipt_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    ack: &HomeAck,
) -> Result<()> {
    RECEIPT.put(dbs, txn, &ack.id, ack)
}

/// Stores `sealed` as the parts of handoff `id`, each at most
/// [`HOME_HANDOFF_PART_BYTES`]; returns how many.
pub(super) fn put_parts_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &HandoffId,
    sealed: &[u8],
) -> Result<u32> {
    let mut count = 0u32;
    for part in sealed.chunks(HOME_HANDOFF_PART_BYTES) {
        PART.put(
            dbs,
            txn,
            &(*id, count.to_be_bytes()),
            &HandoffPart(part.to_vec()),
        )?;
        count = count
            .checked_add(1)
            .ok_or_else(|| refused("a handoff has more parts than an index holds"))?;
    }
    Ok(count)
}

/// The sealed bytes of handoff `id`, joined from its `parts` parts.
pub(super) fn sealed_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
    parts: u32,
) -> Result<Vec<u8>> {
    let mut sealed = Vec::new();
    for index in 0..parts {
        let HandoffPart(bytes) = PART
            .get(dbs, txn, &(*id, index.to_be_bytes()))?
            .ok_or_else(|| refused("a frozen handoff is missing a part"))?;
        sealed.extend_from_slice(&bytes);
    }
    Ok(sealed)
}

/// Part `index` of handoff `id`'s sealed bytes, if this node holds it.
pub(super) fn part_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
    index: u32,
) -> Result<Option<Vec<u8>>> {
    Ok(PART
        .get(dbs, txn, &(*id, index.to_be_bytes()))?
        .map(|HandoffPart(bytes)| bytes))
}

/// How many parts of handoff `id` this node holds in order from the first:
/// on its target, the durable staged position.
pub(super) fn staged_position_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
) -> Result<u32> {
    let mut index = 0u32;
    while PART.contains(dbs, txn, &(*id, index.to_be_bytes()))? {
        index = index
            .checked_add(1)
            .ok_or_else(|| refused("a handoff has more parts than an index holds"))?;
    }
    Ok(index)
}

/// Stages part `index` of handoff `id` on its target. A part at the staged
/// position lands; one before it must be the bytes already there, so a part
/// sent again after a lost reply resumes; one past it is refused. Returns
/// the staged position after it.
pub(super) fn stage_part_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &HandoffId,
    index: u32,
    bytes: &[u8],
) -> Result<u32> {
    let position = staged_position_in_txn(dbs, txn, id)?;
    if index < position {
        let HandoffPart(held) = PART
            .get(dbs, txn, &(*id, index.to_be_bytes()))?
            .ok_or_else(|| refused("a staged part is missing"))?;
        if held != bytes {
            return Err(refused("a part differs from the one staged"));
        }
        return Ok(position);
    }
    if index > position {
        return Err(refused("a part comes before the ones it follows"));
    }
    PART.put(
        dbs,
        txn,
        &(*id, index.to_be_bytes()),
        &HandoffPart(bytes.to_vec()),
    )?;
    staged_position_in_txn(dbs, txn, id)
}

/// Drops the staged parts of handoff `id` once it landed here.
pub(super) fn drop_staged_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    id: &HandoffId,
) -> Result<()> {
    let mut index = 0u32;
    while PART.delete(dbs, txn, &(*id, index.to_be_bytes()))? {
        let Some(next) = index.checked_add(1) else {
            break;
        };
        index = next;
    }
    Ok(())
}

/// CALLS no carrier: a home move that carried nothing (the old home gone
/// before it exported, a lineage that does not chain here, a conflict) is
/// recorded Incomplete with its reason, and nothing refuses for it: the new
/// home keeps today's local opening. An outcome to show, never a wait.
pub(crate) fn record_incomplete_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    reason: IncompleteReason,
) -> Result<()> {
    let mut head = head_in_txn(dbs, txn)?;
    head.incomplete = Some(reason);
    put_head_in_txn(dbs, txn, &head)
}

/// One handoff's status on this node, if it took part in it.
pub(crate) fn handoff_status_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &HandoffId,
) -> Result<Option<HandoffStatus>> {
    Ok(transfer_in_txn(dbs, txn, id)?.map(|transfer| transfer.status))
}

/// Why the last home move that named this node carried nothing, if it did
/// not.
pub(crate) fn incomplete_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<IncompleteReason>> {
    Ok(head_in_txn(dbs, txn)?.incomplete)
}
