//! FIX 5661 C2a: what delivery asks of the carrier, additive beside C1. The
//! source's connection worker reads its plan here ([`delivery_plan`]): freeze
//! for the move its election recorded, deliver what it froze to the route
//! captured with the move ([`super::routes`]), or first resolve where its
//! target stands. The target's engine doors stage the parts here and adopt
//! through C1's [`super::adopt`].
//!
//! FIX 5931: a source elected home again before its target acked reads the
//! target's persisted status first. Never adopted there, it cancels the
//! handoff and takes its state back ([`cancel_frozen`]); adopted, it records
//! the ack and stays history; unread, it records Incomplete and stays frozen.
//! A second move before the first adopted (A to B, then B to C) resolves the
//! same way: adopted at B, B drains its own state; provably not, A supersedes
//! from its frozen state in one writer ([`supersede_export`]). An absent ack
//! or a timeout is never read as "not adopted".
//!
//! FIX 6574: a target's status names a handoff fenced there for good. A
//! source that delivers one (it missed its own cancel, then the home moved
//! to that target again) takes its state back and records a fresh move to
//! the home its election names, that same target included
//! ([`replan_fenced`]); the new export takes a fresh id.

use heed::{RoTxn, RwTxn};

use super::routes;
use super::store::{self, HandoffHead, HandoffRole, HeadFloor, MoveRequest, StagedHandoff};
use super::table::check_registry;
use super::transfer::{ack_in_txn, freeze_in_txn};
use super::{
    HandoffId, HandoffStatus, HomeAck, HomeGeneration, HomeIdentity, HomeMove, IncompleteReason,
    SealedHandoff, home_tables, refused, verify_ack,
};
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::dreamer_runner::{DreamerHomeNodeDesignation, DreamerRunnerStore};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{Named, SideCodec};

const BASIS_DOMAIN: &[u8] = b"oneiron/home-handoff/election-basis/v1\0";

/// A handoff this node froze that no target acked yet, and what delivering
/// it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrozenHandoff {
    pub(crate) id: HandoffId,
    pub(crate) digest: [u8; 32],
    pub(crate) movement: HomeMove,
    /// How many parts hold its sealed bytes here.
    pub(crate) parts: u32,
    /// The endpoint captured for its target with the move; `None` when none
    /// was named for that node.
    pub(crate) endpoint: Option<String>,
}

/// What the source's worker does next for the state this node holds or
/// froze.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryPlan {
    /// Nothing to freeze or deliver here.
    Idle,
    /// The home moved from this node: freeze for this move once every
    /// registered table is quiescent.
    Freeze(HomeMove),
    /// Deliver the frozen handoff to its captured target.
    Deliver(FrozenHandoff),
    /// FIX 5931: this node is elected home again before its target acked.
    Reclaim(FrozenHandoff),
    /// The home moved on past the frozen handoff's target before it acked;
    /// the move a supersession takes, or `None` when this node knows no
    /// machine for the new home.
    Supersede(FrozenHandoff, Option<HomeMove>),
}

/// The home and the move a worker last planned for: an election moves one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ElectionMark {
    home: Option<u64>,
    request: Option<MoveRequest>,
}

/// The home this node's election names and the move it last recorded.
pub(crate) fn election_mark(vault: &Vault) -> Result<ElectionMark> {
    let txn = vault.store.env.read_txn()?;
    Ok(ElectionMark {
        home: DreamerRunnerStore::new(vault)
            .home_node_designation_in_txn(&txn)?
            .map(|home| home.node_id),
        request: store::head_in_txn(vault, &txn)?.request,
    })
}

/// The source's next step. A node that froze a handoff no target acked
/// delivers it, unless this node is home again (reclaim) or the home moved
/// on to a third node (supersede). A node that holds its state and whose
/// election moved the home from it to another node freezes for that move;
/// one whose last move carried nothing (Incomplete) never exports what it
/// opened locally as the lineage's state. Everything else is idle.
pub(crate) fn delivery_plan(vault: &Vault) -> Result<DeliveryPlan> {
    let txn = vault.store.env.read_txn()?;
    let machine = crate::identity::read_machine_id_in_txn(vault, &txn)?;
    let node = crate::identity::read_client_id_in_txn(vault, &txn)?;
    let (Some(machine), Some(node)) = (machine, node) else {
        return Ok(DeliveryPlan::Idle);
    };
    let source = HomeIdentity {
        machine,
        node_id: node,
    };
    let head = store::head_in_txn(vault, &txn)?;
    let home = DreamerRunnerStore::new(vault).home_node_designation_in_txn(&txn)?;
    if let Some(frozen) = frozen_in_txn(vault, &txn, &head)? {
        if home.is_some_and(|home| home.node_id == node) {
            return Ok(DeliveryPlan::Reclaim(frozen));
        }
        let onward = head
            .request
            .and_then(|request| request.to)
            .filter(|to| *to != node && *to != frozen.movement.target.node_id);
        let Some(to) = onward else {
            return Ok(DeliveryPlan::Deliver(frozen));
        };
        // A supersession takes the generation the frozen move took, from the
        // state before it.
        let generation = frozen.movement.generation;
        let movement = move_to(vault, &txn, &head, home.as_ref(), source, to, generation)?;
        return Ok(DeliveryPlan::Supersede(frozen, movement));
    }
    if !head.holds_state() || head.incomplete.is_some() {
        return Ok(DeliveryPlan::Idle);
    }
    let Some(MoveRequest {
        from: Some(from),
        to: Some(to),
    }) = head.request
    else {
        return Ok(DeliveryPlan::Idle);
    };
    if from != node || to == node {
        return Ok(DeliveryPlan::Idle);
    }
    let generation = next_generation(&head)?;
    Ok(
        match move_to(vault, &txn, &head, home.as_ref(), source, to, generation)? {
            Some(movement) => DeliveryPlan::Freeze(movement),
            None => DeliveryPlan::Idle,
        },
    )
}

/// The handoff the floor names, while this node froze it and no target
/// acked it.
fn frozen_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    head: &HandoffHead,
) -> Result<Option<FrozenHandoff>> {
    let Some(floor) = head.floor.filter(|floor| floor.role == HandoffRole::Source) else {
        return Ok(None);
    };
    let Some(transfer) = store::transfer_in_txn(vault, txn, &floor.handoff)?
        .filter(|transfer| transfer.status == HandoffStatus::Frozen)
    else {
        return Ok(None);
    };
    let target = transfer.movement.target.node_id;
    Ok(Some(FrozenHandoff {
        id: floor.handoff,
        digest: transfer.digest,
        movement: transfer.movement,
        parts: transfer.parts,
        endpoint: transfer
            .route
            .filter(|route| route.to == target)
            .and_then(|route| route.endpoint),
    }))
}

/// The move from `source` to sync node `to` at `generation`, or `None` when
/// this node knows no single owner machine for that node.
fn move_to(
    vault: &Vault,
    txn: &RoTxn<'_>,
    head: &HandoffHead,
    home: Option<&DreamerHomeNodeDesignation>,
    source: HomeIdentity,
    to: u64,
    generation: HomeGeneration,
) -> Result<Option<HomeMove>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let (Some(vault_id), Some(machine)) = (fold.vault_id, target_machine(&fold, to)) else {
        return Ok(None);
    };
    let target = HomeIdentity {
        machine,
        node_id: to,
    };
    Ok(Some(HomeMove {
        vault_id,
        source,
        target,
        generation,
        election_basis: election_basis(&vault_id, head.request, home, &target),
    }))
}

/// The one machine whose home candidacy names sync node `node` and that
/// stands here as one of the owner's machines; `None` when none or more than
/// one does. The candidacy's node id is the machine's own signed word.
fn target_machine(fold: &AuthorityFold, node: u64) -> Option<EntityId> {
    let mut named = fold
        .home_candidacy
        .iter()
        .filter(|(_, declared)| declared.node_id == node)
        .map(|(machine, _)| *machine);
    let machine = named.next()?;
    if named.next().is_some() {
        return None;
    }
    fold.trusted_machine(machine).map(|_| machine)
}

/// The generation the next move of the state this node holds takes: 0 with
/// no predecessor before any move, else one past the handoff it adopted.
fn next_generation(head: &HandoffHead) -> Result<HomeGeneration> {
    Ok(match head.floor {
        None => HomeGeneration {
            serial: 0,
            predecessor: None,
        },
        Some(floor) => HomeGeneration {
            serial: floor
                .serial
                .checked_add(1)
                .ok_or_else(|| refused("the lineage has no next generation"))?,
            predecessor: Some(floor.handoff),
        },
    })
}

/// A digest of the election evidence the source read for a move: the move
/// its election recorded, the designation it read and the target.
fn election_basis(
    vault_id: &[u8; 32],
    request: Option<MoveRequest>,
    home: Option<&DreamerHomeNodeDesignation>,
    target: &HomeIdentity,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BASIS_DOMAIN);
    hasher.update(vault_id);
    let nodes = [
        request.and_then(|request| request.from),
        request.and_then(|request| request.to),
        home.map(|home| home.node_id),
    ];
    for node in nodes {
        match node {
            Some(node) => hasher.update(&[1]).update(&node.to_be_bytes()),
            None => hasher.update(&[0]),
        };
    }
    hasher.update(&home.map_or(0, |home| home.elected_at).to_be_bytes());
    hasher.update(target.machine.as_bytes());
    hasher.update(&target.node_id.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Part `index` of the sealed bytes of handoff `id` this node froze.
pub(crate) fn frozen_part(vault: &Vault, id: &HandoffId, index: u32) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    store::part_in_txn(vault, &txn, id, index)?
        .ok_or_else(|| refused("a frozen handoff is missing a part"))
}

/// The source records the ack its target returned for handoff `id`, once
/// the target machine's key verifies it ([`ack_in_txn`]).
pub(crate) fn record_ack(vault: &Vault, id: &HandoffId, ack: HomeAck) -> Result<()> {
    if ack.id != *id {
        return Err(refused("the ack names another handoff"));
    }
    let verified = verify_ack(vault, ack)?;
    vault.with_write_txn(|txn| ack_in_txn(vault, txn, &verified))
}

/// Records `reason` as why the last move naming this node carried nothing,
/// unless it is recorded already.
pub(crate) fn record_unresolved(vault: &Vault, reason: IncompleteReason) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    if store::head_in_txn(vault, &txn)?.incomplete == Some(reason) {
        return Ok(());
    }
    drop(txn);
    vault.with_write_txn(|txn| store::record_incomplete_in_txn(vault, txn, reason))
}

/// FIX 5931: cancels handoff `id`, which this node froze and whose target's
/// persisted status says it never adopted. The handoff stays as Cancelled
/// history and the floor goes back to the one before the freeze, so this
/// node holds its state again; the consumers wake.
pub(crate) fn cancel_frozen(vault: &Vault, id: &HandoffId) -> Result<()> {
    vault.with_write_txn(|txn| cancel_in_txn(vault, txn, id))?;
    vault.store.notify_proactivity_changes();
    Ok(())
}

fn cancel_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, id: &HandoffId) -> Result<()> {
    let mut head = store::head_in_txn(vault, txn)?;
    if head
        .floor
        .filter(|floor| floor.role == HandoffRole::Source)
        .map(|floor| floor.handoff)
        != Some(*id)
    {
        return Err(refused("this node holds no frozen handoff with this id"));
    }
    let mut transfer = store::transfer_in_txn(vault, txn, id)?
        .filter(|transfer| transfer.status == HandoffStatus::Frozen)
        .ok_or_else(|| refused("the handoff is not frozen here"))?;
    // The freeze took the generation after the floor it replaced.
    let generation = transfer.movement.generation;
    head.floor = match generation.predecessor {
        None => None,
        Some(handoff) => Some(HeadFloor {
            serial: generation
                .serial
                .checked_sub(1)
                .ok_or_else(|| refused("the lineage has no earlier generation"))?,
            handoff,
            role: HandoffRole::Target,
        }),
    };
    head.incomplete = None;
    transfer.status = HandoffStatus::Cancelled;
    store::put_transfer_in_txn(vault, txn, id, &transfer)?;
    store::put_head_in_txn(vault, txn, &head)
}

/// FIX 6574: handoff `id`, which this node froze, is fenced at its target
/// for good (its status said so). In one writer this node cancels it, as
/// [`cancel_frozen`] does, after the same check that the floor still names
/// it frozen, and records a fresh move from this node to the home its
/// election names now, that same target included, so the next round freezes
/// a new export for it. The move's route comes from the routes the host fed,
/// else the one the fenced handoff kept for that node. A node its election
/// names home records no move; the consumers wake.
pub(crate) fn replan_fenced(vault: &Vault, id: &HandoffId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let kept = store::transfer_in_txn(vault, txn, id)?.and_then(|transfer| transfer.route);
        cancel_in_txn(vault, txn, id)?;
        let node = crate::identity::read_client_id_in_txn(vault, txn)?;
        let home = DreamerRunnerStore::new(vault)
            .home_node_designation_in_txn(txn)?
            .map(|home| home.node_id);
        let (Some(node), Some(home)) = (node, home) else {
            return Ok(());
        };
        let fresh = MoveRequest {
            from: Some(node),
            to: Some(home),
        };
        let mut head = store::head_in_txn(vault, txn)?;
        if home == node || head.request == Some(fresh) {
            return Ok(());
        }
        head.request = Some(fresh);
        head.route = routes::route_for(&head, home).or(kept.filter(|route| route.to == home));
        store::put_head_in_txn(vault, txn, &head)
    })?;
    vault.store.notify_proactivity_changes();
    Ok(())
}

/// Why a supersession's writer dropped.
enum Unfrozen {
    NotQuiescent,
    Failed(Error),
}

impl From<Error> for Unfrozen {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// A to B to C: cancels handoff `superseded`, which B provably never
/// adopted, and freezes this node's state for `movement` in the same writer,
/// so the state is never held twice or not at all. `None` when a table is
/// not quiescent: the writer drops and the frozen handoff stands.
pub(crate) fn supersede_export(
    vault: &Vault,
    superseded: &HandoffId,
    movement: &HomeMove,
) -> Result<Option<SealedHandoff>> {
    let tables = home_tables();
    check_registry(&tables)?;
    // The install key signs in the writer: load it here.
    vault.load_install_signing_if_minted()?;
    let frozen = vault.try_with_write_txn(|txn| {
        cancel_in_txn(vault, txn, superseded)?;
        freeze_in_txn(vault, txn, movement, &tables)?.ok_or(Unfrozen::NotQuiescent)
    });
    match frozen {
        Ok(sealed) => Ok(Some(sealed)),
        Err(Unfrozen::NotQuiescent) => Ok(None),
        Err(Unfrozen::Failed(error)) => Err(error),
    }
}

/// Refuses handoff `id` at its target's doors when this node froze it.
fn not_source_in_txn(vault: &Vault, txn: &RoTxn<'_>, id: &HandoffId) -> Result<()> {
    if store::transfer_in_txn(vault, txn, id)?
        .is_some_and(|transfer| transfer.role == HandoffRole::Source)
    {
        return Err(refused("this node froze this handoff"));
    }
    Ok(())
}

/// The ack this node signed when it adopted handoff `id` as its target.
pub(crate) fn target_receipt(vault: &Vault, id: &HandoffId) -> Result<Option<HomeAck>> {
    let txn = vault.store.env.read_txn()?;
    not_source_in_txn(vault, &txn, id)?;
    let adopted = store::transfer_in_txn(vault, &txn, id)?.is_some_and(|transfer| {
        transfer.role == HandoffRole::Target && transfer.status == HandoffStatus::Adopted
    });
    if !adopted {
        return Ok(None);
    }
    store::receipt_in_txn(vault, &txn, id)
}

/// How many parts of handoff `id` this target holds staged, in order.
pub(crate) fn staged_position(vault: &Vault, id: &HandoffId) -> Result<u32> {
    let txn = vault.store.env.read_txn()?;
    not_source_in_txn(vault, &txn, id)?;
    store::staged_position_in_txn(vault, &txn, id)
}

/// FIX 6574: whether handoff `id`'s source cancelled it here, so it never
/// lands here.
pub(crate) fn fenced_here(vault: &Vault, id: &HandoffId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    not_source_in_txn(vault, &txn, id)?;
    Ok(store::head_in_txn(vault, &txn)?.fenced(id))
}

/// Stages part `index` of handoff `id` here as its target; returns the
/// staged position after it ([`store::stage_part_in_txn`]). The head keeps
/// what the parts name (FIX 5661 C2b): the digest of the sealed bytes, how
/// many parts hold them, and `source`, the machine its socket proved, so the
/// new home finds a completely staged handoff before its first free-time
/// pass. A part that names another digest, count or source than the ones
/// staged for this id is refused, as is a part of a handoff its source
/// cancelled here (FIX 5931).
pub(crate) fn stage_part(
    vault: &Vault,
    id: &HandoffId,
    digest: &[u8; 32],
    count: u32,
    source: EntityId,
    index: u32,
    bytes: &[u8],
) -> Result<u32> {
    let staged = StagedHandoff {
        id: *id,
        digest: *digest,
        count,
        source,
    };
    vault.with_write_txn(|txn| {
        not_source_in_txn(vault, txn, &staged.id)?;
        let mut head = store::head_in_txn(vault, txn)?;
        if head.fenced(&staged.id) {
            return Err(refused("the source cancelled this handoff here"));
        }
        if head
            .staged
            .is_some_and(|held| held.id == staged.id && held != staged)
        {
            return Err(refused("a part names other bytes than the ones staged"));
        }
        let position = store::stage_part_in_txn(vault, txn, &staged.id, index, bytes)?;
        if head.staged != Some(staged) {
            head.staged = Some(staged);
            store::put_head_in_txn(vault, txn, &head)?;
        }
        Ok(position)
    })
}

/// FIX 5931: the target's answer when the source cancels handoff `id`,
/// sealed to the bytes `digest` names, in one writer, so it serializes with
/// the writer that adopts. Adopted here first, it stays adopted and the
/// saved ack is the answer. Otherwise the id is fenced here for good: its
/// staged parts go, and no adopting writer lands it after (`None`). The
/// source takes its state back only after that. `source` is the machine
/// the caller's socket proved; parts staged from another are refused.
pub(crate) fn fence_handoff(
    vault: &Vault,
    id: &HandoffId,
    digest: &[u8; 32],
    source: EntityId,
) -> Result<Option<HomeAck>> {
    vault.with_write_txn(|txn| {
        not_source_in_txn(vault, txn, id)?;
        if let Some(ack) = store::receipt_in_txn(vault, txn, id)? {
            if ack.digest != *digest {
                return Err(refused("the handoff adopted here has other bytes"));
            }
            return Ok(Some(ack));
        }
        let mut head = store::head_in_txn(vault, txn)?;
        let staged = head.staged.filter(|staged| staged.id == *id);
        if staged.is_some_and(|staged| staged.source != source) {
            return Err(refused("another machine staged this handoff"));
        }
        if staged.is_some() {
            head.staged = None;
        }
        if !head.fenced(id) {
            head.fenced.push(*id);
        }
        store::put_head_in_txn(vault, txn, &head)?;
        store::drop_staged_in_txn(vault, txn, id)?;
        Ok(None)
    })
}

/// The staged parts of handoff `id`, joined.
pub(crate) fn staged_sealed(vault: &Vault, id: &HandoffId) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    not_source_in_txn(vault, &txn, id)?;
    let parts = store::staged_position_in_txn(vault, &txn, id)?;
    store::sealed_in_txn(vault, &txn, id, parts)
}

/// Drops the staged parts of handoff `id` once it landed here.
pub(crate) fn drop_staged(vault: &Vault, id: &HandoffId) -> Result<()> {
    vault.with_write_txn(|txn| {
        not_source_in_txn(vault, txn, id)?;
        store::drop_staged_in_txn(vault, txn, id)
    })
}

/// An ack as the residence lane carries it: named MessagePack.
pub(crate) fn encode_ack(ack: &HomeAck) -> Result<Vec<u8>> {
    <Named as SideCodec<HomeAck>>::encode(ack).map_err(|_| refused("an ack does not encode"))
}

pub(crate) fn decode_ack(bytes: &[u8]) -> Result<HomeAck> {
    <Named as SideCodec<HomeAck>>::decode(bytes).map_err(|_| refused("an ack does not decode"))
}
