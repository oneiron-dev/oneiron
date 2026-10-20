//! The carrier's steps: the drain request an election records, the fence a
//! registered table's write asks, the source's final freeze and export, the
//! target's one adopting transaction, and the source's ack.

use heed::{RoTxn, RwTxn};

use super::envelope::{self, SealedHandoff, TableSection, VerifiedHandoff, VerifiedHomeAck};
use super::lineage::{check_source, lineage_admits};
use super::store::{self, HandoffHead, HandoffRole, HandoffTransfer, HeadFloor, MoveRequest};
use super::table::{HomeTableRegistration, TableAdopt, check_registry};
use super::{
    AdoptOutcome, HandoffStatus, HomeFence, HomeMove, HomeWrite, IncompleteReason, refused,
};
use crate::Vault;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// Records that this node's election moved the home from sync node `from`
/// to `to`. It reads and writes the head row only: no export, signing or
/// sealing runs here, so the election's commit never fails for one. The
/// drain freezes and exports later ([`freeze_export`]). A move to the node
/// it left records nothing. A new move drops the route captured for the
/// last one.
pub(crate) fn request_move_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<()> {
    if from == to {
        return Ok(());
    }
    let mut head = store::head_in_txn(dbs, txn)?;
    head.request = Some(MoveRequest { from, to });
    head.route = None;
    store::put_head_in_txn(dbs, txn, &head)
}

/// The fence a registered table's write asks in its own transaction. A node
/// that froze its state for a move refuses both kinds: its rows are history
/// now. A node draining its state toward a move refuses a new admission and
/// lets an admitted one settle, so its tables go quiescent. Every other
/// node, a new home still waiting for its handoff included, writes as today.
pub(crate) fn guard_in_txn(vault: &Vault, txn: &RoTxn<'_>, mode: HomeWrite) -> Result<()> {
    let head = store::head_in_txn(vault, txn)?;
    if !head.holds_state() {
        return Err(refused("this node froze its home state for a move"));
    }
    if mode == HomeWrite::Admit && draining(vault, txn, &head)? {
        return Err(refused("this node is draining its home state for a move"));
    }
    Ok(())
}

/// Whether the last move this node's election recorded leaves this node.
fn draining(vault: &Vault, txn: &RoTxn<'_>, head: &HandoffHead) -> Result<bool> {
    let Some(request) = head.request else {
        return Ok(false);
    };
    let node = crate::identity::read_client_id_in_txn(vault, txn)?;
    Ok(node.is_some() && request.from == node && request.to != node)
}

/// The source's final writer for `movement`. While any registered table is
/// not quiescent it returns `None` and writes nothing. Otherwise, in that one
/// writer, every table exports from the same view, the manifest is signed
/// and sealed to the target, and the frozen status and the sealed parts
/// commit together: from then on this node's rows are history
/// ([`guard_in_txn`] refuses them). Asked again for the move it froze, it
/// returns the same sealed bytes, never a second export.
///
/// The move must start at this install and node, in this vault, take the
/// next generation of the state this node holds, and name another of the
/// owner's machines as its target.
pub(crate) fn freeze_export(
    vault: &Vault,
    movement: &HomeMove,
    tables: &[HomeTableRegistration],
) -> Result<Option<SealedHandoff>> {
    check_registry(tables)?;
    // The install key signs in the writer: load it here.
    vault.load_install_signing_if_minted()?;
    vault.with_write_txn(|txn| freeze_in_txn(vault, txn, movement, tables))
}

/// [`freeze_export`]'s final writer, for a caller that already holds it (a
/// supersession cancels and freezes in one). The caller checked the registry
/// and loaded the install key.
pub(super) fn freeze_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    movement: &HomeMove,
    tables: &[HomeTableRegistration],
) -> Result<Option<SealedHandoff>> {
    let view: &RoTxn<'_> = txn;
    let head = store::head_in_txn(vault, view)?;
    if let Some(floor) = head.floor.filter(|floor| floor.role == HandoffRole::Source) {
        return frozen_again(vault, view, &floor, movement).map(Some);
    }
    check_source(vault, view, &head, movement)?;
    let fold = vault.authority_view_readonly_in_txn(view)?;
    if fold.vault_id != Some(movement.vault_id) {
        return Err(refused("the move names another vault"));
    }
    let target = envelope::target_key(&fold, movement.target.machine)?;
    for table in tables {
        if !table.quiescent(vault, view, movement)? {
            return Ok(None);
        }
    }
    let fence = HomeFence::new(*movement);
    let mut sections = Vec::with_capacity(tables.len());
    for table in tables {
        sections.push(TableSection {
            table_id: table.table_id().to_owned(),
            schema_version: table.schema_version(),
            rows: table.export(vault, view, &fence)?,
        });
    }
    // The state this node adopted: its signed header is the lineage.
    let lineage = match head.floor {
        Some(floor) => Some(
            store::transfer_in_txn(vault, view, &floor.handoff)?
                .ok_or_else(|| refused("the handoff this node adopted is missing"))?
                .signed,
        ),
        None => None,
    };
    let key = vault.door_signing_key_in_txn(view, movement.source.machine)?;
    let (sealed, signed) = envelope::seal_handoff(movement, &key, &target, lineage, &sections)?;
    let parts = store::put_parts_in_txn(vault, txn, &sealed.id, &sealed.sealed)?;
    let transfer = HandoffTransfer {
        role: HandoffRole::Source,
        status: HandoffStatus::Frozen,
        movement: *movement,
        signed,
        digest: sealed.digest,
        parts,
        // The route captured for this move's target moves with it.
        route: head
            .route
            .clone()
            .filter(|route| route.to == movement.target.node_id),
    };
    store::put_transfer_in_txn(vault, txn, &sealed.id, &transfer)?;
    let floor = HeadFloor {
        serial: movement.generation.serial,
        handoff: sealed.id,
        role: HandoffRole::Source,
    };
    let head = HandoffHead {
        floor: Some(floor),
        request: None,
        incomplete: None,
        route: None,
    };
    store::put_head_in_txn(vault, txn, &head)?;
    Ok(Some(sealed))
}

/// The handoff this node froze, when it is `movement`'s: its same sealed
/// bytes again.
fn frozen_again(
    vault: &Vault,
    txn: &RoTxn<'_>,
    floor: &HeadFloor,
    movement: &HomeMove,
) -> Result<SealedHandoff> {
    let transfer = store::transfer_in_txn(vault, txn, &floor.handoff)?
        .ok_or_else(|| refused("the handoff this node froze is missing"))?;
    if transfer.movement != *movement {
        return Err(refused("this node froze its home state for another move"));
    }
    Ok(SealedHandoff {
        id: floor.handoff,
        digest: transfer.digest,
        movement: transfer.movement,
        sealed: store::sealed_in_txn(vault, txn, &floor.handoff, transfer.parts)?,
    })
}

/// Why the adopting writer dropped without landing anything.
enum Abort {
    /// Not yet; the reason is recorded when the lineage does not chain here.
    Pending(Option<IncompleteReason>),
    Stale,
    Conflict,
    Failed(Error),
}

impl From<Error> for Abort {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// The target's one adopting transaction for `handoff`. Before the writer,
/// every section must match one registered table at its version and decode
/// as its rows; a handoff for other tables or versions is Pending. In the
/// writer: a move for another node is Stale; the same id and digest return
/// the saved ack without calling any adopt, and the same id with other bytes
/// is a Conflict; while this node's own election does not name it home the
/// move is Pending; a generation at or below this node's floor is Stale; a
/// lineage that does not chain is Pending and recorded Incomplete. Then
/// every table adopts in that one transaction, and an error or a table's
/// Conflict drops the writer, so nothing partial lands. The signed ack, the
/// new floor and the status commit with the rows.
pub(crate) fn adopt(
    vault: &Vault,
    handoff: VerifiedHandoff,
    tables: &[HomeTableRegistration],
) -> Result<AdoptOutcome> {
    check_registry(tables)?;
    if !sections_match(&handoff, tables)? {
        return Ok(AdoptOutcome::Pending);
    }
    // The install key signs the ack in the writer: load it here.
    vault.load_install_signing_if_minted()?;
    let reason = match vault.try_with_write_txn(|txn| adopt_in_txn(vault, txn, &handoff, tables)) {
        Ok(outcome) => {
            if matches!(outcome, AdoptOutcome::Adopted(_)) {
                vault.store.notify_proactivity_changes();
            }
            return Ok(outcome);
        }
        Err(Abort::Pending(None)) => return Ok(AdoptOutcome::Pending),
        Err(Abort::Stale) => return Ok(AdoptOutcome::Stale),
        Err(Abort::Failed(error)) => return Err(error),
        Err(Abort::Pending(Some(reason))) => reason,
        Err(Abort::Conflict) => IncompleteReason::Conflict,
    };
    vault.with_write_txn(|txn| record_unadopted(vault, txn, &handoff, reason))?;
    Ok(match reason {
        IncompleteReason::Conflict => AdoptOutcome::Conflict,
        IncompleteReason::SourceGone
        | IncompleteReason::UnknownLineage
        | IncompleteReason::NoRoute
        | IncompleteReason::Unresolved => AdoptOutcome::Pending,
    })
}

fn adopt_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    handoff: &VerifiedHandoff,
    tables: &[HomeTableRegistration],
) -> std::result::Result<AdoptOutcome, Abort> {
    let movement = handoff.movement();
    let node = crate::identity::read_client_id_in_txn(vault, txn)?;
    if crate::identity::read_machine_id_in_txn(vault, txn)? != Some(movement.target.machine)
        || node != Some(movement.target.node_id)
    {
        return Err(Abort::Stale);
    }
    if let Some(ack) = store::receipt_in_txn(vault, txn, &handoff.id)? {
        return if ack.digest == handoff.digest {
            Ok(AdoptOutcome::AlreadyAdopted(ack))
        } else {
            Err(Abort::Conflict)
        };
    }
    let home = DreamerRunnerStore::new(vault).home_node_designation_in_txn(txn)?;
    if home.map(|home| home.node_id) != node {
        return Err(Abort::Pending(None));
    }
    let head = store::head_in_txn(vault, txn)?;
    if head
        .floor
        .is_some_and(|floor| movement.generation.serial <= floor.serial)
    {
        return Err(Abort::Stale);
    }
    if !lineage_admits(&head, handoff) {
        return Err(Abort::Pending(Some(IncompleteReason::UnknownLineage)));
    }
    let fence = HomeFence::new(*movement);
    for table in tables {
        let section = handoff
            .sections
            .iter()
            .find(|section| section.table_id == table.table_id())
            .ok_or_else(|| refused("a registered table has no section"))?;
        if table.adopt(vault, txn, &fence, &section.rows)? == TableAdopt::Conflict {
            return Err(Abort::Conflict);
        }
    }
    let key = vault.door_signing_key_in_txn(txn, movement.target.machine)?;
    let ack = envelope::sign_ack(handoff, &key);
    store::put_receipt_in_txn(vault, txn, &ack)?;
    let transfer = HandoffTransfer {
        role: HandoffRole::Target,
        status: HandoffStatus::Adopted,
        movement: *movement,
        signed: handoff.signed.clone(),
        digest: handoff.digest,
        parts: 0,
        route: None,
    };
    store::put_transfer_in_txn(vault, txn, &handoff.id, &transfer)?;
    let floor = HeadFloor {
        serial: movement.generation.serial,
        handoff: handoff.id,
        role: HandoffRole::Target,
    };
    let head = HandoffHead {
        floor: Some(floor),
        request: None,
        incomplete: None,
        route: None,
    };
    store::put_head_in_txn(vault, txn, &head)?;
    Ok(AdoptOutcome::Adopted(ack))
}

/// Whether `handoff` carries exactly one section per registered table, at
/// the version this build registers. A section that does not decode as its
/// table's rows at a matching version is refused.
fn sections_match(handoff: &VerifiedHandoff, tables: &[HomeTableRegistration]) -> Result<bool> {
    if handoff.sections.len() != tables.len() {
        return Ok(false);
    }
    for table in tables {
        let Some(section) = handoff
            .sections
            .iter()
            .find(|section| section.table_id == table.table_id())
        else {
            return Ok(false);
        };
        if section.schema_version != table.schema_version() {
            return Ok(false);
        }
        table.check(&section.rows)?;
    }
    Ok(true)
}

/// The source records its target's verified ack: the handoff is Acked and
/// the ack kept. The frozen rows and sealed parts stay as non-executable
/// history, nothing deleted and nothing unfrozen (CALLS: retain after ack);
/// a return move takes a new generation from the node that holds the state.
/// The same ack again changes nothing.
pub(crate) fn ack_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, ack: &VerifiedHomeAck) -> Result<()> {
    let ack = ack.ack();
    let mut transfer = store::transfer_in_txn(vault, txn, &ack.id)?
        .filter(|transfer| transfer.role == HandoffRole::Source)
        .ok_or_else(|| refused("this node froze no handoff with this id"))?;
    if ack.digest != transfer.digest
        || ack.generation != transfer.movement.generation
        || ack.target != transfer.movement.target
    {
        return Err(refused("the ack names another handoff"));
    }
    if transfer.status == HandoffStatus::Acked {
        return Ok(());
    }
    transfer.status = HandoffStatus::Acked;
    store::put_transfer_in_txn(vault, txn, &ack.id, &transfer)?;
    store::put_receipt_in_txn(vault, txn, ack)
}

/// Records `reason` for `handoff`, which landed nothing here, on the head and
/// as its status unless this node already holds one for it.
fn record_unadopted(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    handoff: &VerifiedHandoff,
    reason: IncompleteReason,
) -> Result<()> {
    store::record_incomplete_in_txn(vault, txn, reason)?;
    if store::transfer_in_txn(vault, txn, &handoff.id)?.is_some() {
        return Ok(());
    }
    let transfer = HandoffTransfer {
        role: HandoffRole::Target,
        status: HandoffStatus::Incomplete(reason),
        movement: *handoff.movement(),
        signed: handoff.signed.clone(),
        digest: handoff.digest,
        parts: 0,
        route: None,
    };
    store::put_transfer_in_txn(vault, txn, &handoff.id, &transfer)
}
