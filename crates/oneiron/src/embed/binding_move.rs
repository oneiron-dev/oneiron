//! An owner-approved embedder binding, staged through a space move (OF-577, FIX 857 O3b PR B;
//! ARCH-0053 R13: a trained model never deploys by itself, and an embedder switch searches the
//! old index meanwhile).
//!
//! An approved stock switch of the embedder seat, or the owner's separate swap choice for a
//! trained embedder, binds the manifest's retrieval embedder only once the vault searches that
//! model's space. The approval stages one row here, keyed by its source (the offer, or the
//! training run), in the approval's own write: the binding it applies, the binding it expects
//! to replace, and the space move that re-embeds for it. The old manifest binding and kind slots
//! serve while the candidate fills. A binding waits until a declared space pins its model
//! (`model@revision@where`, `model@revision` being the binding's own model id) and the slots it
//! moves are free; each media pass begins its move then ([`Vault::begin_waiting_embedder_moves`]).
//!
//! The owner approved the binding, so its move concludes as the owner's yes once the candidate
//! is full and checked: the check's reading is kept beside it, never a reason to keep the old
//! binding. At that swap, in the move's own write, the manifest takes the binding while it still
//! holds the one expected, and the source's receipt records it: a stock switch's receipt reads
//! applied, and a trained swap writes its role receipt and `Bound` only then. A move that expires
//! unfilled returns its binding to waiting with its candidate, which the next pass declares again
//! and moves to afresh; a move the owner abandons returns it to waiting for a declared space. The
//! owner's undo of the switch cancels a pending binding with its move, or takes an applied one
//! back with the slots its move swapped in; the owner's undo of the move takes the binding back
//! with it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::space::{
    EmbeddingSpace, declare_embedding_space_in_txn, embedding_space_in_txn,
    embedding_spaces_in_txn, kind_slot_bindings_in_txn,
};
use super::space_move::{NotWorse, SpaceMove, SpaceMoveState, SpaceRef, space_move_in_txn};
use crate::deletion::names_no_actor;
use crate::llm::manifest::{ModelBinding, ModelRole, read_manifest};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::SwitchOwner;
use crate::training_pack::RoleSwapReceipt;
use crate::{EntityId, Error, Result, Vault};

/// Staged embedder bindings, pending and settled. Key: source id16 (the offer, or the run).
const BINDING_MOVE: SideTable<EntityId, PendingEmbedderBinding, Named> =
    SideTable::new(&side_table::EMBEDDING_BINDING_MOVE);

/// The one role a binding move binds: retrieval reads the declared spaces' kind slots.
const ROLE: ModelRole = ModelRole::RetrievalEmbedder;

/// What chose a staged embedder binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingSource {
    /// An approved stock switch: its offer, and the owner who approved it.
    Offer { offer: EntityId, owner: SwitchOwner },
    /// The owner's separate swap choice for a trained embedder: the receipt its swap writes.
    Training { receipt: Box<RoleSwapReceipt> },
}

impl BindingSource {
    /// The id its row is keyed by: the offer, or the training run.
    #[must_use]
    pub fn id(&self) -> EntityId {
        match self {
            Self::Offer { offer, .. } => *offer,
            Self::Training { receipt } => receipt.run,
        }
    }
}

/// The space move that re-embeds for a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingMoveLink {
    pub candidate: String,
    pub incumbent: SpaceRef,
    /// The move's `started_at`: which move to that candidate it is.
    pub started_at: u64,
}

/// Where a staged binding stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BindingMoveState {
    /// No declared space pins its model yet, or the slots it moves move elsewhere; the old
    /// binding serves.
    Waiting,
    /// Its move's candidate fills while the old binding and slots serve.
    Filling,
    /// The manifest binds it. `verdict` is its move's last check reading, kept beside the
    /// owner's yes; `None` when no check ran.
    Applied { at: u64, verdict: Option<NotWorse> },
    /// It never applied.
    NotApplied { at: u64, why: BindingNotApplied },
    /// The owner undid it after it applied: the binding it replaced serves again.
    Undone { at: u64, owner: SwitchOwner },
}

/// Why a staged binding never applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingNotApplied {
    /// The owner undid the switch before it applied.
    Cancelled,
    /// The binding it expects to replace, or its trained run, changed since it was staged.
    Stale,
    /// The manifest's own checks refused it at the swap: its validation, or the teacher's
    /// probe approval.
    Refused { reason: String },
}

/// One owner-approved retrieval embedder binding, staged until its space move swaps in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEmbedderBinding {
    pub source: BindingSource,
    /// The binding it expects to replace; it applies only over this one.
    pub previous: Option<ModelBinding>,
    pub binding: ModelBinding,
    /// Vault seconds.
    pub staged_at: u64,
    /// Its current move; `None` while none runs.
    pub link: Option<BindingMoveLink>,
    /// The candidate an expired move dropped, declared again as the next move begins.
    pub refill: Option<EmbeddingSpace>,
    pub state: BindingMoveState,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

/// Whether space id `space` (`model@revision@where`) pins `model` (`provider/name@revision`).
fn pins(space: &str, model: &str) -> bool {
    space.rsplit_once('@').is_some_and(|(pin, _)| pin == model)
}

/// Stages `binding` for the retrieval embedder in the approval's write, over `previous`, the
/// binding the manifest holds now. Its move begins here when a declared space pins its model
/// and the slots are free, and a binding the text slot already reads applies at once.
///
/// # Errors
///
/// A binding the manifest would not validate with, as an immediate bind refused it, or storage
/// errors.
pub(crate) fn stage_embedder_binding_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    source: BindingSource,
    previous: Option<ModelBinding>,
    binding: ModelBinding,
) -> Result<PendingEmbedderBinding> {
    if let Some(mut manifest) = read_manifest(&vault.store, wtxn)? {
        manifest.roles.insert(ROLE, binding.clone());
        manifest.validate()?;
    }
    let mut pending = PendingEmbedderBinding {
        source,
        previous,
        binding,
        staged_at: vault.store.clock.now_recorded_at(),
        link: None,
        refill: None,
        state: BindingMoveState::Waiting,
    };
    attach_in_txn(vault, wtxn, &mut pending)?;
    BINDING_MOVE.put(&vault.store, wtxn, &pending.source.id(), &pending)?;
    Ok(pending)
}

/// The binding `source` staged, while it waits or fills: a repeated swap choice returns it
/// rather than staging it twice.
pub(crate) fn live_binding_move_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<Option<PendingEmbedderBinding>> {
    Ok(BINDING_MOVE
        .get(&vault.store, txn, source)?
        .filter(|pending| {
            matches!(
                pending.state,
                BindingMoveState::Waiting | BindingMoveState::Filling
            )
        }))
}

/// Begins the move `pending` needs: to the first declared space, in id order, that pins its
/// model and can take every kind the text slot's incumbent serves, after declaring again the
/// candidate an expired move dropped. A binding whose text slot already reads a space of its
/// model applies at once. With neither it keeps waiting. A space that refuses the move writes
/// nothing. Returns whether it declared a space, whose setup rows the caller publishes.
fn attach_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    pending: &mut PendingEmbedderBinding,
) -> Result<bool> {
    let mut declared = false;
    if let Some(space) = pending.refill.take()
        && embedding_space_in_txn(&vault.store, wtxn, &space.id)?.is_none()
    {
        match declare_embedding_space_in_txn(&vault.store, wtxn, &space) {
            Ok(()) => declared = true,
            // It no longer validates; the binding waits for a declared space.
            Err(Error::InvalidConfig(_)) => {}
            Err(error) => return Err(error),
        }
    }
    let model = pending.binding.model.as_str().to_owned();
    let incumbent = kind_slot_bindings_in_txn(&vault.store, wtxn)?
        .text
        .map_or(SpaceRef::TextIndex, SpaceRef::Declared);
    let serving = match &incumbent {
        SpaceRef::Declared(id) => id.clone(),
        SpaceRef::TextIndex => vault.text_index_space().id,
    };
    if pins(&serving, &model) {
        pending.link = None;
        pending.state = apply_in_txn(vault, wtxn, pending, None)?;
        return Ok(declared);
    }
    for space in embedding_spaces_in_txn(&vault.store, wtxn)? {
        if !pins(&space.id, &model) {
            continue;
        }
        match vault.begin_space_move_in_txn(wtxn, &space.id, incumbent.clone(), None) {
            Ok(row) => {
                pending.link = Some(BindingMoveLink {
                    candidate: row.candidate,
                    incumbent: row.incumbent,
                    started_at: row.started_at,
                });
                pending.state = BindingMoveState::Filling;
                return Ok(declared);
            }
            // A slot moving elsewhere, or a space that cannot take a kind: the next one.
            Err(Error::InvalidConfig(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(declared)
}

/// Applies `pending` in the write that swaps its move in: the manifest takes the binding while
/// it still holds the one expected and a trained swap's run is still there, then a trained
/// swap writes its role receipt and `Bound`. Returns the state it reaches.
fn apply_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    pending: &PendingEmbedderBinding,
    verdict: Option<NotWorse>,
) -> Result<BindingMoveState> {
    let at = vault.store.clock.now_recorded_at();
    let stale = BindingMoveState::NotApplied {
        at,
        why: BindingNotApplied::Stale,
    };
    let Some(mut manifest) = read_manifest(&vault.store, wtxn)? else {
        return Ok(stale);
    };
    if manifest.roles.get(&ROLE) != pending.previous.as_ref() {
        return Ok(stale);
    }
    if let BindingSource::Training { receipt } = &pending.source
        && crate::training_pack::training_run_in(vault, wtxn, &receipt.run)?.is_none()
    {
        return Ok(stale);
    }
    manifest.roles.insert(ROLE, pending.binding.clone());
    match vault.write_model_manifest_in_txn(wtxn, &manifest, None, None) {
        Ok(()) => {}
        // The manifest's own checks refuse before it writes anything.
        Err(Error::InvalidConfig(reason)) => {
            return Ok(BindingMoveState::NotApplied {
                at,
                why: BindingNotApplied::Refused { reason },
            });
        }
        Err(error) => return Err(error),
    }
    if let BindingSource::Training { receipt } = &pending.source {
        let mut receipt = (**receipt).clone();
        receipt.at = at;
        crate::training_pack::bind_staged_role_swap_in_txn(vault, wtxn, &receipt)?;
    }
    Ok(BindingMoveState::Applied { at, verdict })
}

/// Records `pending`'s state on its source's receipt in the same write: a stock switch's
/// receipt reads it. A trained swap's receipts were written as it applied.
fn settle_source_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    pending: &PendingEmbedderBinding,
) -> Result<()> {
    if let BindingSource::Offer { offer, .. } = &pending.source {
        crate::skill_optimize::settle_staged_switch_in_txn(vault, wtxn, offer, &pending.state)?;
    }
    Ok(())
}

/// The binding linked to `moving`: the same candidate, start and incumbent.
fn linked_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    moving: &SpaceMove,
) -> Result<Option<PendingEmbedderBinding>> {
    Ok(BINDING_MOVE
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, pending)| pending)
        .find(|pending| {
            pending.link.as_ref().is_some_and(|link| {
                link.candidate == moving.candidate
                    && link.started_at == moving.started_at
                    && link.incumbent == moving.incumbent
            })
        }))
}

/// Whether an owner-approved binding fills on `moving`: its conclusion is then the owner's yes.
pub(crate) fn approves_move_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    moving: &SpaceMove,
) -> Result<bool> {
    Ok(linked_in_txn(vault, txn, moving)?
        .is_some_and(|pending| pending.state == BindingMoveState::Filling))
}

/// The join of a move's end, in its write: a swap applies the binding that fills on it, and an
/// expiry or the owner's abandon returns it to waiting, for the next pass to begin again. An
/// expiry joins before its candidate's rows go, so the binding keeps that candidate to declare
/// again.
pub(crate) fn move_ended_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    moving: &SpaceMove,
) -> Result<()> {
    let Some(mut pending) = linked_in_txn(vault, wtxn, moving)?
        .filter(|pending| pending.state == BindingMoveState::Filling)
    else {
        return Ok(());
    };
    let state = match moving.state {
        SpaceMoveState::SwappedIn { .. } => {
            let verdict = moving.last_check.as_ref().map(|check| check.verdict);
            apply_in_txn(vault, wtxn, &pending, verdict)?
        }
        SpaceMoveState::Kept { .. } => {
            pending.link = None;
            pending.refill = embedding_space_in_txn(&vault.store, wtxn, &moving.candidate)?;
            BindingMoveState::Waiting
        }
        SpaceMoveState::Open => {
            pending.link = None;
            BindingMoveState::Waiting
        }
        SpaceMoveState::Undone { .. } => return Ok(()),
    };
    pending.state = state;
    BINDING_MOVE.put(&vault.store, wtxn, &pending.source.id(), &pending)?;
    settle_source_in_txn(vault, wtxn, &pending)
}

/// The join of the owner's undo of a swapped-in move, in its write: the binding the move
/// applied goes back with its slots while the manifest still holds it, and a stock switch's
/// receipt records the undo.
pub(crate) fn move_undone_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    moving: &SpaceMove,
    actor: EntityId,
) -> Result<()> {
    let Some(mut pending) = linked_in_txn(vault, wtxn, moving)?
        .filter(|pending| matches!(pending.state, BindingMoveState::Applied { .. }))
    else {
        return Ok(());
    };
    let at = vault.store.clock.now_recorded_at();
    restore_in_txn(vault, wtxn, &pending)?;
    pending.state = BindingMoveState::Undone {
        at,
        owner: SwitchOwner::Actor(actor),
    };
    BINDING_MOVE.put(&vault.store, wtxn, &pending.source.id(), &pending)?;
    if let BindingSource::Offer { offer, .. } = &pending.source {
        crate::skill_optimize::undo_staged_switch_in_txn(vault, wtxn, offer, actor, at)?;
    }
    Ok(())
}

/// Puts back the binding `pending` replaced, while the manifest still holds `pending`'s own;
/// whether it did.
fn restore_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    pending: &PendingEmbedderBinding,
) -> Result<bool> {
    let Some(mut manifest) = read_manifest(&vault.store, wtxn)? else {
        return Ok(false);
    };
    if manifest.roles.get(&ROLE) != Some(&pending.binding) {
        return Ok(false);
    }
    match &pending.previous {
        Some(previous) => manifest.roles.insert(ROLE, previous.clone()),
        None => manifest.roles.remove(&ROLE),
    };
    vault.write_model_manifest_in_txn(wtxn, &manifest, None, None)?;
    Ok(true)
}

/// The owner's undo of the switch that staged `source`'s binding, in the undo's write: a
/// pending binding is cancelled with its open move, and an applied one takes back the binding
/// it replaced, with the slots its move swapped in while they still read its candidate.
/// Returns the state it reaches and the setup rows the move's write published, for the caller
/// to hand on once it commits.
///
/// # Errors
///
/// No binding staged, one that never applied or is undone already, an applied one the
/// manifest no longer holds (the undo would overwrite a newer binding), or storage errors.
pub(crate) fn undo_staged_binding_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    source: &EntityId,
    actor: EntityId,
) -> Result<(BindingMoveState, BTreeSet<EntityId>)> {
    let mut pending = BINDING_MOVE
        .get(&vault.store, wtxn, source)?
        .ok_or_else(|| invalid("the switch staged no embedder binding"))?;
    let applied = match pending.state {
        BindingMoveState::Waiting | BindingMoveState::Filling => false,
        BindingMoveState::Applied { .. } => true,
        BindingMoveState::NotApplied { .. } => {
            return Err(invalid("the switch never applied; nothing to undo"));
        }
        BindingMoveState::Undone { .. } => return Err(invalid("the switch is already undone")),
    };
    if applied && !restore_in_txn(vault, wtxn, &pending)? {
        return Err(invalid(
            "the seat's binding changed since the switch; undo would overwrite it",
        ));
    }
    let at = vault.store.clock.now_recorded_at();
    pending.state = if applied {
        BindingMoveState::Undone {
            at,
            owner: SwitchOwner::Actor(actor),
        }
    } else {
        BindingMoveState::NotApplied {
            at,
            why: BindingNotApplied::Cancelled,
        }
    };
    BINDING_MOVE.put(&vault.store, wtxn, source, &pending)?;
    let setup = match &pending.link {
        Some(link) => move_back_in_txn(vault, wtxn, link, applied)?,
        None => BTreeSet::new(),
    };
    Ok((pending.state, setup))
}

/// Ends the move `link` names for an undone switch: abandons it while open, or undoes its swap
/// while its slots still read the candidate. A move another write ended or rebound stays.
fn move_back_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    link: &BindingMoveLink,
    applied: bool,
) -> Result<BTreeSet<EntityId>> {
    let Some(moving) = space_move_in_txn(&vault.store, wtxn, &link.candidate)?
        .filter(|moving| moving.started_at == link.started_at)
    else {
        return Ok(BTreeSet::new());
    };
    let ended = match (applied, moving.state) {
        (false, SpaceMoveState::Open) => vault.abandon_space_move_in_txn(wtxn, &link.candidate),
        (true, SpaceMoveState::SwappedIn { .. }) => vault
            .undo_space_move_in_txn(wtxn, &link.candidate)
            .map(|(_, setup)| setup),
        _ => return Ok(BTreeSet::new()),
    };
    match ended {
        Ok(setup) => Ok(setup),
        // Its slots rebound since, or its incumbent retired; each refuses before it writes.
        Err(Error::InvalidConfig(_)) => Ok(BTreeSet::new()),
        Err(error) => Err(error),
    }
}

/// Whether `pending` has work for the media pass: a waiting binding whose expected binding
/// moved, with a candidate to declare again, or that a declared space now pins; a filling one
/// whose move is gone or another.
fn due_in(vault: &Vault, txn: &RoTxn<'_>, pending: &PendingEmbedderBinding) -> Result<bool> {
    match pending.state {
        BindingMoveState::Waiting => Ok(pending.refill.is_some()
            || expected_moved_in(vault, txn, pending)?
            || embedding_spaces_in_txn(&vault.store, txn)?
                .iter()
                .any(|space| pins(&space.id, pending.binding.model.as_str()))),
        BindingMoveState::Filling => Ok(!filling_in(vault, txn, pending)?),
        _ => Ok(false),
    }
}

/// Whether the manifest's retrieval binding is no longer the one `pending` expects to replace.
fn expected_moved_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    pending: &PendingEmbedderBinding,
) -> Result<bool> {
    let current =
        read_manifest(&vault.store, txn)?.and_then(|manifest| manifest.roles.get(&ROLE).cloned());
    Ok(current != pending.previous)
}

/// Whether `pending`'s move is still the open one it began.
fn filling_in(vault: &Vault, txn: &RoTxn<'_>, pending: &PendingEmbedderBinding) -> Result<bool> {
    let Some(link) = &pending.link else {
        return Ok(false);
    };
    Ok(
        space_move_in_txn(&vault.store, txn, &link.candidate)?.is_some_and(|moving| {
            moving.state == SpaceMoveState::Open
                && moving.started_at == link.started_at
                && moving.incumbent == link.incumbent
        }),
    )
}

/// Erasing `actor` from the staged bindings (FIX 3520): each one it approved or undid keeps its
/// bindings, move and state and names no one, as its switch or swap receipt does. One-way, in
/// the erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_binding_move_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut rows = Vec::new();
    for (source, mut pending) in BINDING_MOVE.scan(&vault.store, wtxn)? {
        let approved = match &mut pending.source {
            BindingSource::Offer { owner, .. } => owner.forget(*actor),
            BindingSource::Training { receipt } => receipt.owner.forget(*actor),
        };
        let undid = match &mut pending.state {
            BindingMoveState::Undone { owner, .. } => owner.forget(*actor),
            _ => false,
        };
        if approved || undid {
            rows.push((source, pending));
        }
    }
    for (source, pending) in rows {
        BINDING_MOVE.put(&vault.store, wtxn, &source, &pending)?;
    }
    Ok(())
}

impl Vault {
    /// Every staged embedder binding, pending and settled, in source id order.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn embedder_binding_moves(&self) -> Result<Vec<PendingEmbedderBinding>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(BINDING_MOVE
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(_, pending)| pending)
            .collect())
    }

    /// The embedder binding `source`, a stock switch's offer or a training run, staged, if any.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn embedder_binding_move(
        &self,
        source: &EntityId,
    ) -> Result<Option<PendingEmbedderBinding>> {
        let rtxn = self.store.env.read_txn()?;
        BINDING_MOVE.get(&self.store, &rtxn, source)
    }

    /// Begins the move each waiting embedder binding needs, as the engine: the owner approved
    /// the binding, so its fill asks nothing more, and a candidate an expired move dropped is
    /// declared again first, as a system move's. A waiting binding whose expected binding
    /// moved since closes stale. A filling one whose move is gone or another (a restore brought
    /// the moves back to an older image) waits again, so no historical move applies it. Returns
    /// the candidates whose moves began. Blocking.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn begin_waiting_embedder_moves(&self) -> Result<Vec<String>> {
        {
            let rtxn = self.store.env.read_txn()?;
            let mut due = false;
            for (_, pending) in BINDING_MOVE.scan(&self.store, &rtxn)? {
                if due_in(self, &rtxn, &pending)? {
                    due = true;
                    break;
                }
            }
            if !due {
                return Ok(Vec::new());
            }
        }
        let mut wtxn = self.store.env.write_txn()?;
        let mut begun = Vec::new();
        let mut declared = false;
        for (source, mut pending) in BINDING_MOVE.scan(&self.store, &wtxn)? {
            if !due_in(self, &wtxn, &pending)? {
                continue;
            }
            let before = pending.clone();
            if pending.state == BindingMoveState::Filling {
                pending.link = None;
                pending.state = BindingMoveState::Waiting;
            } else if expected_moved_in(self, &wtxn, &pending)? {
                pending.refill = None;
                pending.state = BindingMoveState::NotApplied {
                    at: self.store.clock.now_recorded_at(),
                    why: BindingNotApplied::Stale,
                };
            } else {
                declared |= attach_in_txn(self, &mut wtxn, &mut pending)?;
                if let Some(link) = &pending.link {
                    begun.push(link.candidate.clone());
                }
            }
            if pending != before {
                BINDING_MOVE.put(&self.store, &mut wtxn, &source, &pending)?;
                settle_source_in_txn(self, &mut wtxn, &pending)?;
            }
        }
        let setup = if declared {
            self.publish_embedding_setup_in_txn(&mut wtxn)?
        } else {
            BTreeSet::new()
        };
        wtxn.commit()?;
        self.embedding_setup_committed(setup);
        Ok(begun)
    }
}
