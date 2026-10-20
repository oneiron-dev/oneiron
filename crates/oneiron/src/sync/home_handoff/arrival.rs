//! FIX 5661 C2b (FIX 6211): the new home's ordering. Before the host's
//! deadline read arms any free-time cadence, and before a wake pass opens a
//! cycle or admits a free-time item, the elected home adopts the handoff
//! staged here in full, through C1's [`super::adopt`] with the commit door's
//! checks. A new home with no usable handoff for its move records why
//! (Incomplete), so what it opens locally never travels as the lineage's
//! state (FIX 6457), and goes on with today's opening: nothing waits or
//! refuses for it.

use super::store::{self, HandoffHead, MoveRequest, StagedHandoff};
use super::{AdoptOutcome, IncompleteReason, adopt, drop_staged, home_tables, open_handoff};
use crate::Vault;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::Result;

/// Readies this node as the vault's MACRO home, when its own election names
/// it home: a handoff staged here in full adopts now; with none that adopts,
/// a move that came to this node records `NotArrived`. Anywhere else, and
/// once either is done, it reads and writes nothing.
///
/// # Errors
///
/// Storage errors reading the head or recording the outcome.
pub(crate) fn prepare_arrival(vault: &Vault) -> Result<()> {
    let Some((node, ready)) = home_here(vault)? else {
        return Ok(());
    };
    if let Some(staged) = ready {
        if adopt_staged(vault, &staged) {
            return Ok(());
        }
        // It stays for the commit door; the passes read it no more.
        unready(vault, &staged)?;
    }
    vault.with_write_txn(|txn| {
        let head = store::head_in_txn(vault, txn)?;
        if !arriving(&head, node) {
            return Ok(());
        }
        store::record_incomplete_in_txn(vault, txn, IncompleteReason::NotArrived)
    })
}

/// This node's sync node id and the handoff staged here in full, while its
/// own election names it home and either one is staged or a move came here
/// that no handoff answered yet; `None` otherwise.
fn home_here(vault: &Vault) -> Result<Option<(u64, Option<StagedHandoff>)>> {
    let txn = vault.store.env.read_txn()?;
    let Some(node) = crate::identity::read_client_id_in_txn(vault, &txn)? else {
        return Ok(None);
    };
    let home = DreamerRunnerStore::new(vault).home_node_designation_in_txn(&txn)?;
    if home.map(|home| home.node_id) != Some(node) {
        return Ok(None);
    }
    let head = store::head_in_txn(vault, &txn)?;
    let ready = match head.staged {
        Some(staged)
            if staged.count > 0
                && store::staged_position_in_txn(vault, &txn, &staged.id)? == staged.count =>
        {
            Some(staged)
        }
        _ => None,
    };
    if ready.is_none() && !arriving(&head, node) {
        return Ok(None);
    }
    Ok(Some((node, ready)))
}

/// Whether the last move this node's election recorded came to this node
/// from another node, while this node has taken part in no move and has
/// recorded no outcome for this one. A pristine node's first election (from
/// no home) and a move leaving this node are neither; a node holding the
/// state it adopted, or one that froze its state, records nothing here.
fn arriving(head: &HandoffHead, node: u64) -> bool {
    head.floor.is_none()
        && head.incomplete.is_none()
        && matches!(
            head.request,
            Some(MoveRequest {
                from: Some(from),
                to: Some(to),
            }) if to == node && from != node
        )
}

/// Adopts `staged` with the commit door's checks; whether it landed. Any
/// failure is logged and leaves the handoff to the commit door.
fn adopt_staged(vault: &Vault, staged: &StagedHandoff) -> bool {
    match try_adopt(vault, staged) {
        Ok(landed) => landed,
        Err(error) => {
            tracing::debug!(
                kind = ?error.kind(),
                "a staged home handoff did not adopt before the pass"
            );
            false
        }
    }
}

/// The commit door's checks, without a socket: the staged machine is still
/// one of the owner's here, the joined parts are the bytes the digest names,
/// and the handoff opens here as that machine's. Then every registered table
/// adopts in one transaction (C1's [`adopt`]).
fn try_adopt(vault: &Vault, staged: &StagedHandoff) -> Result<bool> {
    let sealed = {
        let txn = vault.store.env.read_txn()?;
        let fold = vault.authority_fold_readonly_in_txn(&txn)?;
        if fold.trusted_machine(staged.source).is_none() {
            return Ok(false);
        }
        store::sealed_in_txn(vault, &txn, &staged.id, staged.count)?
    };
    if *blake3::hash(&sealed).as_bytes() != staged.digest {
        return Ok(false);
    }
    let verified = open_handoff(vault, staged.id, &sealed)?;
    if verified.movement().source.machine != staged.source {
        return Ok(false);
    }
    match adopt(vault, verified, &home_tables())? {
        AdoptOutcome::Adopted(_) | AdoptOutcome::AlreadyAdopted(_) => {}
        AdoptOutcome::Pending | AdoptOutcome::Stale | AdoptOutcome::Conflict => return Ok(false),
    }
    // The receipt stands for the staged parts now.
    if let Err(error) = drop_staged(vault, &staged.id) {
        tracing::debug!(kind = ?error.kind(), "an adopted home handoff kept its staged parts");
    }
    Ok(true)
}

/// Drops the head's note of `staged` while it still names it.
fn unready(vault: &Vault, staged: &StagedHandoff) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut head = store::head_in_txn(vault, txn)?;
        if head.staged != Some(*staged) {
            return Ok(());
        }
        head.staged = None;
        store::put_head_in_txn(vault, txn, &head)
    })
}
