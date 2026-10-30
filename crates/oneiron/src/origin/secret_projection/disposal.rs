//! Disposal of masked Git copies (FIX 7608 slice 2b-ii-B2, FIX 9107).
//!
//! A copy is source-bound (CALL P3): once the readable marks naming a blob
//! of its closure moved (FIX 9105: a mark was added, settled or erased on
//! one of its blobs), or the owner erased its canonical store (FIX 10274,
//! by the store's permanent hard-delete marker, whatever its marks say), it
//! is never served again. A recipient copy planned under a release its
//! recipient's grants no longer give is never served again either (FIX
//! 10846). The copies are found by their directories (FIX 10275), so a
//! pass over a vault with none reads nothing. This collector retires such a copy only when
//! nothing still owns it: no checkout binding whose lease still holds its
//! worktree (active, settling, or retained with work kept), and no private
//! ingress a push was received into (a pending push or proposal is never
//! swept; such a copy stays until a later pass settles its proposals).
//! Retiring erases every record about the copy and the graph record
//! itself through the ordinary delete path, then removes the copy's own
//! directory; the canonical store is never touched. No TTL, size or count
//! ends a copy. A failed filesystem removal is retried by the next pass
//! from the same deterministic layout, which also finds every copy
//! directory whose record is already gone (`orphan_dirs`, FIX 10849).

use std::cell::Cell;

use heed::RoTxn;

use super::claims::{RepoProjectionAudience, RepoProjectionClaim, RepoProjectionRecord};
use super::git::{
    RepoGitProjection, RepoGitReleasePlan, closure_marks_stand_in_txn, masked_sibling,
    projection_graph_dir, projection_ingress_dir,
};
use super::recipient::RepoProjectionRevealBinding;
use crate::Vault;
use crate::checkout::lease::{CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, load_act_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};

mod orphan_dirs;

use self::orphan_dirs::{
    collect_orphan_graph_dirs, copy_dirs, repo_projection_store_erased_in_txn,
};

thread_local! {
    /// Set while this thread collects: the deletes it makes run the
    /// post-delete pass again, which then does nothing.
    static COLLECTING: Cell<bool> = const { Cell::new(false) };
}

/// Runs the collector after a masked copy's checkout was collected,
/// logging (never raising) a failure: the next pass retries.
pub(crate) fn collect_after_checkout(vault: &Vault, lease: &CheckoutLeaseAct) {
    if let Err(error) = collect_repo_secret_projections(vault) {
        tracing::warn!(
            kind = ?error.kind(),
            epoch = lease.epoch,
            "masked Git copies were not collected after a checkout; the next pass retries"
        );
    }
}

/// Runs the collector after a committed delete, logging (never raising) a
/// failure: the delete stands, and the next pass retries.
pub(crate) fn collect_after_delete(vault: &Vault) {
    if let Err(error) = collect_repo_secret_projections(vault) {
        tracing::warn!(
            kind = ?error.kind(),
            "masked Git copies were not collected after a delete; the next pass retries"
        );
    }
}

/// Retires every masked copy that no longer stands and nothing owns, and
/// answers how many it retired. Re-entrant calls on the collecting thread
/// do nothing.
///
/// # Errors
/// A store failure reading the copies or marks. One copy's own failure is
/// logged and left for the next pass.
pub(crate) fn collect_repo_secret_projections(vault: &Vault) -> Result<usize> {
    if COLLECTING.with(|collecting| collecting.replace(true)) {
        return Ok(0);
    }
    let collected = collect_unowned(vault)
        .and_then(|retired| collect_orphan_graph_dirs(vault).map(|removed| retired + removed));
    COLLECTING.with(|collecting| collecting.set(false));
    collected
}

fn collect_unowned(vault: &Vault) -> Result<usize> {
    let copies = copy_dirs(vault)?;
    if copies.is_empty() {
        return Ok(0);
    }
    let retiring = {
        let txn = vault.store.env.read_txn()?;
        let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
        let mut retiring = Vec::new();
        for (_, graph, _) in copies {
            let Some(claim) = RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph)? else {
                continue;
            };
            let RepoProjectionRecord::Graph { store_id, .. } = &claim.record else {
                continue;
            };
            let stale = repo_projection_store_erased_in_txn(vault, &txn, store_id)?
                || !closure_marks_stand_in_txn(vault, &txn, &claim, &facts)?;
            if stale && !owned_in_txn(vault, &txn, &graph)? {
                retiring.push((graph, *store_id));
            }
        }
        retiring
    };
    Ok(retire_each(vault, retiring))
}

/// Retires the recipient copies of the masked copy `masked` planned for
/// `binding` under any release but `current`'s (FIX 10846): a grant they
/// were planned under no longer gives the same files, and every exchange
/// plans afresh, so none is served again. `None` retires every one. A copy
/// something still owns stays. Logs, never raises, a failure: the next
/// exchange retries.
pub(crate) fn retire_superseded_recipient_copies(
    vault: &Vault,
    masked: &RepoGitProjection,
    binding: &RepoProjectionRevealBinding,
    current: Option<&RepoGitReleasePlan>,
) {
    if COLLECTING.with(|collecting| collecting.replace(true)) {
        return;
    }
    match superseded_recipient_copies(vault, masked, binding, current) {
        Ok(retiring) => {
            retire_each(vault, retiring);
        }
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "superseded recipient Git copies were not retired; the next exchange retries"
        ),
    }
    COLLECTING.with(|collecting| collecting.set(false));
}

/// The unowned recipient copies [`retire_superseded_recipient_copies`]
/// retires, each with its canonical store.
fn superseded_recipient_copies(
    vault: &Vault,
    masked: &RepoGitProjection,
    binding: &RepoProjectionRevealBinding,
    current: Option<&RepoGitReleasePlan>,
) -> Result<Vec<(EntityId, EntityId)>> {
    let current: Option<Vec<_>> = current.map(|plan| plan.release().into_iter().collect());
    let mut retiring = Vec::new();
    let txn = vault.store.env.read_txn()?;
    for (store_id, graph, _) in copy_dirs(vault)? {
        if Some(store_id) != masked.store_id() {
            continue;
        }
        let Some(claim) = RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph)? else {
            continue;
        };
        let RepoProjectionRecord::Graph {
            audience:
                RepoProjectionAudience::Recipient {
                    binding: planned,
                    released,
                },
            ..
        } = &claim.record
        else {
            continue;
        };
        if planned == binding
            && current.as_ref() != Some(released)
            && masked_sibling(&claim)?.graph == masked.graph_id()
            && !owned_in_txn(vault, &txn, &graph)?
        {
            retiring.push((graph, store_id));
        }
    }
    Ok(retiring)
}

/// Retires each of `retiring`, logging one copy's failure for the next
/// pass, and answers how many it retired.
fn retire_each(vault: &Vault, retiring: Vec<(EntityId, EntityId)>) -> usize {
    let mut retired = 0_usize;
    for (graph, store) in retiring {
        match retire(vault, graph, store) {
            Ok(()) => retired += 1,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a stale masked Git copy was not retired; the next pass retries"
            ),
        }
    }
    retired
}

/// Whether anything still owns `graph`: a private ingress seeded from it,
/// or a checkout binding whose lease still holds its worktree.
fn owned_in_txn(vault: &Vault, txn: &RoTxn<'_>, graph: &EntityId) -> Result<bool> {
    let records = RepoProjectionClaim::records_about_in_txn(vault, txn, graph)?;
    if records
        .iter()
        .any(|(_, kind)| kind == "ingress" || kind == "ingress_store")
    {
        return Ok(true);
    }
    for (checkout, epoch) in RepoProjectionClaim::checkouts_about_in_txn(vault, txn, graph)? {
        let Some(id) = checkout_id(&checkout) else {
            continue;
        };
        let lease = load_act_in_txn(vault, txn, id)
            .map_err(|_| crate::error::Error::CorruptedIndex("a checkout lease does not decode"))?;
        if lease
            .is_some_and(|lease| lease.epoch == epoch && lease.state != CheckoutLeaseState::Settled)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn checkout_id(text: &str) -> Option<CheckoutId> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * at..2 * at + 2)?, 16).ok()?;
    }
    CheckoutId::from_bytes(bytes).ok()
}

/// Erases every record about `graph`, then the graph record, then the
/// copy's own directory (its private ingress's too, should one be left).
fn retire(vault: &Vault, graph: EntityId, store: EntityId) -> Result<()> {
    let records = {
        let txn = vault.store.env.read_txn()?;
        RepoProjectionClaim::records_about_in_txn(vault, &txn, &graph)?
    };
    for (id, _) in records {
        vault.delete_entity_with_reason(&id, crate::DeleteReason::PolicyDelete)?;
    }
    vault.delete_entity_with_reason(&graph, crate::DeleteReason::PolicyDelete)?;
    for dir in [
        projection_graph_dir(vault, store, graph)?,
        projection_ingress_dir(vault, store, graph)?,
    ] {
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
    }
    Ok(())
}
