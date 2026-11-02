//! Disposal of masked Git copies (FIX 7608 slice 2b-ii-B2, FIX 9107).
//!
//! A copy is source-bound (CALL P3): once the readable marks it was made
//! under moved (a mark was added, settled or erased), or the owner erased
//! its canonical store (FIX 10274, by the store's permanent hard-delete
//! marker, whatever its marks say), it is never served again. This collector retires such a copy only when
//! nothing still owns it: no checkout binding whose lease still holds its
//! worktree (active, settling, or retained with work kept), and no private
//! ingress a push was received into (a pending push or proposal is never
//! swept; such a copy stays until a later pass settles its proposals).
//! Retiring erases every record about the copy and the graph record
//! itself through the ordinary delete path, then removes the copy's own
//! directory; the canonical store is never touched. No TTL, size or count
//! ends a copy. A failed filesystem removal is retried by the next pass
//! from the same deterministic layout, which also finds an erased store's
//! copies whose records its erase already took (`erased_store`).

use std::cell::Cell;

use heed::RoTxn;

use super::claims::{RepoProjectionClaim, RepoProjectionRecord};
use super::git::{projection_graph_dir, projection_ingress_dir};
use crate::Vault;
use crate::checkout::lease::{CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, load_act_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};

mod erased_store;

use self::erased_store::{collect_erased_store_graphs, repo_projection_store_erased_in_txn};

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
        .and_then(|retired| collect_erased_store_graphs(vault).map(|removed| retired + removed));
    COLLECTING.with(|collecting| collecting.set(false));
    collected
}

fn collect_unowned(vault: &Vault) -> Result<usize> {
    let retiring = {
        let txn = vault.store.env.read_txn()?;
        let readable =
            RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?.ids()?;
        let mut retiring = Vec::new();
        RepoProjectionClaim::for_each_graph_in_txn(vault, &txn, |graph| {
            let RepoProjectionRecord::Graph {
                store_id, marks, ..
            } = &graph.record
            else {
                return Ok(());
            };
            let stale =
                *marks != readable || repo_projection_store_erased_in_txn(vault, &txn, store_id)?;
            if stale && !owned_in_txn(vault, &txn, &graph.graph)? {
                retiring.push((graph.graph, *store_id));
            }
            Ok(())
        })?;
        retiring
    };
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
    Ok(retired)
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
