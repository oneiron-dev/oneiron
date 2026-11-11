//! Canonical search for the existing `vault.search` run row.

use std::collections::{BTreeSet, HashMap};

use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::federation::Scope;
use crate::{AttemptId, EntityId, Result, ScoredEntity, Vault};

/// A served row's worlds and scope as the read that served it proves them;
/// either is `None` when that read cannot prove it.
pub(crate) struct ServedRow {
    pub(crate) worlds: Option<BTreeSet<EntityId>>,
    pub(crate) scope: Option<Scope>,
}

/// Each served row's proof, or `None` where the row itself did not read.
pub(crate) type ServedRows = HashMap<EntityId, Option<ServedRow>>;

/// Canonical keyed search for the existing `vault.search` run row: the hits
/// `reader`'s lane admits, claims of the `claims` statuses.
///
/// `claims` is the host-door policy the caller supplies: `Recorded` where
/// the door permits it, otherwise `Surfaceable` (FIX 5976). A caller filter
/// is met inside the scan, before the rank and the cut (FIX 3977). Session
/// routing stays in `ExecutorStorage`; this owns the canonical branch only.
pub(crate) fn search_as(
    vault: &Vault,
    query: &str,
    limit: usize,
    reader: ScopedReadActorKey,
    claims: ClaimReadStatus,
    filter: Option<&crate::gate::RetrievalFilter>,
) -> Result<Vec<ScoredEntity>> {
    let lane = vault
        .scoped_read(reader)
        .with_claim_status(claims)
        .with_read_filter(filter);
    // A caller filter is met inside the scan, before the rank and
    // the cut (FIX 3977).
    let hits = match filter {
        Some(_) => vault.search_text_scoped_observed(&lane, query, limit, |_, _| {}, None)?,
        None => vault.search_text(query, limit)?,
    };
    Ok(lane.filter_scored_entities(hits)?.value)
}

/// Canonical observed search for the existing `vault.search` run row, for
/// the executor run's ledger (FIX 6130): on a keyed lane the same hits
/// [`search_as`] serves, plus each hit's proof in the read that scored it
/// and in the read that admitted it; with no key the unfiltered observed
/// hits, plus each hit's proof in the read that scored it.
///
/// `claims` is the host-door policy the caller supplies, as in
/// [`search_as`]. `attempt` is the leased attempt the telemetry row names,
/// never read authority. The unkeyed own-entry filter stays in the adapter:
/// with no key this returns `(hits, scored, None)` and the caller keeps the
/// hits its actor reads by its own entry.
pub(crate) fn search_observed(
    vault: &Vault,
    query: &str,
    limit: usize,
    read_as: Option<ScopedReadActorKey>,
    claims: ClaimReadStatus,
    filter: Option<&crate::gate::RetrievalFilter>,
    attempt: Option<AttemptId>,
) -> Result<(Vec<ScoredEntity>, ServedRows, Option<ServedRows>)> {
    let mut scored = ServedRows::new();
    let observe = |txn: &heed::RoTxn<'_>, hits: &[ScoredEntity]| {
        scored = hits
            .iter()
            .map(|hit| (hit.id, served_row_in(vault, txn, hit.id)))
            .collect();
    };
    let lane = read_as.map(|reader| {
        vault
            .scoped_read(reader)
            .with_claim_status(claims)
            .with_read_filter(filter)
    });
    // A caller filter is met inside the scan, before the rank and the
    // cut, so a row it excludes takes no place an admitted row could
    // fill (FIX 3977).
    let hits = match (&lane, filter) {
        (Some(lane), Some(_)) => {
            vault.search_text_scoped_observed(lane, query, limit, observe, attempt)?
        }
        _ => vault.search_text_observed_for_attempt(query, limit, observe, attempt)?,
    };
    let (hits, admitted) = match lane {
        Some(lane) => {
            let mut admitted = ServedRows::new();
            let hits = lane
                .filter_scored_entities_observed(hits, None, |txn, id| {
                    admitted.insert(id, served_row_in(vault, txn, id));
                })?
                .value;
            (hits, Some(admitted))
        }
        None => (hits, None),
    };
    Ok((hits, scored, admitted))
}

/// The worlds and scope of the row `id` as the read `txn` serves it, base
/// reality by its own id; either is `None` where that read cannot prove it
/// (FIX 6130, FIX 7162). A NOTE in several worlds outside base notes every
/// one (FIX-LIST 9433).
fn served_row_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Option<ServedRow> {
    use crate::ports::EntityStore;
    let row = vault.port_entity_get(txn, &id).ok()??;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id).ok()??;
    let worlds = crate::federation::record_scope::note_world::served_worlds_in(
        &vault.store,
        txn,
        id,
        row.entity_type,
        &row.body,
    )
    .ok()
    .flatten();
    let scope = crate::federation::record_scope::scope_for_blob(&vault.store, txn, id, &raw)
        .ok()
        .flatten();
    Some(ServedRow { worlds, scope })
}
