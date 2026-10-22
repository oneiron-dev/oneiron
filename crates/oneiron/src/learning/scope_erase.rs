//! A project's learning scope goes with the project (FIX 6038). Erasing a
//! project removes every cell keyed in its scope, with the rows keyed by
//! the cell's digest: its subject index, evidence and stored prior. Each
//! learning head scoped to it is retracted and re-keyed to one fresh opaque
//! scope, and a surviving prior or head whose borrowed provenance names the
//! erased scope loses that provenance, keeping its measurement. No stored
//! key or body still derives from the erased id. Vault cells and every
//! other project's stay as they are.

use std::collections::BTreeSet;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;

use super::LEARNING_PREDICATES;
use super::cell::LearningPredicate;
use super::evidence::{CELL, EVIDENCE};
use super::prior::PRIOR;
use super::project::{StoredEstimateClaim, entity_header};

/// The subject index by its raw key (subject id16 + cell digest), so a
/// registration that no longer decodes still takes its index rows.
const CELL_BY_SUBJECT_RAW: SideTable<Vec<u8>, LearningPredicate, Named> =
    SideTable::new(&side_table::LEARNING_CELL_SUBJECT);

/// Learning heads read per page of the predicate index: a pace, not a cap.
const HEAD_PAGE: usize = 256;

/// Removes erased `entity`'s learning scope. A cell registration that no
/// longer decodes goes with every row keyed by its digest. An entity no
/// cell, head or prior names changes nothing.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_learning_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let rows = CELL
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut doomed = BTreeSet::new();
    for (key, value) in rows {
        let Ok(digest) = <[u8; 32]>::try_from(key.as_slice()) else {
            continue;
        };
        match CELL.decode_value(&value) {
            Ok(row) if row.cell.project != Some(*entity) => {}
            Ok(_) => {
                doomed.insert(digest);
            }
            Err(error) => {
                tracing::warn!(%error, "a learning cell that no longer decodes goes with its rows");
                doomed.insert(digest);
            }
        }
    }
    for digest in &doomed {
        EVIDENCE.delete_from(&vault.store, wtxn, digest)?;
        PRIOR.delete(&vault.store, wtxn, digest)?;
        CELL.delete(&vault.store, wtxn, digest)?;
    }
    if !doomed.is_empty() {
        let index = CELL_BY_SUBJECT_RAW
            .iter_raw_from(&vault.store, wtxn, &[])?
            .collect::<Result<Vec<_>>>()?;
        for (key, _) in index {
            let digest = key
                .len()
                .checked_sub(32)
                .and_then(|at| <[u8; 32]>::try_from(&key[at..]).ok());
            if digest.is_some_and(|digest| doomed.contains(&digest)) {
                CELL_BY_SUBJECT_RAW.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    let named = entity.to_hex();
    clear_prior_provenance_in_txn(vault, wtxn, &named)?;
    rescope_heads_in_txn(vault, wtxn, *entity, &named)
}

/// Clears the provenance of every stored prior that names the erased scope;
/// its value and weight stay. A prior that no longer decodes is deleted.
fn clear_prior_provenance_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    named: &str,
) -> Result<()> {
    let rows = PRIOR
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        let Ok(digest) = <[u8; 32]>::try_from(key.as_slice()) else {
            continue;
        };
        if !contains(&value, named.as_bytes()) {
            continue;
        }
        match PRIOR.decode_value(&value) {
            Ok(mut prior) => {
                if prior
                    .from
                    .as_deref()
                    .is_some_and(|from| from.contains(named))
                {
                    prior.from = None;
                    PRIOR.put(&vault.store, wtxn, &digest, &prior)?;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "a learning prior that no longer decodes is deleted");
                PRIOR.delete(&vault.store, wtxn, &digest)?;
            }
        }
    }
    Ok(())
}

/// Walks every learning head, found by predicate, not by registration. A
/// head scoped to `entity` is re-keyed to one fresh opaque scope, and
/// retracted at the erase's time while active; a head whose borrowed
/// provenance names it loses that provenance.
fn rescope_heads_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: EntityId,
    named: &str,
) -> Result<()> {
    let mut erased: Option<(EntityId, u64)> = None;
    for predicate in LEARNING_PREDICATES {
        let mut after = None;
        loop {
            let page = crate::claim::claim_ids_for_predicate_page_in_txn(
                &vault.store,
                wtxn,
                predicate,
                after,
                HEAD_PAGE,
            )?;
            let Some(last) = page.last().copied() else {
                break;
            };
            after = Some(last);
            for id in page {
                let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
                    continue;
                };
                if body.source != Some(ClaimSource::Observed)
                    || body.approval != ClaimApprovalStatus::Auto
                {
                    continue;
                }
                let Ok(mut stored) = StoredEstimateClaim::from_value(&body.value) else {
                    continue;
                };
                let scoped = stored.cell.project == Some(entity);
                let cited = stored
                    .estimate
                    .prior
                    .from
                    .as_deref()
                    .is_some_and(|from| from.contains(named));
                if !scoped && !cited {
                    continue;
                }
                if cited {
                    stored.estimate.prior.from = None;
                }
                let header = entity_header(vault, wtxn, &id)?;
                let mut range = TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                };
                if scoped {
                    let (scope, now) = match erased {
                        Some(minted) => minted,
                        None => {
                            let minted = (
                                vault.store.clock.entity_id()?,
                                crate::ports::recorded_at_in_txn(&vault.store, wtxn)?,
                            );
                            erased = Some(minted);
                            minted
                        }
                    };
                    stored.cell.project = Some(scope);
                    if body.lifecycle == ClaimLifecycleStatus::Active {
                        // A withdrawal stamped before the row it closes would
                        // make the re-put range invalid.
                        let at = now.max(header.occurred_start);
                        body.lifecycle = ClaimLifecycleStatus::Retracted;
                        body.valid_to = Some(at);
                        range.end = at;
                    }
                }
                body.value = stored.to_value()?;
                vault.put_reserved_claim_in_txn(wtxn, &id, &body, range, header.learned_at)?;
            }
        }
    }
    Ok(())
}

/// Whether `bytes` holds `needle` anywhere: a cheap test before a decode.
pub(super) fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}
