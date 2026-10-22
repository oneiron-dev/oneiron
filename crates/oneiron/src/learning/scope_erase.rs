//! A project's learning scope goes with the project (FIX 6038). Erasing a
//! project removes every cell keyed in its scope, with the cell's subject
//! index, evidence and stored prior. Each claim head such a cell projected
//! is retracted and re-keyed to one fresh opaque scope, so no stored key or
//! body still derives from the erased id. Vault cells and every other
//! project's stay as they are.

use std::collections::BTreeSet;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;

use super::evidence::{CELL, CELL_BY_SUBJECT, EVIDENCE, evidence_in_txn};
use super::prior::PRIOR;
use super::project::{StoredEstimateClaim, entity_header};

/// Removes erased `entity`'s learning scope: every cell keyed in it and the
/// rows keyed by those cells, and its heads re-keyed and retracted. An
/// entity no cell is scoped to changes nothing. A row that no longer
/// decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_learning_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let scoped: Vec<_> = crate::skill_attribution::erase_scan_in_txn(vault, wtxn, CELL)?
        .into_iter()
        .filter(|(_, row)| row.cell.project == Some(*entity))
        .collect();
    if scoped.is_empty() {
        return Ok(());
    }
    let mut subjects = BTreeSet::new();
    for (digest, row) in &scoped {
        for (receipt, _) in evidence_in_txn(vault, wtxn, digest)? {
            EVIDENCE.delete(&vault.store, wtxn, &(*digest, receipt))?;
        }
        PRIOR.delete(&vault.store, wtxn, digest)?;
        CELL_BY_SUBJECT.delete(&vault.store, wtxn, &(row.cell.subject, *digest))?;
        CELL.delete(&vault.store, wtxn, digest)?;
        subjects.insert(row.cell.subject);
    }
    let erased = vault.store.clock.entity_id()?;
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    for subject in subjects {
        rekey_heads_in_txn(vault, wtxn, &subject, *entity, erased, now)?;
    }
    Ok(())
}

/// Re-keys every learning head on `subject` whose cell is scoped to
/// `entity`, active or superseded, to the opaque scope `erased`; an active
/// one is retracted at `now`. A borrowed prior's provenance that names the
/// erased scope goes too.
fn rekey_heads_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    entity: EntityId,
    erased: EntityId,
    now: u64,
) -> Result<()> {
    let named = entity.to_hex();
    for id in vault.claims_for_subject_in_txn(wtxn, subject)? {
        let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
            continue;
        };
        if !super::is_learning_predicate(&body.predicate)
            || body.source != Some(ClaimSource::Observed)
            || body.approval != ClaimApprovalStatus::Auto
        {
            continue;
        }
        let Ok(mut stored) = StoredEstimateClaim::from_value(&body.value) else {
            continue;
        };
        if stored.cell.project != Some(entity) {
            continue;
        }
        stored.cell.project = Some(erased);
        if stored
            .estimate
            .prior
            .from
            .as_deref()
            .is_some_and(|from| from.contains(named.as_str()))
        {
            stored.estimate.prior.from = None;
        }
        body.value = stored.to_value()?;
        let header = entity_header(vault, wtxn, &id)?;
        let mut range = TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        if body.lifecycle == ClaimLifecycleStatus::Active {
            // A withdrawal stamped before the row it closes would make the
            // re-put range invalid.
            let at = now.max(header.occurred_start);
            body.lifecycle = ClaimLifecycleStatus::Retracted;
            body.valid_to = Some(at);
            range.end = at;
        }
        vault.put_reserved_claim_in_txn(wtxn, &id, &body, range, header.learned_at)?;
    }
    Ok(())
}
