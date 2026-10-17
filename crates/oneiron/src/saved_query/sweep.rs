//! The host's saved-query sweep (ARCH-0059 `eval`): the queries a wake
//! evaluates, the people it pages through, and the owner reach each query is
//! evaluated under. Each wake keeps to the query's own `max_entities_per_wake`
//! and `max_judges_per_wake`; the verdict memo makes an unmoved person free.

use super::definition::{EvalMode, QueryScope, SavedQueryLifecycle, SavedQueryRecord};
use super::storage::{load_record_in_txn, saved_query_type_byte};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

/// A sweep's candidates: PERSON, a campaign's population unit (ARCH-0059).
pub const SWEEP_CANDIDATE_TYPE: u8 = crate::registry::ENTITY_TYPE_PERSON;

/// Saved-query ids read per page of the type index.
const QUERY_PAGE: usize = 256;

/// Every saved query a sweep evaluates: active, and Wake or Reactive. A
/// Reactive query is swept too until reactive delivery is wired, so it is
/// never silently inert. A vault without the CRM pack has none.
pub fn sweep_saved_queries(vault: &Vault) -> Result<Vec<SavedQueryRecord>> {
    let Ok(kind) = saved_query_type_byte(vault) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(kind, after.as_ref(), QUERY_PAGE)?;
        let full = page.len() == QUERY_PAGE;
        after = page.last().copied();
        let rtxn = vault.store.env.read_txn()?;
        for query_ref in page {
            let Some(record) = load_record_in_txn(vault, &rtxn, query_ref, kind)? else {
                continue;
            };
            if record.definition.lifecycle == SavedQueryLifecycle::Active
                && record.definition.eval.mode != EvalMode::Manual
            {
                records.push(record);
            }
        }
        if !full {
            return Ok(records);
        }
    }
}

/// The reach a sweep evaluates `owner`'s query under, read now: all of the
/// vault for the vault owner. `None` for any other owner, whose current
/// grants no resolver maps to a [`QueryScope`] yet: the sweep leaves that
/// query to an explicit evaluation rather than guess its reach.
pub fn sweep_owner_grants(vault: &Vault, owner: EntityId) -> Result<Option<QueryScope>> {
    let rtxn = vault.store.env.read_txn()?;
    let is_owner =
        crate::memory::actor_is_vault_owner_in_txn(vault, &rtxn, owner, EdgeActorClass::Human)
            .map_err(|error| Error::InvalidConfig(error.message))?;
    Ok(is_owner.then(QueryScope::default))
}
