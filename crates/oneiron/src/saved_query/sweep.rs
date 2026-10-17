//! The host's saved-query sweep (ARCH-0059 `eval`): the queries a wake
//! evaluates, the people it pages through, and the owner reach each query is
//! evaluated under. Each wake keeps to the query's own `max_entities_per_wake`
//! and `max_judges_per_wake`; the verdict memo makes an unmoved person free.
//! A Reactive query is also re-checked for each person a claim write moves
//! ("new claim lands → re-check just that entity"), read off the vault's
//! change log.

use std::collections::BTreeSet;

use super::definition::{EvalMode, QueryScope, SavedQueryLifecycle, SavedQueryRecord};
use super::storage::{load_record_in_txn, saved_query_type_byte};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSubject;
use crate::ports::{ChangeLogStoreRead, EntityStoreRead};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

/// A sweep's candidates: PERSON, a campaign's population unit (ARCH-0059).
pub const SWEEP_CANDIDATE_TYPE: u8 = crate::registry::ENTITY_TYPE_PERSON;

/// Saved-query ids read per page of the type index.
const QUERY_PAGE: usize = 256;

/// Every saved query a sweep evaluates: active, and Wake or Reactive. A
/// Reactive query is swept too, as the backstop for what its change feed
/// cannot see (a deleted claim's subject, an edge, the passage of time). A
/// vault without the CRM pack has none.
pub fn sweep_saved_queries(vault: &Vault) -> Result<Vec<SavedQueryRecord>> {
    active_saved_queries(vault, |mode| mode != EvalMode::Manual)
}

/// Every active Reactive saved query: those a claim write re-checks.
pub fn reactive_saved_queries(vault: &Vault) -> Result<Vec<SavedQueryRecord>> {
    active_saved_queries(vault, |mode| mode == EvalMode::Reactive)
}

fn active_saved_queries(
    vault: &Vault,
    mode: impl Fn(EvalMode) -> bool,
) -> Result<Vec<SavedQueryRecord>> {
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
                && mode(record.definition.eval.mode)
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

/// The people a run of the vault's change log moved, for Reactive saved
/// queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonChanges {
    /// The last change read; the next read goes on after it. `None` when
    /// no change was read.
    pub through: Option<[u8; 16]>,
    /// Whether changes remain after `through`.
    pub more: bool,
    pub persons: BTreeSet<EntityId>,
}

/// The newest change in the vault's change log: where a Reactive reader
/// starts, so it re-checks only what changes from then on.
pub fn saved_query_change_head(vault: &Vault) -> Result<Option<[u8; 16]>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault.port_changelog_head(&txn)?.map(|(id, _)| id))
}

/// Up to `max_rows` changes after `after`, and the people they moved: a
/// person whose own row changed, and the person a live changed claim is
/// about. A deleted claim's subject cannot be read back, nor is an edge a
/// claim; the sweep's paged pass covers those.
pub fn saved_query_changes_after(
    vault: &Vault,
    after: Option<[u8; 16]>,
    max_rows: usize,
) -> Result<PersonChanges> {
    let txn = vault.store.env.read_txn()?;
    let mut changes = PersonChanges::default();
    let mut rows = vault.port_changelog_after(&txn, after)?;
    for row in rows.by_ref().take(max_rows) {
        let (id, change) = row?;
        changes.through = Some(id);
        let Some(raw) = vault.store.port_entity_raw(&txn, &change.entity)? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type == SWEEP_CANDIDATE_TYPE {
            changes.persons.insert(change.entity);
            continue;
        }
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        let ClaimSubject::Entity(subject) = body.subject else {
            continue;
        };
        let person = vault
            .store
            .port_entity_raw(&txn, &subject)?
            .and_then(|raw| EntityMetadataHeader::parse(&raw))
            .is_some_and(|header| header.entity_type == SWEEP_CANDIDATE_TYPE);
        if person {
            changes.persons.insert(subject);
        }
    }
    changes.more = rows.next().is_some();
    Ok(changes)
}
