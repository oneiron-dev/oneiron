//! Owner-bound per-claim watches stored as SAVED_QUERY definitions.
//!
//! The query identity is deterministic for (owner, anchor). This makes the
//! flag idempotent and prevents two concurrent callers from creating two
//! standing watches. The definition is the durable authority, not a socket.
use crate::EdgeActorClass;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::MemoryResult;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;

use super::definition::{
    EvalMode, EvalPolicy, QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryDefinition,
    SavedQueryLifecycle, SavedQueryRecord,
};
use super::filter::{FilterAst, MatcherSpec};
use super::lifecycle::next_version;
use super::storage::{load_record_in_txn, saved_query_type_byte, store_record_in_txn};

const MAX_MEMORY_WATCHES: usize = 128;

/// An active durable watch, addressed by its SAVED_QUERY identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryWatch {
    pub query_ref: EntityId,
    pub anchor: EntityId,
}

fn kind_is_installed(vault: &Vault) -> bool {
    vault
        .structural_kind_registrations()
        .iter()
        .any(|registration| {
            registration.short_id_prefix == super::definition::SAVED_QUERY_SHORT_ID_PREFIX
                && registration.pack == crate::campaign::CRM_PACK_ID
        })
}

fn watch_id(owner: EntityId, anchor: EntityId) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.saved_query.memory_watch.v1");
    hash.update(owner.as_bytes());
    hash.update(anchor.as_bytes());
    EntityId::from_bytes(
        hash.finalize().as_bytes()[..16]
            .try_into()
            .map_err(|_| Error::InvariantViolation("memory watch id digest"))?,
    )
}

fn anchor_of(definition: &SavedQueryDefinition) -> Option<EntityId> {
    if definition.schema_version != SAVED_QUERY_SCHEMA_VERSION
        || definition.eval.mode != EvalMode::Reactive
        || definition.scope != QueryScope::default()
        || !matches!(&definition.matcher, MatcherSpec::Hard { expression: FilterAst::All { terms } } if terms.is_empty())
    {
        return None;
    }
    match &definition.filter {
        FilterAst::EdgeExists {
            edge_kind,
            target: Some(anchor),
        } if edge_kind == "supersedes" => Some(*anchor),
        _ => None,
    }
}

fn is_watch(record: &SavedQueryRecord, owner: EntityId, anchor: EntityId) -> bool {
    record.definition.owner_actor == owner
        && anchor_of(&record.definition) == Some(anchor)
        && watch_id(owner, anchor).ok() == Some(record.query_ref)
}

/// Sets the owner's per-entry watch flag. The SAVED_QUERY row survives restart
/// and the returned query ref can be used as the durable flag's identity.
/// A vault must have registered its SAVED_QUERY kind before accepting watches.
pub fn set_memory_watch(
    vault: &Vault,
    owner: EntityId,
    anchor: EntityId,
    enabled: bool,
    now: u64,
) -> MemoryResult<Option<MemoryWatch>> {
    if !enabled && !kind_is_installed(vault) {
        return Ok(None);
    }
    let kind = saved_query_type_byte(vault)?;
    if enabled
        && (vault.get_entity_type(&anchor)? != Some(ENTITY_TYPE_CLAIM)
            || vault.get_claim(&anchor)?.is_none())
    {
        return Err(Error::EntityNotFound.into());
    }
    let query_ref = watch_id(owner, anchor)?;
    vault.try_with_write_txn(|txn| {
        vault
            .memory(owner, EdgeActorClass::Human)
            .verify_owner_in_txn(&*txn)?;
        let existing = load_record_in_txn(vault, txn, query_ref, kind)?;
        match existing {
            Some(mut record) => {
                if !is_watch(&record, owner, anchor) {
                    return Err(
                        Error::InvariantViolation("memory watch query identity collision").into(),
                    );
                }
                if record.definition.lifecycle == SavedQueryLifecycle::Archived {
                    return Err(Error::InvalidConfig(
                        "archived memory watch cannot be reopened".into(),
                    )
                    .into());
                }
                if record.definition.lifecycle.is_evaluable() == enabled {
                    return Ok(enabled.then_some(MemoryWatch { query_ref, anchor }));
                }
                if enabled
                    && active_watch_count_in_txn(vault, txn, kind, owner)? >= MAX_MEMORY_WATCHES
                {
                    return Err(Error::InvalidConfig(
                        "per-owner memory watch limit exceeded".into(),
                    )
                    .into());
                }
                record.definition.definition_version =
                    next_version(record.definition.definition_version)?;
                record.definition.lifecycle = if enabled {
                    SavedQueryLifecycle::Active
                } else {
                    SavedQueryLifecycle::Disabled
                };
                record.updated_at = now;
                store_record_in_txn(vault, txn, &record, kind)?;
            }
            None if enabled => {
                if active_watch_count_in_txn(vault, txn, kind, owner)? >= MAX_MEMORY_WATCHES {
                    return Err(Error::InvalidConfig(
                        "per-owner memory watch limit exceeded".into(),
                    )
                    .into());
                }
                // A foreign entity at the deterministic identity is never overwritten.
                if vault.port_entity_record(txn, &query_ref)?.is_some() {
                    return Err(
                        Error::InvariantViolation("memory watch query identity collision").into(),
                    );
                }
                let record = SavedQueryRecord {
                    query_ref,
                    definition: SavedQueryDefinition {
                        schema_version: SAVED_QUERY_SCHEMA_VERSION,
                        owner_actor: owner,
                        scope: QueryScope::default(),
                        definition_version: 1,
                        filter: FilterAst::EdgeExists {
                            edge_kind: "supersedes".into(),
                            target: Some(anchor),
                        },
                        matcher: MatcherSpec::Hard {
                            expression: FilterAst::All { terms: Vec::new() },
                        },
                        eval: EvalPolicy {
                            mode: EvalMode::Reactive,
                            max_entities_per_wake: 128,
                            max_judges_per_wake: 1,
                        },
                        lifecycle: SavedQueryLifecycle::Active,
                    },
                    created_at: now,
                    updated_at: now,
                };
                store_record_in_txn(vault, txn, &record, kind)?;
            }
            None => return Ok(None),
        }
        Ok(enabled.then_some(MemoryWatch { query_ref, anchor }))
    })
}

fn active_watch_count_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    owner: EntityId,
) -> Result<usize> {
    let mut count = 0;
    for item in vault.port_entity_ids_by_type(txn, kind, None)? {
        let id = item?;
        if let Some(record) = load_record_in_txn(vault, txn, id, kind)?
            && let Some(anchor) = anchor_of(&record.definition)
            && is_watch(&record, owner, anchor)
            && record.definition.lifecycle.is_evaluable()
        {
            count += 1;
            if count >= MAX_MEMORY_WATCHES {
                break;
            }
        }
    }
    Ok(count)
}

/// Reads one owner's watch, without revealing another owner's query.
pub fn memory_watch(
    vault: &Vault,
    owner: EntityId,
    anchor: EntityId,
) -> Result<Option<MemoryWatch>> {
    if !kind_is_installed(vault) {
        return Ok(None);
    }
    let kind = saved_query_type_byte(vault)?;
    let txn = vault.store.env.read_txn()?;
    let query_ref = watch_id(owner, anchor)?;
    Ok(load_record_in_txn(vault, &txn, query_ref, kind)?
        .filter(|record| {
            is_watch(record, owner, anchor) && record.definition.lifecycle.is_evaluable()
        })
        .map(|_| MemoryWatch { query_ref, anchor }))
}

/// Lists only active watches bound to this owner. Other SAVED_QUERY definitions
/// cannot impersonate a watch merely by using the same filter expression.
pub fn memory_watches(vault: &Vault, owner: EntityId) -> Result<Vec<MemoryWatch>> {
    if !kind_is_installed(vault) {
        return Ok(Vec::new());
    }
    let kind = saved_query_type_byte(vault)?;
    let txn = vault.store.env.read_txn()?;
    let mut watches = Vec::new();
    for item in vault.port_entity_ids_by_type(&txn, kind, None)? {
        let id = item?;
        let Some(record) = load_record_in_txn(vault, &txn, id, kind)? else {
            continue;
        };
        if let Some(anchor) = anchor_of(&record.definition)
            && is_watch(&record, owner, anchor)
            && record.definition.lifecycle.is_evaluable()
        {
            watches.push(MemoryWatch {
                query_ref: id,
                anchor,
            });
        }
    }
    watches.sort_by_key(|watch| watch.query_ref);
    Ok(watches)
}
