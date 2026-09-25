//! Exact, capped scope resolution over a single transaction snapshot.

use super::graph::{self, chain, edge_ids, invalid, require_member, require_type};
use super::migration::migrate_in_txn;
use super::{ResolvedScope, ScopePath, ScopeSelector};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::registry::ENTITY_TYPE_SESSION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::RwTxn;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

fn sub_session_records(
    vault: &Vault,
    txn: &RwTxn<'_>,
    scope: &ScopeSelector,
    session: EntityId,
) -> Result<Vec<EntityId>> {
    require_type(&vault.store, txn, &session, ENTITY_TYPE_SESSION)?;
    if scope.session.is_some_and(|id| id != session) {
        return Err(invalid("conflicting session selectors"));
    }
    let spawned = edge_ids(&vault.store, txn, &session, EdgeKind::SpawnedBy, false, 2)?;
    if spawned.len() != 1 {
        return Err(invalid("SubSession requires exactly one SpawnedBy edge"));
    }
    require_member(&vault.store, txn, &scope.conversation, &spawned[0])?;
    let prefix = [b"session_turns:v1:".as_slice(), session.as_bytes()].concat();
    let mut records = Vec::new();
    for (n, entry) in vault
        .store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .enumerate()
    {
        if n >= MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        let (key, value) = entry?;
        if key.len() != prefix.len() + 16 || value.as_ref() != [1] {
            return Err(Error::CorruptedIndex("session turns index"));
        }
        let id = EntityId::from_bytes(
            key.as_ref()[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("session turns index"))?,
        )?;
        match live_entity_row_in_txn(&vault.store, txn, &id)? {
            LiveEntityRow::DeletedShell | LiveEntityRow::Absent => continue,
            _ => {}
        }
        require_member(&vault.store, txn, &scope.conversation, &id)?;
        if crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &id)?
            != Some(session)
        {
            return Err(Error::CorruptedIndex("session turns index"));
        }
        records.push(id);
    }
    // A complete reverse-membership result is sorted topologically, not by
    // UUID. Each Parent is either the spawning turn or another member. Kahn's
    // bounded walk rejects cycles without an O(n^2) walk from every record.
    let members: HashSet<_> = records.iter().copied().collect();
    let mut children: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for id in &records {
        let parent = graph::parent(&vault.store, txn, id)?
            .ok_or_else(|| invalid("sub-session record lacks Parent"))?;
        if parent == spawned[0] {
            ready.insert(*id);
        } else if members.contains(&parent) {
            children.entry(parent).or_default().push(*id);
        } else {
            return Err(invalid("sub-session Parent is outside its scope"));
        }
    }
    let mut ordered = Vec::with_capacity(records.len());
    while let Some(id) = ready.pop_first() {
        ordered.push(id);
        if let Some(children) = children.remove(&id) {
            ready.extend(children);
        }
    }
    if ordered.len() != records.len() {
        return Err(crate::error::RegistryError::CycleDetected.into());
    }
    Ok(ordered)
}

pub(crate) fn resolve_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    scope: &ScopeSelector,
) -> Result<ResolvedScope> {
    migrate_in_txn(vault, txn, &scope.conversation)?;
    if let ScopePath::SubSession(session) = scope.path {
        return Ok(ResolvedScope {
            scope: scope.clone(),
            records: sub_session_records(vault, txn, scope, session)?,
        });
    }
    if let Some(session) = scope.session {
        require_type(&vault.store, txn, &session, ENTITY_TYPE_SESSION)?;
    }
    let mut records = match scope.path {
        ScopePath::Canonical => graph::canonical_chain(&vault.store, txn, &scope.conversation)?,
        ScopePath::Branch(id) => chain(&vault.store, txn, &scope.conversation, id)?,
        ScopePath::SubSession(_) => unreachable!("handled above"),
    };
    // Branch paths must use the dedicated SubSession selector rather than
    // pulling a retained worker's records into the parent conversation.
    for id in &records {
        if graph::is_sub_session_record(&vault.store, txn, id)? {
            return Err(invalid("use SubSession to select sub-session records"));
        }
    }
    if scope.include_forks {
        let mut seen: HashSet<_> = records.iter().copied().collect();
        let mut queue: VecDeque<_> = records.iter().copied().collect();
        let mut examined = records.len();
        while let Some(parent) = queue.pop_front() {
            let children = edge_ids(
                &vault.store,
                txn,
                &parent,
                EdgeKind::Parent,
                true,
                MAX_ANCESTOR_DEPTH.saturating_sub(examined),
            )?;
            examined += children.len();
            for child in children {
                if seen.contains(&child) {
                    continue;
                }
                match live_entity_row_in_txn(&vault.store, txn, &child)? {
                    LiveEntityRow::Absent | LiveEntityRow::DeletedShell => continue,
                    _ => {}
                }
                require_member(&vault.store, txn, &scope.conversation, &child)?;
                if graph::parent(&vault.store, txn, &child)? != Some(parent) {
                    return Err(Error::CorruptedIndex("conversation Parent index"));
                }
                if graph::is_sub_session_record(&vault.store, txn, &child)? {
                    continue;
                }
                seen.insert(child);
                records.push(child);
                queue.push_back(child);
            }
        }
    }
    if let Some(session) = scope.session {
        let mut filtered = Vec::new();
        for id in records {
            if crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &id)?
                == Some(session)
            {
                filtered.push(id);
            }
        }
        records = filtered;
    }
    Ok(ResolvedScope {
        scope: scope.clone(),
        records,
    })
}

impl Vault {
    /// Resolves a complete scope. Safety limits refuse instead of truncating
    /// the covers set that a later summary will attest to.
    pub fn resolve_dag_scope(&self, scope: &ScopeSelector) -> Result<ResolvedScope> {
        self.with_write_txn(|txn| resolve_in_txn(self, txn, scope))
    }
}
