//! A source's own sharing, kept by the import (ARCH-0027 #import-audience,
//! owner ruling 2026-10-17): the rows of a conversation the source shared
//! read to the people it shared it with, and to the importer, who holds the
//! export (Engine ruling L2-18-READERS = A).
//!
//! Each sharing container reads under one source policy
//! ([`crate::source_audience`]), found by the container and kept in
//! `INGEST_HISTORY_SHARING_POLICY`. The first import of a container writes
//! the policy; each later one sets its readers again, so a member the source
//! no longer names reads none of the container's rows from that import on,
//! as a group address's edited member list does. A contact the owner maps
//! later reads the container's rows from then on (`members set`, in
//! `members.rs`). Each conversation lands under its own thread policy below
//! the container's, as a mail thread does.
//! The Dreamer reads each such thread, as it reads every import: what it
//! extracts lands Proposed under the import's review, held by lineage to
//! the rows' readers.

use std::collections::BTreeSet;

use super::{HistorySharing, HistorySharingCounts, HistorySource};
use crate::error::Result;
use crate::memory::{MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault, source_audience};

/// The source policy of each sharing container, by `source:container`.
const POLICIES: SideTable<String, EntityId, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_SHARING_POLICY);

/// The key of the sharing container `container` of `source`, in this
/// module's table and in the member module's.
pub(super) fn container_key(source: HistorySource, container: &str) -> String {
    format!("{}:{container}", source.source_id())
}

/// The source policy `sharing`'s container reads under, written in `txn` the
/// first time and its readers set again on each later import: every member
/// the owner mapped to a PERSON, and the importer `actor`'s own PERSON. The
/// counts say how many PERSONs read it and how many members are contacts.
///
/// # Errors
///
/// A bad request for a member mapped to no live PERSON, and for an importer
/// who stands for no PERSON; storage failures.
pub(super) fn container_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: HistorySource,
    sharing: &HistorySharing,
    actor: EntityId,
    at: u64,
) -> MemoryResult<(EntityId, HistorySharingCounts)> {
    let mut readers = BTreeSet::new();
    for person in sharing
        .members
        .iter()
        .filter_map(|member| member.person.as_ref())
    {
        if !live_person_in(vault, txn, person)? {
            return Err(MemoryError::bad_request(
                "a shared conversation's member maps to a live PERSON",
            ));
        }
        readers.insert(*person);
    }
    readers.insert(importer_reader_in(vault, txn, actor)?);
    let contacts: BTreeSet<&str> = sharing
        .members
        .iter()
        .filter(|member| member.person.is_none() && !member.importer)
        .map(|member| member.provider_id.as_str())
        .collect();
    let counts = HistorySharingCounts {
        readers: u32::try_from(readers.len()).unwrap_or(u32::MAX),
        unmapped: u32::try_from(contacts.len()).unwrap_or(u32::MAX),
    };
    let key = container_key(source, &sharing.container);
    if let Some(policy) = POLICIES.get(&vault.store, txn, &key)? {
        source_audience::set_source_readers_in_txn(vault, txn, &policy, readers, actor, at)?;
        return Ok((policy, counts));
    }
    let policy =
        source_audience::create_source_policy_in_txn(vault, txn, readers, false, actor, at)?;
    POLICIES.put(&vault.store, txn, &key, &policy)?;
    Ok((policy, counts))
}

/// Sets the readers of the sharing container whose key is `key`
/// ([`container_key`]) again, in `txn`: the PERSONs `persons` and the
/// importer `actor`'s own, as [`container_policy_in_txn`] sets them. Whether
/// an import wrote the container's policy; one it never wrote is left.
///
/// # Errors
///
/// A bad request for an importer who stands for no PERSON; storage failures.
pub(super) fn set_container_readers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &str,
    mut persons: BTreeSet<EntityId>,
    actor: EntityId,
    at: u64,
) -> MemoryResult<bool> {
    let Some(policy) = POLICIES.get(&vault.store, txn, &key.to_owned())? else {
        return Ok(false);
    };
    persons.insert(importer_reader_in(vault, txn, actor)?);
    source_audience::set_source_readers_in_txn(vault, txn, &policy, persons, actor, at)?;
    Ok(true)
}

/// The importer `actor`'s own PERSON, who reads every container it imports.
fn importer_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> MemoryResult<EntityId> {
    importer_person_in(vault, txn, actor)?.ok_or_else(|| {
        MemoryError::bad_request("a shared conversation is imported by a person who reads it")
    })
}

/// The thread policy the conversation `native_id` lands under, below its
/// container's source policy `policy`, written in `txn` the first time and
/// shared with the Dreamer then. Without the share the Dreamer, a MACHINE
/// that is no reader, would read none of a shared import's words.
///
/// # Errors
///
/// Storage failures.
pub(super) fn conversation_thread_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    policy: &EntityId,
    native_id: &str,
    actor: EntityId,
    at: u64,
) -> Result<EntityId> {
    let thread = source_audience::thread_policy_in_txn(vault, txn, policy, native_id, actor, at)?;
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?;
    source_audience::share_thread_in_txn(vault, txn, &thread, dreamer, true, actor, at)?;
    Ok(thread)
}

/// Whether `id` is a live PERSON in `txn`.
pub(super) fn live_person_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.live_type()
            == Some(ENTITY_TYPE_PERSON),
    )
}

/// The PERSON the importing `actor` stands for: its own PERSON or its pen's,
/// or the one owner of a vault with no authority root for its embedded owner
/// actor ([`source_audience::embedded_owner_person_in`]).
pub(super) fn importer_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Option<EntityId>> {
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    if let Some(person) =
        crate::workspace_roster::subject_person_of_actor_in_txn(vault, txn, actor, at)?
        && live_person_in(vault, txn, &person)?
    {
        return Ok(Some(person));
    }
    source_audience::embedded_owner_person_in(vault, txn, actor)
}
