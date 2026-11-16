//! The members of each workspace a shared source was imported from (Engine
//! ruling L2-18-CONTACT = A, under the owner's IMPORT-IDENTITY ruling of
//! 15 Nov 00:43): each member's name, and the PERSON the owner mapped it to,
//! or none. A member mapped to none is a contact: its name and its words are
//! kept, it reads nothing, and no PERSON is minted for it ("Imported
//! speakers stay in provenance", ARCH-0027). The owner can map it later; the
//! sharing rule then applies to it.
//!
//! The owner confirms the map once per import: [`Vault::propose_history_members`]
//! proposes it, keeping what the owner mapped before and matching the rest by
//! email. [`Vault::set_history_member`] maps one member later, and gives it
//! the containers it is in, from the members each container of the
//! workspace was shared with.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{HistoryMember, HistorySharing, HistorySource, sharing};
use crate::comm::{CommError, CommParties};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// One member of a workspace, by `source:workspace:member`.
const MEMBERS: SideTable<String, StoredMember, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_SOURCE_MEMBER);

/// One sharing container of a workspace, by `source:container`.
const CONTAINERS: SideTable<String, StoredContainer, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_SOURCE_CONTAINER);

/// The party key of an email address is `email:<mailbox>`.
const EMAIL_PARTY_PREFIX: &str = "email:";

/// A member as the table keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMember {
    name: Option<String>,
    person: Option<EntityId>,
    importer: bool,
}

/// A sharing container as the table keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredContainer {
    /// The workspace the container is in.
    workspace: String,
    /// The source's ids of the members it is shared with.
    members: BTreeSet<String>,
}

/// One member of a workspace to propose a PERSON for: the source's id for
/// it, and the email address the source gives for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMemberAddress {
    pub provider_id: String,
    pub email: Option<String>,
}

fn workspace_prefix(source: HistorySource, workspace: &str) -> String {
    format!("{}:{workspace}:", source.source_id())
}

impl Vault {
    /// Keeps the members of the `workspace` of `source` as the owner mapped
    /// them for this import: each member's name, and its PERSON or none.
    /// Each import writes every member it names again, so the table holds
    /// the latest map; a member it does not name keeps its row. It keeps,
    /// in the same transaction, the members each of the import's sharing
    /// `containers` is shared with.
    ///
    /// # Errors
    ///
    /// A bad request for a member mapped to no live PERSON; a failure of the
    /// vault itself. Nothing is written then.
    pub fn import_history_members(
        &self,
        owner: &AuthenticatedOwner,
        source: HistorySource,
        workspace: &str,
        members: &[HistoryMember],
        containers: &[&HistorySharing],
    ) -> MemoryResult<()> {
        let memory = self.memory(owner.revalidate(self)?, EdgeActorClass::Human);
        memory.with_verified_actor_write_txn(|wtxn| {
            owner.revalidate_in_txn(self, wtxn)?;
            let prefix = workspace_prefix(source, workspace);
            for member in members {
                if let Some(person) = &member.person
                    && !sharing::live_person_in(self, wtxn, person)?
                {
                    return Err(MemoryError::bad_request(
                        "a workspace member maps to a live PERSON",
                    ));
                }
                let row = StoredMember {
                    name: member.name.clone(),
                    person: member.person,
                    importer: member.importer,
                };
                MEMBERS.put(
                    &self.store,
                    wtxn,
                    &format!("{prefix}{}", member.provider_id),
                    &row,
                )?;
            }
            for container in containers {
                let row = StoredContainer {
                    workspace: workspace.to_owned(),
                    members: container
                        .members
                        .iter()
                        .map(|member| member.provider_id.clone())
                        .collect(),
                };
                CONTAINERS.put(
                    &self.store,
                    wtxn,
                    &sharing::container_key(source, &container.container),
                    &row,
                )?;
            }
            Ok(())
        })
    }

    /// The members the table keeps for the `workspace` of `source`, in
    /// member id order.
    ///
    /// # Errors
    ///
    /// A storage error reading the table.
    pub fn history_import_members(
        &self,
        source: HistorySource,
        workspace: &str,
    ) -> Result<Vec<HistoryMember>> {
        let txn = self.store.env.read_txn()?;
        let prefix = workspace_prefix(source, workspace);
        Ok(MEMBERS
            .scan_from(&self.store, &txn, prefix.as_bytes())?
            .into_iter()
            .map(|(key, row)| HistoryMember {
                provider_id: key.strip_prefix(prefix.as_str()).unwrap_or(&key).to_owned(),
                name: row.name,
                person: row.person,
                importer: row.importer,
            })
            .collect())
    }

    /// Proposes who each of `members` of the `workspace` of `source` is, for
    /// the owner to confirm once per import (owner ruling IMPORT-IDENTITY =
    /// C, 15 Nov 00:43). For each member, the first that holds:
    /// - the member table maps it to a live PERSON, or as the importer's own
    ///   member: the owner said so before, and it is kept;
    /// - its email address, lowercased, is the mailbox of the `email:` party
    ///   key of exactly one comm PERSON, lowercased: that PERSON. An address
    ///   two PERSONs carry proposes none, and the importer's own PERSON is
    ///   never proposed: the owner names its own member;
    /// - none: the member stays a contact.
    ///
    /// It reads only. Each answer names the member and its proposed PERSON,
    /// or the importer; no name.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds; a failure of the vault itself.
    pub fn propose_history_members(
        &self,
        owner: &AuthenticatedOwner,
        source: HistorySource,
        workspace: &str,
        members: &[HistoryMemberAddress],
    ) -> Result<Vec<HistoryMember>> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let importer = sharing::importer_person_in(self, &txn, actor)?;
        let parties = CommParties::read_in_txn(self, &txn).map_err(|error| match error {
            CommError::Engine(error) => error,
            other => crate::Error::InvalidConfig(other.to_string()),
        })?;
        let mut mailboxes: BTreeMap<String, BTreeSet<EntityId>> = BTreeMap::new();
        for (party_key, person) in parties.entries() {
            if let Some(mailbox) = party_key.strip_prefix(EMAIL_PARTY_PREFIX) {
                mailboxes
                    .entry(mailbox.to_lowercase())
                    .or_default()
                    .insert(person);
            }
        }
        let prefix = workspace_prefix(source, workspace);
        let mut proposals = Vec::with_capacity(members.len());
        for member in members {
            let mut proposal = HistoryMember {
                provider_id: member.provider_id.clone(),
                name: None,
                person: None,
                importer: false,
            };
            let kept = MEMBERS.get(
                &self.store,
                &txn,
                &format!("{prefix}{}", member.provider_id),
            )?;
            if let Some(kept) = kept {
                if kept.importer {
                    proposal.importer = true;
                    proposals.push(proposal);
                    continue;
                }
                if let Some(person) = kept.person
                    && sharing::live_person_in(self, &txn, &person)?
                {
                    proposal.person = Some(person);
                    proposals.push(proposal);
                    continue;
                }
            }
            proposal.person = member
                .email
                .as_deref()
                .and_then(|email| mailboxes.get(&email.to_lowercase()))
                .filter(|persons| persons.len() == 1)
                .and_then(BTreeSet::first)
                .copied()
                .filter(|person| Some(*person) != importer);
            proposals.push(proposal);
        }
        Ok(proposals)
    }

    /// Maps the member `member` of the `workspace` of `source` to `person`,
    /// or to none (a contact), and sets again, in the same transaction, the
    /// readers of every sharing container of the workspace the member is
    /// in: the live PERSON each of the container's members is mapped to,
    /// and the importer's own (Engine ruling L2-18-CONTACT = A). A member
    /// mapped later reads its containers' rows from then on, the earlier
    /// ones included; a member mapped to none reads none of them. A PERSON
    /// since deleted reads nothing. Returns how many containers' readers
    /// were set.
    ///
    /// # Errors
    ///
    /// A bad request for a member the table does not keep for the
    /// workspace, for a `person` that is no live PERSON, and for an
    /// importer who stands for no person; an owner proof that no longer
    /// holds; a failure of the vault itself. Nothing is written then.
    pub fn set_history_member(
        &self,
        owner: &AuthenticatedOwner,
        source: HistorySource,
        workspace: &str,
        member: &str,
        person: Option<EntityId>,
        at: u64,
    ) -> MemoryResult<u32> {
        let memory = self.memory(owner.revalidate(self)?, EdgeActorClass::Human);
        memory.with_verified_actor_write_txn(|wtxn| {
            let actor = owner.revalidate_in_txn(self, wtxn)?;
            let prefix = workspace_prefix(source, workspace);
            let key = format!("{prefix}{member}");
            let mut row = MEMBERS.get(&self.store, wtxn, &key)?.ok_or_else(|| {
                MemoryError::bad_request("the member is one an import of the workspace kept")
            })?;
            if let Some(person) = &person
                && !sharing::live_person_in(self, wtxn, person)?
            {
                return Err(MemoryError::bad_request(
                    "a workspace member maps to a live PERSON",
                ));
            }
            row.person = person;
            row.importer = false;
            MEMBERS.put(&self.store, wtxn, &key, &row)?;
            let mut mapped = BTreeMap::new();
            for (key, row) in MEMBERS.scan_from(&self.store, wtxn, prefix.as_bytes())? {
                if let Some(person) = row.person
                    && sharing::live_person_in(self, wtxn, &person)?
                {
                    let id = key.strip_prefix(prefix.as_str()).unwrap_or(&key);
                    mapped.insert(id.to_owned(), person);
                }
            }
            let source_prefix = format!("{}:", source.source_id());
            let containers = CONTAINERS.scan_from(&self.store, wtxn, source_prefix.as_bytes())?;
            let mut set = 0_u32;
            for (key, container) in containers {
                if container.workspace != workspace || !container.members.contains(member) {
                    continue;
                }
                let readers = container
                    .members
                    .iter()
                    .filter_map(|id| mapped.get(id))
                    .copied()
                    .collect();
                if sharing::set_container_readers_in_txn(self, wtxn, &key, readers, actor, at)? {
                    set = set.saturating_add(1);
                }
            }
            Ok(set)
        })
    }
}
