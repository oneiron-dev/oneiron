//! The members of each workspace a shared source was imported from (Engine
//! ruling L2-18-CONTACT = A, under the owner's IMPORT-IDENTITY ruling of
//! 15 Nov 00:43): each member's name, and the PERSON the owner mapped it to,
//! or none. A member mapped to none is a contact: its name and its words are
//! kept, it reads nothing, and no PERSON is minted for it ("Imported
//! speakers stay in provenance", ARCH-0027). The owner can map it later; the
//! sharing rule then applies to it.

use serde::{Deserialize, Serialize};

use super::{HistoryMember, HistorySource, sharing};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// One member of a workspace, by `source:workspace:member`.
const MEMBERS: SideTable<String, StoredMember, Named> =
    SideTable::new(&side_table::INGEST_HISTORY_SOURCE_MEMBER);

/// A member as the table keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredMember {
    name: Option<String>,
    person: Option<EntityId>,
    importer: bool,
}

fn workspace_prefix(source: HistorySource, workspace: &str) -> String {
    format!("{}:{workspace}:", source.source_id())
}

impl Vault {
    /// Keeps the members of the `workspace` of `source` as the owner mapped
    /// them for this import: each member's name, and its PERSON or none.
    /// Each import writes every member it names again, so the table holds
    /// the latest map; a member it does not name keeps its row.
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
}
