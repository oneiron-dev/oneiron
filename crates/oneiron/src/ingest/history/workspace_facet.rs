//! The facet a shared workspace's import lands its TURNs under (Engine
//! rulings L2-18-WORKSPACE-SCOPE = A and L2-18-WORKSPACE-FACET-CARRIER = A,
//! 15 Nov): one FACET per workspace, named after it and worn by the importer,
//! made by the first import and found again by name by every later one.
//!
//! A facet is a mask: it grants nothing and never limits the owner
//! (ARCH-0022 #facet-read-ruling), so who reads the rows stays the source
//! policy's alone. The facet names the workspace as one group, and a
//! credential that opted into it reads that workspace's TURNs. Only the TURN
//! carries it: the FacetOf table admits no CONVERSATION or MESSAGE
//! (ONE-1645), so those keep their substrate facet, as for every source.

use super::sharing;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

impl Vault {
    /// The FACET named `workspace` that the importer wears: the one an
    /// earlier import of that workspace made, else a new one made now, at
    /// `at`. `None` when the importer stands for no live PERSON, since a
    /// facet's wearer is one; the import then lands its TURNs under the vault
    /// default.
    ///
    /// # Errors
    ///
    /// A blank or over-long name, an owner proof that no longer holds, or a
    /// failure of the vault itself.
    pub fn history_import_facet(
        &self,
        owner: &AuthenticatedOwner,
        workspace: &str,
        at: u64,
    ) -> MemoryResult<Option<EntityId>> {
        let actor = owner.revalidate(self)?;
        Ok(match self.importer_facet(actor, workspace)? {
            None => None,
            Some((_, Some(facet))) => Some(facet),
            Some((person, None)) => Some(self.create_facet(owner, person, workspace, at)?),
        })
    }

    /// The live PERSON the importing `actor` stands for, and the FACET of
    /// that name it already wears, if any.
    fn importer_facet(
        &self,
        actor: EntityId,
        name: &str,
    ) -> Result<Option<(EntityId, Option<EntityId>)>> {
        let txn = self.store.env.read_txn()?;
        let Some(person) = sharing::importer_person_in(self, &txn, actor)? else {
            return Ok(None);
        };
        if !sharing::live_person_in(self, &txn, &person)? {
            return Ok(None);
        }
        Ok(Some((
            person,
            self.worn_facet_named_in_txn(&txn, &person, name)?,
        )))
    }
}
