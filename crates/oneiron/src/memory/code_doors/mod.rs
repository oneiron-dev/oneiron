//! Typed symbol lease, proposal submit and mutation oplog doors (DOOR-137).
//! Each one projects an engine path that exists: the trusted task symbol
//! declaration, the one-file repository proposal and the durable mutation
//! oplog. None schedules a proposal behind a lease, allocates a queue entry,
//! fences a release by epoch or mints a receipt; the engine has none of them.
//!
//! Authority is the owner's live proof alone (`Memory::code_owner`). The
//! lease holder and the proposal actor are always that caller.

mod leases;
mod proposals;
mod types;

pub use types::*;

use std::collections::BTreeSet;

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

impl Memory<'_> {
    /// The CALL behind every DOOR-137 door: symbol leases, proposal submit
    /// and the oplog are owner-only. The proof must be live on this vault and
    /// name this handle's own human actor, who is then the lease holder and
    /// the proposal actor. An agent never borrows it, and no request field
    /// names a holder or an actor.
    fn code_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "symbol leases and code proposals act as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// A row the door reads or names, which the caller's credential must
    /// read, of registry kind `kind` when one is named. Absent and withheld
    /// read alike.
    fn code_readable(&self, id: EntityId, kind: Option<u8>) -> MemoryResult<()> {
        self.produced_from([id]);
        if self.get_entity(&id.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "code door record is absent or withheld",
            ));
        }
        if let Some(kind) = kind
            && self.vault.get_entity_type(&id)? != Some(kind)
        {
            return Err(MemoryError::bad_request(format!(
                "{} is not the record kind this field names",
                id.to_hex()
            )));
        }
        Ok(())
    }

    /// The CALL behind the public repository identity: `repo` is an existing
    /// CODE_ARTIFACT the caller reads, and the door uses the repo_ref stored
    /// on it. No folder path, synthetic repository or other pin is taken
    /// from the request.
    fn code_repo(&self, repo: EntityId) -> MemoryResult<RepoRef> {
        self.code_readable(repo, Some(ENTITY_TYPE_CODE_ARTIFACT))?;
        let body = self
            .vault
            .get_code_artifact(&repo)?
            .ok_or_else(|| MemoryError::not_found("code artifact not found"))?;
        Ok(RepoRef::parse(&body.repo_ref)?)
    }

    /// Where an answer lists what it derives from: each named row that
    /// still exists, once.
    fn code_listed(&self, rows: impl IntoIterator<Item = EntityId>) -> MemoryResult<()> {
        for row in rows.into_iter().collect::<BTreeSet<_>>() {
            if self.vault.get_entity_type(&row)?.is_some() {
                self.produced_from([row]);
            }
        }
        Ok(())
    }
}
