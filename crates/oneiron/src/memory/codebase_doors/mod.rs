//! Typed code snapshot doors (DOOR-118): the import of one committed local
//! Git tree, its pinned manifest, its frozen source bytes and exact-name Rust
//! symbol definitions within it. Each projects an engine path that exists;
//! none registers a repository, enforces an editable whitelist, grants repo
//! membership, mints a receipt or answers a calls, imports or refs query.
//!
//! Authority is the owner's live proof alone (`Memory::codebase_owner`),
//! checked before any id resolves, so a refusal is no existence oracle.
//! Every read then goes through this credential-bound handle.

mod snapshots;
mod symbols;
mod types;

pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::codebase::CodebaseSnapshotMount;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

impl Memory<'_> {
    /// The CALL behind every DOOR-118 door: codebase snapshot doors are
    /// owner-only (the caller's own owner proof). The proof must be live on
    /// this vault and name this handle's own human actor. A delegated reader
    /// waits for real repo membership; it never borrows the owner.
    fn codebase_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "code snapshot doors act as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// A row the answer is read from, which the caller's credential must read.
    /// `false` when it is absent or withheld; both read the same.
    fn codebase_readable(&self, id: EntityId) -> MemoryResult<bool> {
        self.produced_from([id]);
        Ok(self.get_entity_tolerant(&id.to_hex())?.value.is_some())
    }

    /// The CALL behind the snapshot selector: `repo` is the imported
    /// CODE_ARTIFACT and `snapshot` its fork hash in 64 lower-hex characters.
    /// The mount is of exactly that artifact; a fork hash that no longer
    /// matches refuses, and nothing re-resolves by repository, project or
    /// newest import. `None` when the artifact is absent or withheld.
    fn codebase_pinned(
        &self,
        repo: EntityId,
        snapshot: &str,
    ) -> MemoryResult<Option<CodebaseSnapshotMount<'_>>> {
        if snapshot.len() != 64
            || !snapshot
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MemoryError::bad_request(
                "snapshot must be the fork hash, 64 lower-hex characters",
            ));
        }
        if !self.codebase_readable(repo)?
            || self.vault.get_entity_type(&repo)? != Some(ENTITY_TYPE_CODE_ARTIFACT)
        {
            return Ok(None);
        }
        let Some(mount) = self.vault.mount_codebase_snapshot(&repo)? else {
            return Ok(None);
        };
        if bytes_to_hex_lower(&mount.snapshot().fork_hash) != snapshot {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "this code artifact no longer holds the pinned snapshot",
                &["Name the repo and snapshot an import returned."],
            ));
        }
        Ok(Some(mount))
    }
}
