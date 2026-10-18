//! Typed hook regeneration doors (DOOR-077): `vault.hooks.regen.due` lists
//! the vault's own hook bindings whose contract moved under them,
//! `vault.hooks.regen.get` reads one binding's regen record, and
//! `vault.hooks.regen.adopt` enacts the candidate pending on it. Each one
//! projects the engine's own operation: `Vault::hooks_due_for_regen`,
//! `Vault::hook_regen_record` and `Vault::adopt_hook_regen`, which installs
//! through the owner's own pack put. No door runs a hook's intent again:
//! no production regenerator exists to run it.
//!
//! Authority is the owner's live proof (`Memory::hook_regen_owner`), from
//! any surface the owner is authenticated on, checked before any binding
//! resolves.

mod types;

pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::task_verb::sdk::PackPutReceipt;

/// The one refusal for a binding this caller cannot read the regen of:
/// unknown, or resting on a row this credential does not read. Neither is
/// told apart.
fn binding_unavailable() -> MemoryError {
    MemoryError::not_found("hook binding is unknown or withheld")
}

/// The rows a binding's regen stands on: the binding claim, the CODE
/// entity it names and the exact pack source its body came from.
fn binding_rows(binding: EntityId, row: &PackHookBinding) -> [EntityId; 3] {
    [binding, row.code, row.source]
}

/// A body hash as the engine writes one: BLAKE3, 64 lowercase hex.
fn is_body_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// An adoption the record refuses (no candidate pending, not the candidate
/// named, or a stamp it lacks) is a state to read again, not a bad request.
fn adopt_refusal(error: crate::Error) -> MemoryError {
    match error {
        crate::Error::InvalidConfig(reason) => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            reason,
            &["Read the binding with vault.hooks.regen.get and adopt the candidate_hash it shows."],
        ),
        other => other.into(),
    }
}

impl Memory<'_> {
    /// The CALL behind every DOOR-077 door: hook regeneration is read and
    /// adopted by the vault's owner alone. The proof must be live on this
    /// vault and name this handle's own human actor. No request field names
    /// an actor, and an agent never borrows the proof.
    fn hook_regen_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "hook regeneration is read and adopted as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// The CALL behind the human stamp (DOOR-077): the owner's own adopt
    /// call stamps a candidate whose golden replay differs. A call bound to
    /// generated code's origin carries no stamp, whatever credential it runs
    /// under; an identical fingerprint needs none.
    fn hook_regen_stamped(&self) -> bool {
        !self.writes_generated()
    }

    /// Whether this credential reads each of `rows` that exists.
    fn hook_regen_reads(&self, rows: [EntityId; 3]) -> MemoryResult<bool> {
        for row in rows {
            if self.vault.get_entity_type(&row)?.is_some()
                && self.get_entity(&row.to_hex())?.value.is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Lists the rows `binding` stands on, and refuses it unless this
    /// credential reads each of them.
    fn hook_regen_binding(&self, binding: EntityId) -> MemoryResult<()> {
        let rows = self
            .vault
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .map(|(id, row)| binding_rows(id, &row))
            .ok_or_else(binding_unavailable)?;
        self.produced_from(rows);
        if !self.hook_regen_reads(rows)? {
            return Err(binding_unavailable());
        }
        Ok(())
    }

    /// `vault.hooks.regen.due`: each binding of the vault's own packs whose
    /// last good body passed under another contract than this engine's and
    /// has no regen waiting, as `Vault::hooks_due_for_regen` finds them. A
    /// binding resting on a row this credential does not read is left out,
    /// never named.
    pub fn hooks_regen_due_as(&self, owner: &AuthenticatedOwner) -> MemoryResult<Vec<EntityId>> {
        self.hook_regen_owner(owner)?;
        let due = self.vault.hooks_due_for_regen()?;
        let mut listed = Vec::with_capacity(due.len());
        for (id, row) in self.vault.pack_hook_bindings()? {
            if !due.contains(&id) {
                continue;
            }
            let rows = binding_rows(id, &row);
            if self.hook_regen_reads(rows)? {
                self.produced_from(rows);
                listed.push(id);
            }
        }
        Ok(listed)
    }

    /// `vault.hooks.regen.get`: one binding's regen record as the engine
    /// keeps it, with the hash of the candidate waiting on it. None for a
    /// readable binding bound under no record. It changes nothing.
    pub fn hooks_regen_record_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenBindingRequest,
    ) -> MemoryResult<Option<HookRegenView>> {
        self.hook_regen_owner(owner)?;
        self.hook_regen_binding(input.binding)?;
        Ok(self
            .vault
            .hook_regen_record(input.binding)?
            .map(HookRegenView::from))
    }

    /// `vault.hooks.regen.adopt`: the owner enacts the candidate pending on
    /// one binding, named by the hash `vault.hooks.regen.get` showed,
    /// through `Vault::adopt_hook_regen` and the owner's own pack put, which
    /// revalidates the owner in its writer. The answer is that put's own
    /// receipt: a Candidate or Blocked put installs nothing, and the
    /// decision keeps waiting.
    pub fn hooks_regen_adopt_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenAdoptRequest,
    ) -> MemoryResult<PackPutReceipt> {
        self.hook_regen_owner(owner)?;
        if !is_body_hash(&input.candidate_hash) {
            return Err(MemoryError::bad_request(
                "candidate_hash is the pending candidate body's BLAKE3, 64 lowercase hex",
            ));
        }
        self.hook_regen_binding(input.binding)?;
        let put = PackPutReceipt::from(
            self.vault
                .adopt_hook_regen(
                    owner,
                    input.binding,
                    &input.candidate_hash,
                    self.hook_regen_stamped(),
                )
                .map_err(adopt_refusal)?,
        );
        // The source the put staged, which its receipt names.
        if let Some(source) = put
            .receipt
            .as_deref()
            .and_then(|receipt| EntityId::from_hex(&receipt.source_id).ok())
        {
            self.produced_from([source]);
        }
        Ok(put)
    }
}
