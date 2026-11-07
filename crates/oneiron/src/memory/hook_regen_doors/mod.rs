//! Typed hook regeneration doors (DOOR-077): `vault.hooks.regen.due` lists
//! the vault's own hook bindings whose contract moved under them,
//! `vault.hooks.regen.get` reads one binding's regen record, and
//! `vault.hooks.regen.adopt` enacts the candidate pending on it.
//! `vault.hooks.regen.cancel` sets a waiting decision aside,
//! `vault.hooks.regen.revert` puts back the body an adoption replaced, and
//! `vault.hooks.regen.history` reads the hook's regen receipts (FIX 4690,
//! 4691). Each one projects the engine's own operation on `Vault`; adopt
//! and revert install through the owner's own pack put.
//!
//! Authority is the owner's live proof (`Memory::hook_regen_owner`), from
//! any surface the owner is authenticated on, checked before any binding
//! resolves.

mod types;

pub use types::*;

use super::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, Memory,
    MemoryError, MemoryResult,
};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::runtime_hooks::{
    HookBodyRuntime, HookRegenActor, HookRegenCancel, HookRegenReceipt, HookRegenerator,
    MAX_HOOK_REGEN_HISTORY,
};
use crate::skill_hub::pack_catalog::{HookAuthor, PackHookBinding};
use crate::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallReceipt};
use serde::{Deserialize, Serialize};

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
                && self.get_entity_tolerant(&row.to_hex())?.value.is_none()
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
        self.produced_from_put(&put);
        Ok(put)
    }

    /// `vault.hooks.regen.cancel`: the owner sets aside the decision waiting
    /// on one binding, named as `vault.hooks.regen.get` showed it, through
    /// `Vault::cancel_hook_regen`. The hook keeps its body, and the contract
    /// the decision targeted is declined until it moves again.
    pub fn hooks_regen_cancel_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenCancelRequest,
    ) -> MemoryResult<HookRegenCancel> {
        self.hook_regen_owner(owner)?;
        if input
            .candidate_hash
            .as_deref()
            .is_some_and(|hash| !is_body_hash(hash))
        {
            return Err(MemoryError::bad_request(
                "candidate_hash is the pending candidate body's BLAKE3, 64 lowercase hex",
            ));
        }
        self.hook_regen_binding(input.binding)?;
        self.vault
            .cancel_hook_regen(owner, input.binding, input.candidate_hash.as_deref())
            .map_err(adopt_refusal)
    }

    /// `vault.hooks.regen.revert`: the owner puts back the body the last
    /// adoption on one binding replaced, through `Vault::revert_hook_regen`
    /// and the owner's own pack put. The answer is that put's own receipt:
    /// a Candidate or Blocked put installs nothing, and the record stays.
    pub fn hooks_regen_revert_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenRevertRequest,
    ) -> MemoryResult<PackPutReceipt> {
        self.hook_regen_owner(owner)?;
        if !is_body_hash(&input.adopted_hash) {
            return Err(MemoryError::bad_request(
                "adopted_hash is the adopted body's BLAKE3, 64 lowercase hex",
            ));
        }
        self.hook_regen_binding(input.binding)?;
        let put = PackPutReceipt::from(
            self.vault
                .revert_hook_regen(owner, input.binding, &input.adopted_hash)
                .map_err(adopt_refusal)?,
        );
        self.produced_from_put(&put);
        Ok(put)
    }

    /// `vault.hooks.regen.history`: one page of a binding's regen receipts,
    /// newest first, across the hook's rebinds. It changes nothing.
    pub fn hooks_regen_history_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenHistoryRequest,
    ) -> MemoryResult<Vec<HookRegenReceipt>> {
        self.hook_regen_owner(owner)?;
        self.hook_regen_binding(input.binding)?;
        let limit = input
            .limit
            .map_or(MAX_HOOK_REGEN_HISTORY, |limit| limit as usize);
        Ok(self
            .vault
            .hook_regen_history(input.binding, input.before, limit)?)
    }

    /// `vault.hooks.regen.run`, on a serving host: the owner runs one
    /// binding's intent again against this engine's contract, on the host's
    /// hook sandbox and model seat (`runtime`, `regenerator`). The decision
    /// lands on the record and in its history and enacts nothing; the
    /// answer is the record as it now stands.
    pub fn hooks_regen_run_as(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenBindingRequest,
        runtime: &dyn HookBodyRuntime,
        regenerator: &dyn HookRegenerator,
    ) -> MemoryResult<Option<HookRegenView>> {
        self.hook_regen_owner(owner)?;
        self.hook_regen_binding(input.binding)?;
        self.vault.regenerate_hook_as(
            runtime,
            regenerator,
            input.binding,
            // `hook_regen_owner` proved the owner is this door's actor.
            &HookRegenActor::Owner { actor: self.actor },
        )?;
        Ok(self
            .vault
            .hook_regen_record(input.binding)?
            .map(HookRegenView::from))
    }

    /// `vault.hooks.regen.run` on a handle with no serving host: a regen
    /// writes its body on the host's model seat, which an embedded vault
    /// does not hold.
    pub fn hooks_regen_run_unhosted(
        &self,
        owner: &AuthenticatedOwner,
        input: HookRegenBindingRequest,
    ) -> MemoryResult<Option<HookRegenView>> {
        self.hook_regen_owner(owner)?;
        self.hook_regen_binding(input.binding)?;
        Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "hook_regen_host_unavailable: a regen writes its body on the serving host's model seat",
            &["Call vault.hooks.regen.run through the server's facade, SDK or MCP door."],
        ))
    }

    /// The CALL behind the agent's own regen doors (FIX 4692): this handle is
    /// an agent's, and `binding` is a hook it authored. Any other binding is
    /// refused as unknown, never told apart.
    fn own_hook_regen_binding(&self, binding: EntityId) -> MemoryResult<()> {
        if self.actor_class != crate::EdgeActorClass::Agent {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "an agent reads and adopts the regen of its own hooks",
                &["Use vault.hooks.regen.get and vault.hooks.regen.adopt as the owner."],
            ));
        }
        let rows = self
            .vault
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, row)| {
                *id == binding
                    && matches!(&row.author, HookAuthor::Agent { agent } if *agent == self.actor)
            })
            .map(|(id, row)| binding_rows(id, &row))
            .ok_or_else(binding_unavailable)?;
        self.produced_from(rows);
        Ok(())
    }

    /// `self.hooks.regen.get`: the regen record of a hook this agent
    /// authored, with the candidate_hash its adopt names. It changes nothing.
    pub fn own_hook_regen_record(
        &self,
        input: HookRegenBindingRequest,
    ) -> MemoryResult<Option<HookRegenView>> {
        self.own_hook_regen_binding(input.binding)?;
        Ok(self
            .vault
            .hook_regen_record(input.binding)?
            .map(HookRegenView::from))
    }

    /// `self.hooks.regen.adopt`: this agent adopts the AutoAdopt regen
    /// pending on a hook it authored, named by its candidate_hash, through
    /// its own put of the `local` pack (`Vault::adopt_hook_regen_as_agent`):
    /// the hook stays its own, at its ceiling, its grant carried. A candidate
    /// whose golden replay differs waits for the owner's stamp.
    pub fn own_hook_regen_adopt(
        &self,
        input: HookRegenAdoptRequest,
    ) -> MemoryResult<PackPutReceipt> {
        if !is_body_hash(&input.candidate_hash) {
            return Err(MemoryError::bad_request(
                "candidate_hash is the pending candidate body's BLAKE3, 64 lowercase hex",
            ));
        }
        self.own_hook_regen_binding(input.binding)?;
        let agent = self.write_actor();
        let put = PackPutReceipt::from(
            self.vault
                .adopt_hook_regen_as_agent(&agent, input.binding, &input.candidate_hash)
                .map_err(adopt_refusal)?,
        );
        self.produced_from_put(&put);
        Ok(put)
    }

    /// The source a pack put staged, which its receipt names.
    fn produced_from_put(&self, put: &PackPutReceipt) {
        if let Some(source) = put
            .receipt
            .as_deref()
            .and_then(|receipt| EntityId::from_hex(&receipt.source_id).ok())
        {
            self.produced_from([source]);
        }
    }
}

/// What one pack put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackPutOutcome {
    Installed,
    /// Its code waits for its sandbox to qualify it.
    Candidate,
    /// The vault's install rules refused it; `reason` says why.
    Blocked,
}

/// `vault.packs.put`'s answer: the outcome, and the install receipt unless
/// the put was blocked.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackPutReceipt {
    pub outcome: PackPutOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Box<PackInstallReceipt>>,
}

impl From<PackInstallDisposition> for PackPutReceipt {
    fn from(disposition: PackInstallDisposition) -> Self {
        let (outcome, reason, receipt) = match disposition {
            PackInstallDisposition::Installed(receipt) => {
                (PackPutOutcome::Installed, None, Some(receipt))
            }
            PackInstallDisposition::Candidate(receipt) => {
                (PackPutOutcome::Candidate, None, Some(receipt))
            }
            PackInstallDisposition::Blocked { reason } => {
                (PackPutOutcome::Blocked, Some(reason), None)
            }
        };
        Self {
            outcome,
            reason,
            receipt,
        }
    }
}
