//! The typed per-model code-run heal count door (DOOR-093). It projects the
//! durable tally the executor already keeps, `Vault::code_run_model_heal_count`:
//! how many durable turns of this vault each model needed wire healing for.
//! It is not a correction receipt. The tally stores no run, turn,
//! checkpoint, repair flag or retry outcome, so the door answers none.
//!
//! Authority is the owner's live proof alone (`Memory::code_run_owner`). The
//! tally spans every run of the vault and names no caller, so no run handle
//! or run caller reads it.

mod types;

pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::ModelId;
use crate::consent::AuthenticatedOwner;

impl Memory<'_> {
    /// The CALL behind who reads the tally: the owner alone, by the
    /// caller's own proof. The proof must be live on this vault and name
    /// this handle's own human actor. The tally is an aggregate over every
    /// run, keyed by model alone, so no narrower caller can be filtered to
    /// its own share of it.
    fn code_run_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the model heal count is read as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// `vault.code.model_heal_count`: the owner reads this vault's own
    /// healed-turn tally for one model, zero when it holds none.
    ///
    /// The CALL behind the scope: the canonical tally of this vault alone,
    /// as the executor commits it with each durable turn. No off-record
    /// session overlay, other node or other vault is summed in.
    pub fn code_run_model_heal_count_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRunModelHealCountRequest,
    ) -> MemoryResult<CodeRunModelHealCountView> {
        self.code_run_owner(owner)?;
        let model = heal_count_model(input.model_id)?;
        let count = self.vault.code_run_model_heal_count(&model)?;
        Ok(CodeRunModelHealCountView {
            model_id: count.model_id,
            healed_turns: count.healed_turns,
        })
    }
}

/// The CALL behind the model a tally is read for: the exact
/// `provider/name@revision` grammar of `ModelId`, as given. Nothing is
/// trimmed, no latest revision is looked up and no provider wire label is
/// mapped to a configured model. A valid id with no tally reads as zero
/// (`Vault::code_run_model_heal_count`), never as not found.
fn heal_count_model(model_id: String) -> MemoryResult<ModelId> {
    ModelId::new(model_id).map_err(|error| {
        MemoryError::bad_request(format!(
            "model_id is not a provider/name@revision model id: {error}"
        ))
    })
}
