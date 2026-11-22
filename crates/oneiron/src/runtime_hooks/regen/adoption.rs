//! Enacting a hook's pending regen (ARCH-0080 §8): the owner's adopt and the
//! agent adopts, each through its own put of the hook's pack.

use super::*;

impl Vault {
    /// Enacts `binding`'s pending regen as the owner: the candidate replaces
    /// the hook's body in its pack, through the owner's own put, or, for a
    /// hook an agent authored, through that agent's own put of the `local`
    /// pack, so the hook stays the agent's, at its ceiling, its grant carried
    /// (FIX 4692). `candidate_hash` names the candidate its caller read
    /// ([`HookRegenRecord::candidate_hash`]); only that pending candidate
    /// enacts. An AutoAdopt needs no question; a NeedsHumanStamp adopts only
    /// with `stamped`, the owner's stamp. Only a put that installs the
    /// candidate advances the record, to the new body under the target
    /// contract. A Candidate or Blocked put leaves the last good body and the
    /// pending decision as they were, and is answered as it is.
    ///
    /// # Errors
    ///
    /// No regen is pending, it is not the candidate named, or it needs a
    /// stamp it lacks; and the put's own refusals.
    pub fn adopt_hook_regen(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        candidate_hash: &str,
        stamped: bool,
    ) -> Result<PackInstallDisposition> {
        let actor = owner.revalidate(self)?;
        self.enact_hook_regen(
            HookPut::Owner(owner),
            &HookRegenActor::Owner { actor },
            binding,
            candidate_hash,
            stamped,
        )
    }

    /// Enacts the regen pending on a hook `agent` authored, as that agent,
    /// through its own put of the `local` pack (FIX 4692): the hook stays the
    /// agent's, at its ceiling, its grant carried. An agent carries no
    /// owner's stamp, so only an AutoAdopt enacts; a candidate whose golden
    /// replay differs waits for the owner.
    ///
    /// # Errors
    ///
    /// A hook the agent did not author, no AutoAdopt pending or not the one
    /// named, and the put's own refusals.
    pub fn adopt_hook_regen_as_agent(
        &self,
        agent: &WriteActor,
        binding: EntityId,
        candidate_hash: &str,
    ) -> Result<PackInstallDisposition> {
        self.enact_hook_regen(
            HookPut::Agent {
                agent: *agent,
                owner: None,
                admit: None,
            },
            &HookRegenActor::Agent {
                agent: agent.entity_ref(),
            },
            binding,
            candidate_hash,
            false,
        )
    }

    /// Enacts the regen pending on a hook a resident agent authored, as a
    /// granted agent that is not necessarily its author (restriction wave 7,
    /// C41): through the AUTHORING agent's own put of the `local` pack, as
    /// the engine's own pass puts it, so the hook stays its author's, at its
    /// ceiling, its grant carried — never through the enactor's put, which
    /// would rebind the hook as its own. The receipt names the enacting
    /// agent. The enactor carries no owner's stamp, so only an AutoAdopt
    /// enacts; a candidate whose golden replay differs waits for the owner.
    /// A hook of any other author is refused: its put is the owner's, and no
    /// owner proof is held here. `admit` is the enactor's admission, run
    /// again in the writer before the put, so a grant, setting or credential
    /// that lapsed after the caller's own check installs nothing.
    ///
    /// # Errors
    ///
    /// An unknown binding, a hook no resident agent authored, no AutoAdopt
    /// pending or not the one named, `admit`'s refusal, and the put's own
    /// refusals.
    pub fn adopt_hook_regen_as_granted_agent(
        &self,
        agent: &WriteActor,
        binding: EntityId,
        candidate_hash: &str,
        admit: &dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<PackInstallDisposition> {
        let Some((_, row)) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
        else {
            return Err(Error::EntityNotFound);
        };
        let HookAuthor::Agent { agent: author } = row.author else {
            return Err(Error::InvalidConfig(
                "a granted agent adopts the regen of a hook a resident agent authored; this hook's regen is the owner's adopt"
                    .to_owned(),
            ));
        };
        self.enact_hook_regen(
            HookPut::Agent {
                agent: WriteActor::new(author, EdgeActorClass::Agent),
                owner: None,
                admit: Some(admit),
            },
            &HookRegenActor::Agent {
                agent: agent.entity_ref(),
            },
            binding,
            candidate_hash,
            false,
        )
    }
}
