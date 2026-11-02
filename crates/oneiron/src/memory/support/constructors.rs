//! Handle construction: the vault's `Memory` openers and the room-turn and task rebinders.
//! `Vault::memory` and `Vault::memory_signed_machine` are its call surface.
//! `memory::support` defines `Memory` and its fields.

use super::*;

impl Vault {
    /// Binds this vault's [`Memory`] surface to an actor. The actor entity
    /// must exist and match the class (PERSON for human/agent, MACHINE for
    /// system) by the time a gated write runs — the engine enforces this per
    /// write.
    ///
    /// `actor_class` is not a convenience the caller may drop: it is half of
    /// what the store-truth check verifies, and the two are bound together
    /// here so no verb can be reached without both.
    #[must_use]
    pub fn memory(&self, actor: EntityId, actor_class: EdgeActorClass) -> Memory<'_> {
        Memory {
            vault: self,
            actor,
            actor_class,
            session_key: None,
            machine_signer: None,
            read_proof: None,
            host_action: None,
            room_turn: None,
            host_origin: None,
            locality: crate::claim::CallerLocality::OnDevice,
            destination: crate::settings::ReadDestination::on_device(),
            producers: None,
            birth_position: Default::default(),
            owner_authorship: None,
            owner_surface: crate::authority::ActSurface::ThisInstall,
            host_slip_issuer: None,
            invocation: None,
            hook_ask: None,
            invocation_slip: None,
            transport_invocation: false,
            task_grant: None,
            kept_requester: None,
            origin_conversation: None,
            task_host: None,
            task_decisions: None,
            off_record_session: None,
            credential: false,
            credential_instrument: None,
            attested_owner: None,
            credential_door: None,
            rewrite_admit: None,
            task_work_turn: None,
            external_git_source_host: None,
            repo_tool_recipient: crate::origin::secret_projection::RepoToolRecipient::OFF,
        }
    }

    /// Binds a MACHINE's claim writes to its enrolled software signing key.
    /// Transport authentication alone cannot supply this proof. Other memory
    /// verbs remain subject to their own authorization and write doors.
    ///
    /// The surface's claim and key-value writes call `sign` inside the vault's
    /// write transaction, which may be one group commit shared with other
    /// writes. `sign` must only sign: it must not call into this vault or wait
    /// on anything a vault caller can hold while it writes, or the vault's
    /// writer deadlocks.
    #[must_use]
    pub fn memory_signed_machine<'a>(
        &'a self,
        machine: EntityId,
        public_key: [u8; 32],
        sign: &'a (dyn Fn(&[u8]) -> crate::Result<[u8; 64]> + Send + Sync),
    ) -> Memory<'a> {
        Memory {
            vault: self,
            actor: machine,
            actor_class: EdgeActorClass::System,
            session_key: None,
            machine_signer: Some((public_key, sign)),
            read_proof: None,
            host_action: None,
            room_turn: None,
            host_origin: None,
            locality: crate::claim::CallerLocality::OnDevice,
            destination: crate::settings::ReadDestination::on_device(),
            producers: None,
            birth_position: Default::default(),
            owner_authorship: None,
            owner_surface: crate::authority::ActSurface::ThisInstall,
            host_slip_issuer: None,
            invocation: None,
            hook_ask: None,
            invocation_slip: None,
            transport_invocation: false,
            task_grant: None,
            kept_requester: None,
            origin_conversation: None,
            task_host: None,
            task_decisions: None,
            off_record_session: None,
            credential: false,
            credential_instrument: None,
            attested_owner: None,
            credential_door: None,
            rewrite_admit: None,
            task_work_turn: None,
            external_git_source_host: None,
            repo_tool_recipient: crate::origin::secret_projection::RepoToolRecipient::OFF,
        }
    }
}

impl<'v> Memory<'v> {
    /// Opens this actor's turn in `room` (ARCH-0067 §8). The engine reads the
    /// roster from the room's own record and each member's grants; the caller
    /// supplies only the room. Every read through the returned turn runs
    /// inside `room_scope(roster)` for the current roster and passes the
    /// all-of-audience rule and every member's own read. The turn only
    /// narrows: every check the actor's reads already make still runs.
    pub fn for_room_turn(&self, room: EntityId) -> MemoryResult<super::RoomTurnHandle<'v>> {
        self.verified_actor_class()?;
        self.require_room_in_facets(room)?;
        let ceiling = match self.room_turn_now()? {
            Some(now) if now.room == room => now,
            Some(_) => {
                return Err(MemoryError::bad_request_with(
                    "room differs from the bound room turn",
                    &[],
                ));
            }
            None => self.room_ceiling(room)?,
        };
        Ok(super::RoomTurnHandle {
            memory: Memory {
                vault: self.vault,
                actor: self.actor,
                actor_class: self.actor_class,
                session_key: self.session_key,
                machine_signer: self.machine_signer,
                read_proof: self.read_proof.clone(),
                host_action: self.host_action.clone(),
                room_turn: Some(ceiling),
                host_origin: self.host_origin.clone(),
                locality: self.locality,
                destination: self.destination.clone(),
                producers: self.producers,
                birth_position: self.birth_position,
                // A room turn writes into the room's talk, not as the owner
                // in person.
                owner_authorship: None,
                owner_surface: crate::authority::ActSurface::ThisInstall,
                host_slip_issuer: None,
                // The same logical verb, run inside the turn.
                invocation: self.invocation,
                hook_ask: self.hook_ask,
                invocation_slip: self.invocation_slip.clone(),
                transport_invocation: self.transport_invocation,
                task_grant: self.task_grant,
                kept_requester: self.kept_requester.clone(),
                origin_conversation: self.origin_conversation,
                task_host: self.task_host.clone(),
                task_decisions: self.task_decisions.clone(),
                off_record_session: self.off_record_session.clone(),
                credential: self.credential,
                credential_instrument: self.credential_instrument.clone(),
                attested_owner: self.attested_owner,
                credential_door: self.credential_door.clone(),
                rewrite_admit: self.rewrite_admit.clone(),
                task_work_turn: self.task_work_turn.clone(),
                // A call's import transport never crosses into a turn.
                external_git_source_host: None,
                repo_tool_recipient: self.repo_tool_recipient.clone(),
            },
        })
    }

    /// Binds the host's decision path for the task surface's questions
    /// (OF-533): a post's take question and a report's done and ask-up
    /// questions then go through its ladder instead of asking up. A model
    /// rung may block on the host's runtime, so a host binds it only on a
    /// blocking thread. It grants nothing: decide() advises, and every check
    /// still runs.
    #[must_use]
    pub fn with_task_decisions(mut self, decisions: crate::task_verb::TaskDecisions<'v>) -> Self {
        self.task_decisions = Some(std::sync::Arc::new(decisions));
        self
    }

    /// The task surface's decision path a host bound, if any.
    pub(crate) fn task_decisions(&self) -> Option<&crate::task_verb::TaskDecisions<'v>> {
        self.task_decisions.as_deref()
    }

    /// Binds the host's own slip issuer, the key that signs a Connect pact's
    /// disconnect (FIX 3875). A delete the owner makes in person through this
    /// surface ([`Self::with_owner_authorship`]) then withdraws each live
    /// Connect guest grant naming the PERSON it deletes, before the delete
    /// scrubs or publishes. A surface without it deletes as before.
    #[must_use]
    pub fn with_host_slip_issuer(mut self, issuer: &'v crate::authority::HostSlipIssuer) -> Self {
        self.host_slip_issuer = Some(issuer);
        self
    }
}
