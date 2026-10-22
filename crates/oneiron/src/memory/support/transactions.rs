//! Write plumbing: owner authorship, host origin, claim envelopes and actor-verified write txns.
//! `Memory::with_verified_actor_write_txn` and its content-write sibling are its call surface.
//! `memory::support` defines `Memory` and `HostWriteOrigin`.

use super::*;

impl Memory<'_> {
    /// The owner authorship of a claim write in `txn`, revalidated there.
    ///
    /// A surface bound to a host origin or a machine signer writes for
    /// someone else, so it authors nothing as the owner.
    pub(in crate::memory) fn owner_authored_write_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Option<crate::consent::OwnerAuthoredWrite>> {
        let Some(owner) = &self.owner_authorship else {
            return Ok(None);
        };
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return Ok(None);
        }
        if owner.revalidate_in_txn(self.vault, txn)? != self.actor
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(crate::Error::Gate(
                crate::error::GateError::ConsentOwnerNotAuthenticated(
                    "owner proof does not name this surface's actor",
                ),
            ));
        }
        owner.owner_authored_write_in_txn(self.vault, txn).map(Some)
    }

    /// The owner proof a host bound ([`Self::with_owner_authorship`]), for a
    /// door that revalidates it itself; `None` on a surface that writes for
    /// someone else.
    pub(crate) fn owner_authorship(&self) -> Option<&crate::consent::AuthenticatedOwner> {
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return None;
        }
        self.owner_authorship.as_ref()
    }

    /// Where the owner's request reached this install
    /// ([`Self::with_owner_surface`]), for the audit record of his act:
    /// this install's own on a surface that writes for someone else, as
    /// [`Self::owner_authorship`] binds no proof there.
    pub(crate) fn owner_surface(&self) -> crate::authority::ActSurface {
        if self.host_origin.is_some() || self.machine_signer.is_some() {
            return crate::authority::ActSurface::ThisInstall;
        }
        self.owner_surface
    }

    /// Binds this surface's claim writes to a host-owned origin: every claim
    /// door then stamps the origin's source, lineage and provenance, and the
    /// caller's declared source is not read. Approval still follows from that
    /// source and the gate decides.
    #[must_use]
    pub fn with_host_origin(mut self, origin: HostWriteOrigin) -> Self {
        if let Some(binding) = &origin.task_host {
            self.task_host = Some(binding.clone());
        }
        if let Some(ask) = origin.hook_ask {
            self.hook_ask = Some(ask);
        }
        // A turn program's waking slip binds the surface its call reaches
        // (FIX 8717): its reads take the slip's key, its claim writes the
        // slip's position check.
        if let Some(proof) = &origin.read_proof {
            self.read_proof = Some(proof.clone());
        }
        self.host_origin = Some(origin);
        self
    }

    /// The model provider the host's origin names for this call (OF-560):
    /// the one its ladder served the calling program's turn from. `None` for
    /// a caller no host-run model drives, such as an external HTTP or MCP
    /// agent.
    #[must_use]
    pub fn model_provider(&self) -> Option<&str> {
        self.host_origin
            .as_ref()
            .and_then(HostWriteOrigin::model_provider)
    }

    /// Whether a host bound this surface to generated code's origin. Such a
    /// surface never speaks, answers or assigns in a person's name.
    pub(crate) fn writes_generated(&self) -> bool {
        self.host_origin
            .as_ref()
            .is_some_and(|origin| origin.source() == ClaimSource::Generated)
    }

    /// The source a claim door writes: the bound origin's, else the caller's.
    pub(in crate::memory) fn claim_source(&self, declared: &str) -> MemoryResult<ClaimSource> {
        match &self.host_origin {
            Some(origin) => Ok(origin.source()),
            None => super::claims::parse_claim_source(declared),
        }
    }

    /// The envelope a claim door writes under: the bound origin's, else the
    /// facade's own provenance for `verb` over the caller's `source`.
    pub(in crate::memory) fn claim_envelope(
        &self,
        source: ClaimSource,
        verb: &str,
        approval: ClaimApprovalStatus,
    ) -> crate::Result<crate::WriteEnvelope> {
        match self.host_envelope(approval)? {
            Some(envelope) => Ok(envelope),
            None => Ok(crate::WriteEnvelope::new(
                crate::WriteActor::new(self.actor, self.actor_class),
                source,
                crate::WriteProvenance::new(facade_provenance(verb))?,
                approval,
            )),
        }
    }

    /// The bound origin's envelope at `approval`, for a writer that stamps its
    /// own source and provenance when no origin is bound.
    pub(crate) fn host_envelope(
        &self,
        approval: ClaimApprovalStatus,
    ) -> crate::Result<Option<crate::WriteEnvelope>> {
        let Some(origin) = &self.host_origin else {
            return Ok(None);
        };
        if origin.envelope.actor() != crate::WriteActor::new(self.actor, self.actor_class) {
            return Err(Error::InvalidClaimBody(
                "host write origin does not match bound facade",
            ));
        }
        Ok(Some(origin.envelope.clone().with_approval(approval)))
    }

    /// The room turn this handle is bound to, if any.
    pub(crate) fn room_turn(&self) -> Option<&crate::claim::RoomTurnCeiling> {
        self.room_turn.as_ref()
    }

    /// What a verb hook's ask saves so settlement runs this call again as its
    /// caller, with no credential (ARCH-0080 §3 Ask): the sitting, the room
    /// turn's room, where the caller reads from, the transport mark, the
    /// origin conversation and the host action, beside the actor, class and
    /// invocation the ask keeps. The drain takes its own task-work turn, and
    /// the credential instrument and door name nothing without a credential.
    /// `None` when this surface holds what only its host could rebuild: a
    /// credential, read proof, slip or task grant, a thread's turn, owner
    /// authorship, a host origin, a machine signer, a producer list, a birth
    /// position, a TASK host, a decision path, an off-record session or a
    /// door's rewrite admission. Where the caller sits decides nothing here.
    /// An owner surface ([`Self::with_owner_surface`]) does not stop a plain
    /// resume: the target keeps it, and the rebuilt handle records it, for
    /// audit only (FIX 5364).
    /// `None` resumes only on the caller's retry.
    pub(crate) fn plain_resume(&self) -> Option<crate::runtime_hooks::verb::PlainRowResume> {
        let rebuilt = !self.credential
            && self.read_proof.is_none()
            && self.invocation_slip.is_none()
            && self.task_grant.is_none()
            && self
                .room_turn
                .as_ref()
                .is_none_or(|turn| turn.branch.is_none())
            && self.owner_authorship.is_none()
            && self.host_origin.is_none()
            && self.machine_signer.is_none()
            && self.producers.is_none()
            && self.birth_position == crate::federation::record_scope::BirthPosition::default()
            && self.task_host.is_none()
            && self.task_decisions.is_none()
            && self.off_record_session.is_none()
            && self.rewrite_admit.is_none();
        rebuilt.then(|| {
            crate::runtime_hooks::verb::PlainRowResume::of(
                self.session_key,
                self.room_turn.as_ref().map(|turn| turn.room),
                self.locality,
                self.transport_invocation,
                self.origin_conversation,
                self.host_action.as_ref(),
                self.owner_surface,
            )
        })
    }

    /// The bound actor entity id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    /// One actor-bound content writer. Its interface exposes read-only
    /// observation and typed content programs; ordinary content cannot take
    /// a raw mutable transaction from this entry.
    pub(crate) fn with_actor_content_write_txn<T>(
        &self,
        write: impl FnOnce(&mut crate::federation::ActorContentTxn<'_, '_, '_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.with_actor_content_write_txn_as(
            crate::WriteActor::new(self.actor, self.actor_class),
            write,
        )
    }

    /// Preserve the observed authority frontier when a typed Vault NOTE door
    /// is called with an already-bound WriteActor rather than the facade's
    /// ordinary actor pair.
    pub(crate) fn with_actor_content_write_txn_as<T>(
        &self,
        actor: crate::WriteActor,
        write: impl FnOnce(&mut crate::federation::ActorContentTxn<'_, '_, '_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        if actor.entity_ref() != self.actor || actor.actor_class() != self.actor_class {
            return Err(
                Error::InvalidClaimBody("content actor does not match bound facade").into(),
            );
        }
        self.vault.try_with_write_txn_grouped(|wtxn| {
            verify_actor_binding_in_txn(self.vault, wtxn, self.actor, self.actor_class)?;
            let mut content = crate::federation::ActorContentTxn::new(self.vault, wtxn, actor)?;
            let result = write(&mut content)?;
            content.finish()?;
            Ok(result)
        })
    }

    /// Legacy domain-specific actor writes that do not yet expose a resolved
    /// record position require a full content-write grant in a shared vault.
    /// A scoped writer uses `with_actor_content_write_txn` and its typed
    /// effects instead. No caller may use raw access to bypass membership.
    pub(crate) fn with_verified_actor_write_txn<T>(
        &self,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.with_verified_actor_write_txn_as(crate::store::Callback::Audited, write)
    }

    /// [`Self::with_verified_actor_write_txn`] through the door `callback`
    /// names: a write that runs host code in its transaction is
    /// [`crate::store::Callback::Opaque`].
    pub(crate) fn with_verified_actor_write_txn_as<T>(
        &self,
        callback: crate::store::Callback,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.vault.write_txn_door(callback, |wtxn| {
            self.verify_actor_write_in_txn(wtxn)?;
            write(wtxn)
        })
    }

    /// The actor checks [`Self::with_verified_actor_write_txn_as`] runs in its
    /// transaction, for a writer that must run its own check before them.
    pub(crate) fn verify_actor_write_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        verify_actor_binding_in_txn(self.vault, txn, self.actor, self.actor_class)?;
        if let Some(creation) = self.vault.shared_vault_creation_in_txn(txn)? {
            self.vault.authorize_shared_vault_write_in_txn(
                txn,
                creation.vault_id,
                &crate::WriteActor::new(self.actor, self.actor_class),
                &crate::federation::SharedVaultWrite::Content(crate::federation::Scope::top()),
            )?;
        }
        Ok(())
    }
}
