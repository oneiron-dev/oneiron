//! Handle binders: the `with_*` methods and the accessors that read back what a binder set.
//! `Memory::with_session` and its sibling `with_*` methods are its call surface.
//! `memory::support` defines `Memory`, `RewriteAdmit` and the fields these set.

use super::*;

impl Memory<'_> {
    /// Bind witnessed turns to the host's actor/machine sitting. This is
    /// context, not authority: ordinary actor and write checks still apply.
    #[must_use]
    pub fn with_session(mut self, key: crate::session_lifecycle::SessionKey) -> Self {
        self.session_key = Some(key);
        self
    }

    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    /// Binds the vault task-work turn a host already holds for this
    /// operation (Rule 5): the surface's task work runs on it and never waits
    /// in the line again. A host that waited for the turn passes that one.
    #[must_use]
    pub fn with_task_work_turn(
        mut self,
        turn: std::sync::Arc<crate::work_line::TaskWorkTurn>,
    ) -> Self {
        self.task_work_turn = Some(turn);
        self
    }

    /// The task-work turn this surface's operation holds, if it holds one:
    /// a surface the operation builds for another actor binds the same turn
    /// ([`Self::with_task_work_turn`]) rather than waiting for a second one.
    #[must_use]
    pub fn task_work_turn(&self) -> Option<std::sync::Arc<crate::work_line::TaskWorkTurn>> {
        self.task_work_turn.clone()
    }

    /// Whether this surface's operation holds its task-work turn already.
    pub(crate) fn has_task_work_turn(&self) -> bool {
        self.task_work_turn.is_some()
    }

    /// This surface holding its operation's task-work turn: the one it
    /// holds, else the actor's next turn in the vault's line, waited for on
    /// this thread. Take it at the operation's outer entry, before any
    /// transaction; nested task work then reuses it.
    #[must_use]
    pub(crate) fn task_work_memory(&self) -> Self {
        let mut memory = self.clone();
        if memory.task_work_turn.is_none() {
            memory.task_work_turn = Some(std::sync::Arc::new(
                self.vault.admit_task_work_blocking(self.actor),
            ));
        }
        memory
    }

    /// Binds this surface's reads to the verified credential the actor
    /// presented (ONE-1187-D6: a render read runs under the principal's
    /// already-held key). Every read verb then reads under the key that proof
    /// builds, never a broader one — not even the owner's. The proof's holder
    /// must be the bound actor; a read refuses otherwise.
    #[must_use]
    pub fn with_read_proof(mut self, proof: &crate::authority::VerifiedSlip) -> Self {
        self.read_proof = Some(proof.clone());
        self
    }

    /// Marks this surface's claim writes as made in person by the vault's
    /// authenticated owner: owner-authored writes carry their own
    /// confirmation, so a critical claim they land attaches no confirm.
    ///
    /// A host binds it only for a request the owner made directly, through a
    /// door that authenticated the owner (an unattenuated owner credential or
    /// the native owner door). An agent's, a room turn's or an import's write
    /// never carries it. Each claim write revalidates the proof as the vault's
    /// owner in its own transaction and refuses when it no longer holds; the
    /// proof's actor must be this surface's actor, as a human.
    #[must_use]
    pub fn with_owner_authorship(mut self, owner: &crate::consent::AuthenticatedOwner) -> Self {
        self.owner_authorship = Some(owner.clone());
        self
    }

    /// Binds where the owner's request reached this install, as the host
    /// verified it on that request (FIX 4650): the hosted console, a linked
    /// machine its connection proved, or this install. An owner act this
    /// surface records carries it, for audit and receipts only. No rule reads
    /// it, so it grants, proves and admits nothing, and a host never takes it
    /// from the request's input. A surface without it records this install.
    #[must_use]
    pub fn with_owner_surface(mut self, surface: crate::authority::ActSurface) -> Self {
        self.owner_surface = surface;
        self
    }

    /// Binds the logical verb's id a transport carried in, so a verb hook
    /// fires once for it however many wrappers it crosses.
    #[must_use]
    pub fn with_invocation(mut self, invocation: crate::runtime_hooks::InvocationId) -> Self {
        self.invocation = Some(invocation);
        self
    }

    /// Binds the ask handle of the hook pause a transport's call names as
    /// the one it resumes (`x-oneiron-hook-ask`, MCP `_meta.hook_ask`; L13
    /// PR-D, FIX 4283), beside its invocation. It grants nothing: a pause
    /// the call's session no longer holds refuses instead of running as a
    /// new call.
    #[must_use]
    pub fn with_hook_ask(mut self, ask: EntityId) -> Self {
        self.hook_ask = Some(ask);
        self
    }

    /// The hook pause this surface's call names as the one it resumes.
    pub(crate) fn hook_ask(&self) -> Option<EntityId> {
        self.hook_ask
    }

    /// Binds the signed instrument the caller's request was admitted on.
    /// Work this surface queues carries it, and that work's standing is the
    /// slip's own when it runs: verified again then, a revoked slip stops it.
    #[must_use]
    pub fn with_invocation_slip(
        mut self,
        binding: &crate::authority::InvocationSlipBinding,
    ) -> Self {
        self.invocation_slip = Some(binding.clone());
        self
    }

    /// The signed instrument a host bound, if any.
    pub(crate) fn invocation_slip(&self) -> Option<&crate::authority::InvocationSlipBinding> {
        self.invocation_slip.as_ref()
    }

    /// The code-mode call site the bound origin carries, if any (DOOR-079
    /// 1a): only the dispatcher puts one there.
    pub(crate) fn code_consent_site(&self) -> Option<&crate::code_run::CodeConsentCallSite> {
        self.host_origin.as_ref()?.code_consent.as_ref()
    }

    /// The original caller a code consent wait keeps (DOOR-079 1a): this
    /// surface's actor and, when its host bound one, the exact instrument its
    /// request was admitted on, with the door it came in by. Every caller
    /// shape that reaches a dispatcher is kept as it is: an embedded or host
    /// surface keeps no credential, and its grant alone limits the settle. It
    /// reads neither where the caller sits nor the hook-only rebuild rule.
    pub(crate) fn code_consent_principal(&self) -> crate::code_run::CodeConsentPrincipal {
        crate::code_run::CodeConsentPrincipal {
            actor_ref: self.actor,
            credential: self.invocation_slip.clone().map(|witness| {
                crate::code_run::CodeConsentSavedCredential {
                    instrument: self.credential_instrument.clone(),
                    door: self.credential_door.clone(),
                    witness,
                }
            }),
            opener_slip: None,
        }
    }

    /// Marks this surface as a transport caller's, with a slip or without
    /// one, on loopback as off the device. It only narrows: no call clears it.
    #[must_use]
    pub fn with_transport_invocation(mut self) -> Self {
        self.transport_invocation = true;
        self
    }

    /// Whether the in-process host itself holds this surface: no transport
    /// reached it and no credential (slip, read proof or task grant) is
    /// bound to it.
    pub(crate) fn native_invocation(&self) -> bool {
        !self.transport_invocation
            && self.invocation_slip.is_none()
            && self.read_proof.is_none()
            && self.task_grant.is_none()
    }

    /// Binds the ask guest's grant a host admitted for this surface's actor
    /// ([`Vault::admit_ask_guest_grant`]). Its task verbs then prove the
    /// actor by that grant, checked again on every verb, so a withdrawn or
    /// lapsed grant stops them; a grant whose member is not the bound actor
    /// proves nothing. Like a slip it is a credential: the surface is no
    /// longer the host's own, and room turns and clones keep it.
    #[must_use]
    pub fn with_task_grant(mut self, grant: &crate::authority::AdmittedTaskGrant) -> Self {
        self.task_grant = Some(*grant);
        self
    }

    /// Binds the conversation whose request started this surface's work
    /// (OF-221). A host binds it only from the authenticated request that
    /// actually started the work, never from caller text, a selected room or
    /// a transcript. A root TASK this surface creates keeps it, through
    /// approval and wave planning, and the agent that realizes it carries it
    /// as its dispatch origin; a child always takes its parent's instead. It
    /// grants nothing.
    #[must_use]
    pub fn with_origin_conversation(mut self, id: EntityId) -> Self {
        self.origin_conversation = Some(id);
        self
    }

    /// Binds the off-record session the host's request names (its
    /// `x-oneiron-session`) for this surface's principal, the request's own:
    /// context, not authority. Inside one the live registry holds anonymous
    /// and that principal is verified in (its room's roster, or the actor
    /// who entered it alone), a reference refusal or an unlinked prose link
    /// is refused or unlinked as anywhere else but writes no receipt
    /// (OF-063, Engine ruling 10-17, matching OF-538's call receipts). Every
    /// other caller writes its receipts as anywhere else, and so does one
    /// with no principal: it binds no session (Engine ruling 2137/2271).
    /// Every authenticated host or embedded surface that writes for a
    /// principal binds the session its caller names here (FIX 1668): the
    /// server's transport handles through `credential_memory`, an embedded
    /// host's for its app host's principal, the actor it bound.
    #[must_use]
    pub fn in_off_record_session(mut self, session_ref: &str) -> Self {
        self.off_record_session = Some(session_ref.trim().to_owned());
        self
    }

    /// Whether this surface's call sits in an anonymous off-record session
    /// its principal is verified in, which keeps no record: the one signal
    /// OF-538's call receipts read
    /// ([`Vault::off_record_session_is_anonymous_for`]), judged now, when a
    /// receipt would be written, not when the session was bound.
    ///
    /// The principal is the one the bound credential names (its holder,
    /// the same one the transports' call receipts compare), or none for the
    /// host root, which names no person and so binds no session; a surface
    /// no credential is bound to calls for its bound actor, the principal its
    /// host authenticated (an embedded app host's, MCP's configured root's
    /// registered actor).
    pub(crate) fn keeps_no_record(&self) -> bool {
        self.off_record_session.as_deref().is_some_and(|session| {
            let principal = match &self.read_proof {
                Some(proof) => EntityId::from_hex(&proof.claims().holder_ref).ok(),
                None => Some(self.actor),
            };
            self.vault
                .off_record_session_is_anonymous_for(session, principal)
        })
    }

    /// The off-record session this surface binds and the principal it binds
    /// it for, as [`Self::keeps_no_record`] reads them: where a call that
    /// keeps no record keeps its verb hooks' records (FIX 4283). `None` when
    /// it binds no session.
    pub(crate) fn off_record_binding(&self) -> Option<(&str, Option<EntityId>)> {
        let session = self.off_record_session.as_deref()?;
        let principal = match &self.read_proof {
            Some(proof) => EntityId::from_hex(&proof.claims().holder_ref).ok(),
            None => Some(self.actor),
        };
        Some((session, principal))
    }

    /// The logical verb's id a host bound, if any.
    #[must_use]
    pub fn invocation(&self) -> Option<crate::runtime_hooks::InvocationId> {
        self.invocation
    }

    /// The origin conversation a host bound, if any.
    #[must_use]
    pub fn origin_conversation(&self) -> Option<EntityId> {
        self.origin_conversation
    }

    /// Marks this surface as a caller's whose credential this host admitted.
    /// It grants and narrows nothing: a verb hook's ask on its call saves no
    /// way to run the call without the credential, so the caller's retry,
    /// which the host verifies again, resumes it, or the host's own check
    /// when it bound the credential's instrument and door (ARCH-0080 §3 Ask).
    #[must_use]
    pub fn for_credential(mut self) -> Self {
        self.credential = true;
        self
    }

    /// Binds the exact instrument the caller's credential is, which its host
    /// verifies again (ARCH-0080 §3 Ask). It grants and narrows nothing: with
    /// a door bound too ([`Self::with_credential_door`]), a verb hook's ask
    /// on this surface's call saves a reference to both, so settlement runs
    /// the call again through that door once the host verified the
    /// credential again.
    #[must_use]
    pub fn with_credential_instrument(
        mut self,
        instrument: crate::runtime_hooks::verb::VerbAskInstrument,
    ) -> Self {
        self.credential_instrument = Some(instrument);
        self
    }

    /// Binds the door the caller came in by, which its host can run the call
    /// through again. It grants and narrows nothing.
    #[must_use]
    pub fn with_credential_door(mut self, door: crate::runtime_hooks::verb::VerbAskDoor) -> Self {
        self.credential_door = Some(door);
        self
    }

    /// The reference a verb hook's ask saves for this credential caller's
    /// call, with the instrument its request was admitted on as its witness:
    /// only for an instrument and door a host bound, in the room turn that
    /// door named, if any, and with nothing else on the surface its door
    /// could not rebuild (a host origin, a machine signer, a TASK host, an
    /// off-record session or a thread's turn). A slip's is its verified slip
    /// and the binding its request was admitted on; a managed vault's
    /// attested owner's is the person, the actor this surface is bound to as
    /// a human, with no slip (FIX 11063). `None` resumes only on the
    /// caller's retry.
    #[must_use]
    pub fn verb_ask_credential(&self) -> Option<crate::runtime_hooks::verb::VerbAskCredential> {
        use crate::runtime_hooks::verb::{
            VerbAskCredential, VerbAskCredentialRef, VerbAskCredentialSource,
            VerbAskCredentialWitness, VerbAskDoor,
        };
        let door = self.credential_door.as_ref()?;
        let room = match door {
            VerbAskDoor::Facade { room } => *room,
            VerbAskDoor::Mcp { .. } | VerbAskDoor::McpOwner { .. } => None,
        };
        let rebuilt = self.credential
            && self.room_turn.as_ref().map(|turn| turn.room) == room
            && self
                .room_turn
                .as_ref()
                .is_none_or(|turn| turn.branch.is_none())
            && self.host_origin.is_none()
            && self.machine_signer.is_none()
            && self.task_host.is_none()
            && self.off_record_session.is_none();
        if !rebuilt {
            return None;
        }
        let instrument = self.credential_instrument.clone()?;
        let witness = match instrument.source {
            VerbAskCredentialSource::Slip { .. } => {
                self.read_proof.as_ref()?;
                VerbAskCredentialWitness::Slip(self.invocation_slip.clone()?)
            }
            VerbAskCredentialSource::AttestedOwner { holder } => {
                if holder != self.actor || self.actor_class != crate::EdgeActorClass::Human {
                    return None;
                }
                VerbAskCredentialWitness::AttestedOwner { holder }
            }
        };
        let reference = VerbAskCredentialRef {
            instrument,
            door: door.clone(),
            on_device: self.locality == crate::claim::CallerLocality::OnDevice,
        };
        Some(VerbAskCredential::new(reference, witness))
    }

    /// Binds the door's admission of a hook's rewritten args: a rewrite the
    /// door would refuse from the caller is refused from a hook too. A room
    /// turn opened on this surface keeps it.
    #[must_use]
    pub fn with_rewrite_admit(mut self, admit: RewriteAdmit) -> Self {
        self.rewrite_admit = Some(admit);
        self
    }

    /// The door's admission of rewritten args a host bound, if any.
    pub(crate) fn rewrite_admit(&self) -> Option<&RewriteAdmit> {
        self.rewrite_admit.as_ref()
    }

    /// Binds the running agent attempt whose TASK creates this surface makes
    /// (OF-532): a TASK it creates for an agent then runs inside that
    /// attempt's lease tree and project. A host builds the binding from the
    /// leased row it holds, never from caller text. It grants nothing: each
    /// create re-proves the lease, the actor and the spend scope in its own
    /// transaction, and a stale one refuses.
    #[must_use]
    pub fn with_task_host(mut self, binding: crate::task_verb::HostBinding) -> Self {
        self.task_host = Some(binding);
        self
    }

    /// The TASK creator a host bound, if any.
    pub(crate) fn task_host(&self) -> Option<&crate::task_verb::HostBinding> {
        self.task_host.as_ref()
    }
}
