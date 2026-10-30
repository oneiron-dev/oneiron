//! The owner-proof doors: authenticate, bind, recheck and the proof's read key.

use super::*;

impl Vault {
    /// Produces an [`AuthenticatedOwner`] from the independent checks DEC-0006
    /// requires: the store-truth human-actor check, the GenUI
    /// principal-authentication result, the entity's REGISTRY-ACTIVE state,
    /// and the principal↔actor binding.
    ///
    /// This is the ONLY constructor of [`AuthenticatedOwner`]. A guard, a
    /// preference, a claim, or a transcript line cannot reach it, so
    /// "owner-only minting" is an engine check rather than a UI promise.
    ///
    /// The registry-active assertion is load-bearing: a PERSON row that has
    /// been merged or split away is a redirect shell, not an owner — an
    /// `AuthenticatedOwner` minted on it would stamp grants on a dead
    /// identity. [`ActorBound::new`] then verifies the principal ref normalizes
    /// to a non-empty reference; and a hex principal ref must decode to THIS
    /// actor, so the ref that authenticated is the actor the grant lands for
    /// (no cross-actor principal substitution).
    ///
    /// # Errors
    ///
    /// Returns [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated) when the principal did
    /// not authenticate, the principal ref normalizes empty, the named actor
    /// is not a store-truth human entity, the entity is registry-inactive
    /// (merged / split shell), or a hex principal ref binds to another actor.
    pub fn authenticate_owner(
        &self,
        actor: EntityId,
        principal_ref: &str,
        principal_authenticated: bool,
        decision_id: GateDecisionId,
    ) -> Result<AuthenticatedOwner> {
        if !principal_authenticated {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "GenUI principal authentication did not succeed",
            )));
        }
        let principal_ref =
            normalized_ref("principal_ref", principal_ref.to_owned()).map_err(|_| {
                Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "principal_ref is empty",
                ))
            })?;
        // The ActorBound constructor is the lane's principal-shape check: an
        // unusable principal ref is a rejected authentication, not a stamped
        // grant on a malformed subject.
        ActorBound::new(principal_ref.as_str()).map_err(|_| {
            Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "principal_ref is unusable",
            ))
        })?;
        if !self.is_store_truth_human_actor(&actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "actor is not a store-truth human entity",
            )));
        }
        // Registry-active: a merged or split shell is a redirect, not an
        // owner. The topology fold fails closed.
        match self.entity_lifecycle_state(&actor).map_err(|_| {
            Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "actor lifecycle is unreadable",
            ))
        })? {
            crate::identity_topology::EntityLifecycleState::Active => {}
            crate::identity_topology::EntityLifecycleState::Merged
            | crate::identity_topology::EntityLifecycleState::Split => {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "actor is registry-inactive (merged/split shell), not an owner",
                )));
            }
        }
        // A deleted PERSON keeps its shell and its Active lifecycle.
        if !person_is_live_in_txn(self, &self.store.env.read_txn()?, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "actor is deleted, not an owner",
            )));
        }
        // A hex principal ref is an entity reference: it must decode to THIS
        // actor, or the authenticated principal and the minted grant would
        // name different actors.
        if let Ok(principal_id) = EntityId::from_hex(principal_ref.as_str())
            && principal_id != actor
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "principal_ref binds to a different actor entity",
            )));
        }
        Ok(AuthenticatedOwner {
            actor,
            principal_ref,
            decision_id,
            vault_path: self.store.env.path().to_path_buf(),
            vault_open: self.store.open_nonce,
            credential: None,
            person_credential: None,
            request_credential: None,
            host_action: None,
        })
    }

    /// Produces an [`AuthenticatedOwner`] for one decision from a host
    /// action (FIX 2222): the owner a self-hosted root, or the explicit local
    /// dev mode, acts as. The proof carries the action, so every
    /// revalidation in an acting transaction also requires the root to stay
    /// live and keep binding this owner. A hosted operator's root never gets
    /// here: it resolves no [`crate::authority::HostActionAuthority`].
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the action no longer holds or its person is no live owner of
    /// this vault; [`Error::HostActionRequiresSupportGrant`] on a vault that
    /// is not self-hosted.
    pub fn authenticate_host_action_owner(
        &self,
        action: &crate::authority::HostActionAuthority,
        decision_id: GateDecisionId,
    ) -> Result<AuthenticatedOwner> {
        let actor = action.actor().entity_ref();
        let owner = AuthenticatedOwner {
            actor,
            principal_ref: actor.to_hex(),
            decision_id,
            vault_path: self.store.env.path().to_path_buf(),
            vault_open: self.store.open_nonce,
            credential: None,
            person_credential: None,
            request_credential: None,
            host_action: Some(Box::new(action.guard().clone())),
        };
        self.recheck_owner(&owner)?;
        Ok(owner)
    }

    /// Binds `owner` to the verified, full owner-grade capability its request
    /// arrived with. From then on every door that revalidates the proof in
    /// its committing transaction also refuses once that capability is
    /// revoked or expired, or once the actor is no longer an owner of this
    /// vault, so a request queued behind either change never lands.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the capability is not the owner's own unattenuated human slip, is
    /// no longer live, or the actor is not an owner of this vault now.
    pub fn bind_owner_credential(
        &self,
        mut owner: AuthenticatedOwner,
        credential: crate::authority::VerifiedSlip,
    ) -> Result<AuthenticatedOwner> {
        own_full_slip(&owner, &credential)?;
        owner.credential = Some(Box::new(credential));
        self.recheck_owner(&owner)?;
        Ok(owner)
    }

    /// [`Self::bind_owner_credential`] judged in the caller's transaction
    /// `txn`, answering the owner's actor: the owner's repair of a damaged
    /// authority clock judges it against the floor it staged there (FIX
    /// 10106).
    pub(crate) fn bind_owner_credential_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        mut owner: AuthenticatedOwner,
        credential: crate::authority::VerifiedSlip,
    ) -> Result<EntityId> {
        own_full_slip(&owner, &credential)?;
        owner.credential = Some(Box::new(credential));
        owner.revalidate_in_txn(self, txn)
    }

    /// Rechecks `owner` against the vault as it stands now: the person is
    /// live and still owns this vault and, for a bound credential, the
    /// capability is live. For an act that keeps no row of its own to
    /// recheck in, so it runs only if the proof still holds when it starts.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds.
    pub fn recheck_owner(&self, owner: &AuthenticatedOwner) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        Ok(())
    }

    /// The vault owner's read key for the person `owner` proves, held to
    /// that proof (WILL-PLAN L13 row 01): a request that authenticated its
    /// owner with no slip of its own (a managed vault's attested owner) reads
    /// as that owner, and every read proves `owner` again in its own snapshot
    /// as an owner act does ([`AuthenticatedOwner::revalidate_in_txn`]), so
    /// the key reads nothing once the owner lapses. The door sets where its
    /// caller sits (`ScopedReadActorKey::at`). A read key alone authorizes
    /// no act: each committing door still revalidates the proof itself.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds now.
    pub fn owner_proof_read_key(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<crate::claim::ScopedReadActorKey> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        Ok(crate::claim::ScopedReadActorKey::vault_owner(actor)
            .guarded_by_owner_proof(owner.clone()))
    }
}

/// Whether `credential` is `owner`'s own unattenuated human slip.
fn own_full_slip(
    owner: &AuthenticatedOwner,
    credential: &crate::authority::VerifiedSlip,
) -> Result<()> {
    let claims = credential.claims();
    if !credential.is_full_vault_owner_grade()
        || claims.holder_ref != owner.actor.to_hex()
        || claims.actor_class.as_deref() != Some(CONSENT_ACTOR_CLASS)
    {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "credential is not this owner's own full slip",
        )));
    }
    Ok(())
}

impl AuthenticatedOwner {
    /// The slip this proof is bound to, for a persisted delegation that
    /// rechecks it at redemption (a Slack install): its slip id, or `None`
    /// for a proof bound to no credential.
    pub(crate) fn credential_slip_id_for_persist(&self) -> Option<[u8; 32]> {
        self.credential
            .as_ref()
            .map(|credential| credential.claims().slip_id)
    }

    /// The host action this proof was authenticated from, for a persisted
    /// delegation: its owner and its root slip id (`None` for the dev
    /// mode), or `None` for a proof with no host action.
    pub(crate) fn host_action_for_persist(&self) -> Option<(Option<[u8; 32]>, EntityId)> {
        self.host_action
            .as_ref()
            .map(|action| (action.root_slip_id(), action.owner()))
    }
}
