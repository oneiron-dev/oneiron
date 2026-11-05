//! Owned caller/session authority for native work that outlives a borrowed Memory.

use super::*;
use std::sync::Arc;

/// A caller-bound session route that can travel with native asynchronous work.
///
/// Only [`SessionWitnessContext::into_binding`] constructs it. It retains the
/// actual caller proof and captured route, not the Vault or a borrowed Memory.
/// Each use binds the exact original session instance again and runs the same
/// caller and independent author checks as the one-shot witness context.
pub struct SessionWitnessBinding {
    caller: Caller,
    session_ref: String,
    route: SessionWriteRoute,
}

struct Caller {
    actor: EntityId,
    actor_class: crate::edge::EdgeActorClass,
    authority: CallerAuthority,
}

/// The same priority as verify_caller_in_txn, captured only after admission.
enum CallerAuthority {
    Slip(crate::authority::VerifiedSlip),
    HostAction(crate::authority::HostActionAuthority),
    Owner(crate::consent::AuthenticatedOwner),
    Native,
}

impl SessionWitnessContext<'_> {
    /// Releases the Vault borrow while retaining this exact caller, session and
    /// mode generation. This does not open a stream or create any stored state.
    pub fn into_binding(self) -> MemoryResult<SessionWitnessBinding> {
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)?;
        let authority = if let Some(proof) = &self.caller.read_proof {
            CallerAuthority::Slip(proof.clone())
        } else if let Some(action) = &self.caller.host_action {
            CallerAuthority::HostAction(action.clone())
        } else if let Some(owner) = &self.caller.owner_authorship {
            CallerAuthority::Owner(owner.clone())
        } else if self.caller.native_invocation() && !self.caller.credential {
            CallerAuthority::Native
        } else {
            return Err(caller_refused());
        };
        Ok(SessionWitnessBinding {
            caller: Caller {
                actor: self.caller.actor,
                actor_class: self.caller.actor_class,
                authority,
            },
            session_ref: self.session.session_ref().to_owned(),
            route: self.route,
        })
    }
}

impl SessionWitnessBinding {
    /// The captured route's retention choice, not a refreshed mode or authority
    /// check. Native producers must select no-record storage before opening it.
    pub fn keeps_no_record(&self) -> bool {
        self.route.target() == RouteTarget::Discard
    }

    /// Witnesses through the captured caller route after native asynchronous
    /// work. `author` still supplies its own write authority and envelopes.
    /// No stored receipt is invented for an Anonymous route.
    pub fn witness(
        &self,
        author: &Memory<'_>,
        turn: &WitnessTurn,
    ) -> MemoryResult<SessionWitnessOutcome> {
        self.context(author.vault)?.witness(author, turn)
    }

    fn context<'v>(&self, vault: &'v crate::Vault) -> MemoryResult<SessionWitnessContext<'v>> {
        self.route.revalidate()?;
        let session = vault.off_record_session_vault().bind(&self.session_ref)?;
        // A session name or even a copied vault id cannot move this authority
        // to a reopened/replaced session. The captured route owns this Arc.
        if !Arc::ptr_eq(self.route.overlay(), &session.overlay()) {
            return Err(caller_refused());
        }
        let mut caller = vault.memory(self.caller.actor, self.caller.actor_class);
        match &self.caller.authority {
            CallerAuthority::Slip(proof) => caller.read_proof = Some(proof.clone()),
            CallerAuthority::HostAction(action) => caller.host_action = Some(action.clone()),
            CallerAuthority::Owner(owner) => caller.owner_authorship = Some(owner.clone()),
            CallerAuthority::Native => {}
        }
        // Proof-bearing surfaces never acquire the native-host fallback if
        // their original instrument is later revoked or otherwise refuses.
        if !matches!(&self.caller.authority, CallerAuthority::Native) {
            caller.transport_invocation = true;
        }
        Ok(SessionWitnessContext {
            caller,
            session,
            route: self.route.clone(),
        })
    }
}
