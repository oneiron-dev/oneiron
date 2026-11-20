//! The read an account API key makes as its person (OF-448; the lead's ruling
//! DEL2-ROOTLESS-MEMBER-KEY-READ = B, 21 Nov 2026: "An account key holding
//! core:read reads as its person, with every bound kept").
//!
//! The control plane's verdict names the key's person and its scopes, and
//! the host verifies it; the key carries no vault slip. Before this ruling
//! its read lane held no Scope, so the retrieval floor denied every row and a
//! Member's key could not name even its own NOTE or claim. Now a key the host
//! verified as holding `core:read` reads under its person's membership: the
//! current Scope of the person's ordinary membership grant in this shared
//! vault, read verbs only, as a member's own slip is held to that grant.
//! Every other bound the key's lane held still binds: the access grants of
//! its person, the conversation home, row privacy, worlds and facets, and the
//! owner's agent Grants that name the person. A person with no standing
//! membership grant here (an unshared vault included) gets no Scope and
//! reads nothing, as before. Liveness is the verdict's lease (60 to 300 s),
//! as for any session.

use oneiron_authority::federation::{Scope, ScopeAxis};

use crate::Vault;
use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};

impl Vault {
    /// The read key of `person`'s account API key, which the host verified
    /// as holding `core:read` (module docs). Only that host calls this; it
    /// proves nothing about the key itself.
    ///
    /// # Errors
    ///
    /// A store failure. A membership grant that no longer stands gives the
    /// key no Scope, so it reads nothing.
    pub fn account_key_read_key(&self, person: EntityId) -> Result<ScopedReadActorKey> {
        let txn = self.store.env.read_txn()?;
        self.account_key_read_key_in_txn(&txn, person)
    }

    /// [`Self::account_key_read_key`] in `txn`, the snapshot its caller reads.
    pub(crate) fn account_key_read_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<ScopedReadActorKey> {
        let key = ScopedReadActorKey::with_actor_class(
            person.to_hex(),
            crate::EdgeActorClass::Human.gate_actor_class(),
        )
        .ok_or(Error::InvariantViolation(
            "an account key's person names no read key",
        ))?
        .require_access_grants(Some(person));
        let key = match self.account_key_read_scope_in_txn(txn, person)? {
            Some(scope) => {
                // The owner's agent Grants that name the person bound it as
                // they bound a slip it holds (credential_key.rs).
                let bound = self.agent_grant_read_bound_in_txn(txn, &scope, person)?;
                let key = key.within_authority(scope);
                let key = match bound {
                    Some(bound) => key.within_agent_grants(bound.envelope, &bound.alternatives),
                    None => key,
                };
                key.bound_by_live_agent_grants(person)
            }
            None => key,
        };
        // A person is never one of the vault's own agents: the conversation
        // home binds its read (RULING SECREAD-HOME-READ-DOORS = B).
        Ok(key.homed_unnamed())
    }

    /// The read Scope `person`'s account key holds in `txn`: its standing
    /// ordinary membership grant's current Scope, held to the read verbs.
    /// `None` on a vault that is not shared, and for a person who holds no
    /// such grant here.
    fn account_key_read_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<Option<Scope>> {
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(None);
        };
        let Some((grant_ref, _role)) = self.member_grant_in_txn(txn, creation.vault_id, person)?
        else {
            return Ok(None);
        };
        let membership =
            match self.current_member_grant_scope_in_txn(txn, grant_ref, &person.to_hex()) {
                Ok(Some(membership)) => membership,
                Ok(None) => return Ok(None),
                // A membership grant that no longer stands (withdrawn, lapsed,
                // its person gone) is none: the key reads nothing, as before,
                // never a failed read. A store failure stays an error.
                Err(error) if error.kind() == ErrorKind::InvalidAuthorityLogBody => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        let mut read = Scope::top();
        read.verbs = ScopeAxis::Some(
            ["read", "core:read"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        Ok(Some(
            ScopedReadActorKey::read_authority(&membership).meet(&read),
        ))
    }
}
