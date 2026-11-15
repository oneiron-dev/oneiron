//! What a pairing link's principal may name: its facets, an
//! organization's administration powers and an app backend's verbs.

use super::*;
use crate::federation::OrgAdminPower;
use oneiron_authority::federation::{ScopeAxis, ScopeId};

impl Vault {
    /// A facet limit is for agents and rooms, never the owner (owner ruling
    /// FACET-READ = A): a link held by the vault owner's person takes none,
    /// judged as the credential's own class, as reads judge it. A write facet
    /// is one of the link's facets.
    pub(super) fn validate_pairing_facets_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: &PairingPrincipal,
        scope: &Scope,
        holder_ref: Option<&str>,
    ) -> Result<()> {
        if let Some(facet) = principal.write_facet.as_deref() {
            let facet = ScopeId(canonical_id(facet)?);
            if !matches!(&scope.facets, ScopeAxis::Some(facets) if facets.contains(&facet)) {
                return Err(pairing_scope(
                    "a write facet must be one of the link's facets",
                ));
            }
        }
        if matches!(scope.facets, ScopeAxis::All)
            || !matches!(principal.actor_class.as_deref(), None | Some("human"))
        {
            return Ok(());
        }
        let Some(holder) = holder_ref.and_then(|holder| crate::EntityId::from_hex(holder).ok())
        else {
            return Ok(());
        };
        let owner = crate::memory::actor_is_vault_owner_in_txn(
            self,
            txn,
            holder,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|_| invalid_authority())?;
        if owner {
            return Err(pairing_scope(
                "the vault owner's credential takes no facet limit",
            ));
        }
        Ok(())
    }
    /// A published app's backend holds verbs only under Grant rows the owner
    /// mints as their own act, default none (canon ARCH-0050 PUBLIC-BACKEND
    /// = A; Engine RULING APP-BACKEND-LINK-GRANT = A, 15 Nov 20:30). A link
    /// that names any verb for a backend that no Grant row names is refused
    /// with [`crate::error::RecordError::AppBackendGrantRequired`], which
    /// names `vault.agents.grants.mint`. A link that names no verb, as the
    /// backend's own first link, and a backend a Grant row names, pass.
    /// `holder_ref` is the link's holder at issue and the redeemer at
    /// redemption, so a link that leaves its holder open is judged for the
    /// backend that redeems it.
    pub(super) fn validate_pairing_backend_verbs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &Scope,
        holder_ref: Option<&str>,
    ) -> Result<()> {
        let Some(holder) = holder_ref.and_then(|holder| crate::EntityId::from_hex(holder).ok())
        else {
            return Ok(());
        };
        // The act rule's two readings (pass 26; A0 #8320 states this `if` as
        // `!Permitted::NoWidening.admits(Direction::Widens)`): a link that
        // names a verb widens its holder's reach, and a link alone may not
        // widen an ungranted backend's.
        let widens = !scope.verbs.is_bottom();
        if widens
            && self.is_artifact_backend_principal_in_txn(txn, holder)?
            && !self.agent_grant_names_in_txn(txn, holder)?
        {
            return Err(crate::error::Error::Record(
                crate::error::RecordError::AppBackendGrantRequired,
            ));
        }
        Ok(())
    }
    pub(super) fn validate_pairing_principal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: &PairingPrincipal,
        scope: &Scope,
    ) -> Result<()> {
        if principal
            .actor_class
            .as_deref()
            .is_some_and(|class| !ACTOR_BINDING_CLASSES.contains(&class))
        {
            return Err(invalid_authority());
        }
        let holder = principal
            .holder_ref
            .as_deref()
            .map(|holder| {
                let id = crate::EntityId::from_hex(holder).map_err(|_| invalid_authority())?;
                if id.to_hex() != holder {
                    return Err(invalid_authority());
                }
                Ok(id)
            })
            .transpose()?;
        let Some(org_ref) = principal.org_ref.as_deref() else {
            // All verbs without an org is a general root, not an org credential.
            if matches!(&scope.verbs, ScopeAxis::Some(verbs) if verbs.iter().any(|verb| verb.starts_with("org:")))
            {
                return Err(invalid_authority());
            }
            return Ok(());
        };
        let org = crate::EntityId::from_hex(org_ref).map_err(|_| invalid_authority())?;
        if org.to_hex() != org_ref {
            return Err(invalid_authority());
        }
        let admin = holder.ok_or_else(invalid_authority)?;
        if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &admin)?
            || self.archive_tombstone_in_txn(txn, &admin)?.is_some()
        {
            return Err(invalid_authority());
        }
        let ScopeAxis::Some(verbs) = &scope.verbs else {
            return Err(invalid_authority());
        };
        if verbs.is_empty() {
            return Err(invalid_authority());
        }
        // Read the fixed setup in the same snapshot as the enrollment/mint.
        let policy = ORG_ADMIN_POLICY
            .get(&self.store, txn, &org.to_hex())
            .map_err(|_| invalid_authority())?
            .ok_or_else(invalid_authority)?;
        if policy.org_ref() != org {
            return Err(invalid_authority());
        }
        for verb in verbs {
            let power = OrgAdminPower::parse(verb).ok_or_else(invalid_authority)?;
            policy
                .authorize(admin, power)
                .map_err(|_| invalid_authority())?;
        }
        Ok(())
    }
}

/// A lower-case hex id, as every id on a link is written.
pub(super) fn canonical_id(hex: &str) -> Result<crate::EntityId> {
    let id = crate::EntityId::from_hex(hex).map_err(|_| invalid_authority())?;
    if id.to_hex() != hex {
        return Err(invalid_authority());
    }
    Ok(id)
}

fn pairing_scope(reason: &'static str) -> crate::error::Error {
    crate::error::Error::Record(crate::error::RecordError::InvalidPairingScope(reason))
}
