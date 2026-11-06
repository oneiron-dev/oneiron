//! An owner's explicit credential for one published app and one live grant.

use std::collections::BTreeSet;

use super::slip_vault::{random_slip_id, require_host};
use super::{CapabilitySlip, CommReach, HostSlipIssuer, SlipClaims, invalid_authority};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{AgentGrantStanding, FederationGrantKind, Scope};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

impl Vault {
    /// Signs a credential for the app named by exactly one existing owner
    /// grant. The owner supplies the app's public binding key and expiry;
    /// no prior credential is widened and no grant is created. Each use
    /// still requires that same grant and its current scope.
    pub fn mint_artifact_backend_slip(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        grant_ref: EntityId,
        holder_key: [u8; 32],
        expires_at: u64,
        comm: Option<CommReach>,
    ) -> Result<CapabilitySlip> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let standing = self
            .artifact_backend_grant_in_txn(&txn, grant_ref)?
            .ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(&txn)?.secs();
        if expires_at <= now {
            return Err(invalid_authority());
        }
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: standing.grant.member_ref.to_hex(),
            binding_key: holder_key,
            scope: standing.grant.authority_scope,
            issued_at: now,
            expires_at,
            ttl_secs: expires_at - now,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: Some("agent".to_owned()),
            org_ref: None,
            grant_ref: Some(grant_ref.to_hex()),
            invitation_ref: None,
            delegation: None,
            comm,
            trusted_contact: None,
            seat_claim: None,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(slip)
    }

    /// The same app grant in the caller's snapshot. Ordinary delegates,
    /// memberships, own-device and guest grants keep their existing path.
    pub(super) fn current_artifact_backend_slip_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
    ) -> Result<Option<Scope>> {
        let Some(grant_ref) = claims.grant_ref.as_deref() else {
            return Ok(None);
        };
        let grant_ref = EntityId::from_hex(grant_ref).map_err(|_| invalid_authority())?;
        let Some(standing) = self.artifact_backend_grant_in_txn(txn, grant_ref)? else {
            return Ok(None);
        };
        if claims.actor_class.as_deref() != Some("agent")
            || claims.holder_ref != standing.grant.member_ref.to_hex()
        {
            return Err(invalid_authority());
        }
        Ok(Some(standing.grant.authority_scope))
    }

    fn artifact_backend_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: EntityId,
    ) -> Result<Option<AgentGrantStanding>> {
        let LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &grant_ref)?
        else {
            return Ok(None);
        };
        let grant = crate::federation::decode_federation_grant_body(&body)?;
        if !grant.owner_agent || grant.kind != FederationGrantKind::Access {
            return Ok(None);
        }
        let member = grant.member_ref;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &member)?
        else {
            return Ok(None);
        };
        if !crate::artifact_hosting::is_backend_principal(member, &body) {
            return Ok(None);
        }
        // Only an app grant reaches the native owner-grant listing; unrelated
        // delegates, members and guests do not read that census.
        let standing = self
            .agent_grants_in_txn(txn)?
            .into_iter()
            .find(|standing| standing.id == grant_ref)
            .ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(txn)?.secs();
        if self
            .store
            .port_deletion_marked(txn, DeletionMarker::Archive, &member)?
            || !standing.grant.confers_at(now)
            || !crate::policy_model::owners_in_txn(self, txn)?.contains(&standing.delegated_by)
            || standing.pact_standing_lapsed_in_txn(self, txn)
        {
            return Err(invalid_authority());
        }
        Ok(Some(standing))
    }
}
