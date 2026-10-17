//! FIX 1925: an invitee's own credential. When an `add_member` holder invites
//! a person and names the public key that person generated on their own
//! device, the invitation's writer mints them a human slip under the host's
//! issuer. Its signed claims name the invitation (`invitation_ref`); the host
//! admits it only at that invitation's list, accept and decline doors, and
//! every slip door reads the invitation beside the fold's revocation check,
//! so the slip stands only while the invitation is pending and unexpired.
//! Once they have joined, the member pairs an ordinary credential.

use std::collections::BTreeSet;

use super::slip_vault::random_slip_id;
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{Scope, ScopeAxis};

impl Vault {
    /// Mints, in the invitation's writer, the human slip of `invitee` for
    /// their invitation `invitation` (entity id hex), under the host's
    /// `issuer`. It binds `holder_key`, the public key the invitee generated
    /// on their own device; no private key is delivered anywhere. It holds
    /// for the invitee PERSON, carries no verb (the host grants it its
    /// invitation's doors alone), and ends at `expires_at`, the invitation's
    /// own expiry.
    pub(crate) fn mint_invitee_slip_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        invitee: EntityId,
        invitation: &str,
        holder_key: [u8; 32],
        expires_at: u64,
    ) -> Result<CapabilitySlip> {
        let vault_id = self
            .authority_view_readonly_in_txn(txn)?
            .vault_id
            .ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(txn)?.secs();
        let scope = Scope {
            verbs: ScopeAxis::Bottom,
            ..Scope::top()
        };
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id,
            parent_id: None,
            holder_ref: invitee.to_hex(),
            binding_key: holder_key,
            scope,
            issued_at: now,
            expires_at,
            ttl_secs: expires_at.checked_sub(now).ok_or_else(invalid_authority)?,
            single_use: false,
            records: BTreeSet::new(),
            channels: BTreeSet::new(),
            actor_class: Some(ACTOR_CLASS_HUMAN.to_owned()),
            org_ref: None,
            grant_ref: None,
            invitation_ref: Some(invitation.to_owned()),
        };
        self.mint_slip_in_txn(txn, issuer, claims)
    }

    /// An invitation-bound slip stands only while its invitation does: the
    /// invitation its claims name, its holder's own, is pending and unexpired
    /// at `now`. A slip that names no invitation passes.
    fn require_live_slip_invitation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        now: u64,
    ) -> Result<()> {
        let Some(invitation) = &claims.invitation_ref else {
            return Ok(());
        };
        let invitee = EntityId::from_hex(&claims.holder_ref).map_err(|_| invalid_authority())?;
        if !self.shared_invitation_pending_in_txn(txn, invitee, invitation, now) {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// What every slip door reads beside the fold's revocation check: a
    /// grant-bound slip's grant (OF-232) and an invitation-bound slip's
    /// invitation still stand.
    pub(super) fn require_live_slip_refs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        now: u64,
    ) -> Result<()> {
        self.require_live_slip_grant_in_txn(txn, claims, now)?;
        self.require_live_slip_invitation_in_txn(txn, claims, now)
    }
}
