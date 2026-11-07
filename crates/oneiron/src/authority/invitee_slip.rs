//! FIX 1925: an invitee's own credential. The invitee binds their pending
//! invitation to a key of their own (FIX 8745): the key of an independent
//! live human slip of theirs, or the key they redeem an owner's invitation
//! pairing code with; an `add_member` holder names none. The binding writer
//! mints them a human slip to that key under the host's issuer. Its signed
//! claims name the invitation (`invitation_ref`); the host admits it only at
//! that invitation's list, accept and decline doors, and every slip door
//! reads the invitation beside the fold's revocation check, so the slip
//! stands only while the invitation is pending and unexpired, while its key
//! is the one the invitation records and while the credential that bound it
//! is live. Once they have joined, the member pairs an ordinary credential.

use std::collections::BTreeSet;

use super::slip_vault::random_slip_id;
use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use oneiron_authority::federation::{Scope, ScopeAxis};

impl Vault {
    /// Mints, in the binding writer, the human slip of `invitee` for their
    /// invitation `invitation` (entity id hex), under the host's `issuer`. It
    /// binds `holder_key`, the key the invitee bound the invitation to
    /// (FIX 8745); no private key is delivered anywhere. It holds
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
            delegation: None,
            comm: None,
            trusted_contact: None,
            seat_claim: None,
        };
        self.mint_slip_in_txn(txn, issuer, claims)
    }

    /// An invitation-bound slip stands only while its invitation does: the
    /// invitation its claims name, its holder's own, is pending and unexpired
    /// at `now`, its binding key is the one the invitation records, and the
    /// credential that bound it is live (FIX 8745). A slip that names no
    /// invitation passes.
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
        if !self.invitation_slip_stands_in_txn(txn, invitee, invitation, &claims.binding_key, now) {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// A contact-bound slip stands only while its naming does (FIX 4325):
    /// the exact relation row the binding names, unrevoked at that version,
    /// both sides live PERSONs. A slip that names no binding passes.
    fn require_live_trusted_contact_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        _now: u64,
    ) -> Result<()> {
        let Some(binding) = &claims.trusted_contact else {
            return Ok(());
        };
        let contact = EntityId::from_hex(&claims.holder_ref).map_err(|_| invalid_authority())?;
        if !self.trusted_contact_binding_stands_in_txn(
            txn,
            binding.person,
            contact,
            binding.version,
        )? {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// What every slip door reads beside the fold's revocation check: a
    /// grant-bound slip's grant (OF-232), an invitation-bound slip's
    /// invitation, a support slip's delegation (OF-606), a contact-bound
    /// slip's naming (FIX 4325) and a seat-child slip's claim (FIX 10624)
    /// still stand.
    pub(super) fn require_live_slip_refs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        now: u64,
    ) -> Result<()> {
        self.require_live_slip_grant_in_txn(txn, claims, now)?;
        self.require_live_slip_invitation_in_txn(txn, claims, now)?;
        self.require_live_delegation_in_txn(txn, claims)?;
        self.require_live_trusted_contact_binding_in_txn(txn, claims, now)?;
        self.require_live_seat_claim_in_txn(txn, claims)
    }

    /// [`Self::require_live_slip_refs_in_txn`] as a judgment, for a slip
    /// verified earlier and checked again (FIX 5952): `false` once its grant,
    /// invitation, delegation, contact naming or seat claim no longer stands,
    /// an error only when that cannot be judged.
    pub(super) fn slip_refs_stand_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
        now: u64,
    ) -> Result<bool> {
        match self.require_live_slip_refs_in_txn(txn, claims, now) {
            Ok(()) => Ok(true),
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(_))) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
