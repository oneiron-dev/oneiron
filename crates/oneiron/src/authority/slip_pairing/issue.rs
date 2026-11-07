//! Issuing a single-use pairing link, the owner's answer for a machine it
//! adds included.

use super::code::{draw_code, pairing_row_key};
use super::*;
use crate::authority::slip_vault::require_host;

impl Vault {
    /// Owner/host API: issue a one-hour enrollment link, scoped at creation.
    pub fn issue_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_for_principal(
            issuer,
            scope,
            slip_lifetime_secs,
            PairingPrincipal::default(),
        )
    }
    /// Owner/host enrollment with identity claims fixed before code delivery.
    /// Organization links require a registered admin and an explicit subset
    /// of the organization's immutable administration policy.
    pub fn issue_pairing_link_for_principal(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_in(
            issuer,
            scope,
            slip_lifetime_secs,
            principal,
            None,
            None,
            None,
        )
    }
    /// [`Self::issue_pairing_link_for_principal`] made by the authenticated
    /// owner. The link records that owner, revalidated as it is stored.
    pub fn issue_owner_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_in(
            issuer,
            scope,
            slip_lifetime_secs,
            principal,
            Some(owner),
            None,
            None,
        )
    }
    /// The owner adds a machine, from any surface where he is authenticated
    /// (`surface`, audit only): the single-use link keeps his approval, his
    /// act and his answer (yours, work/school or rented), and redeeming it
    /// enrols the machine under them in the same transaction as its slip,
    /// carried by the redeeming install (mesh PR1b C2).
    pub fn issue_machine_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        surface: ActSurface,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
        ownership: MachineOwnership,
    ) -> Result<PairingLink> {
        self.issue_pairing_link_in(
            issuer,
            scope,
            slip_lifetime_secs,
            principal,
            Some(owner),
            Some((owner, surface, ownership)),
            None,
        )
    }
    /// Issues a one-use link for the live share's own recipient. The issuer
    /// supplies the recipient's class; redemption supplies only its key.
    /// This credential can open the rendered view and its citations, not read
    /// vault records or enrol a machine.
    pub fn issue_share_view_link(
        &self,
        issuer: &HostSlipIssuer,
        actor: &crate::write_envelope::WriteActor,
        share_id: crate::EntityId,
        actor_class: crate::edge::EdgeActorClass,
        slip_lifetime_secs: u64,
    ) -> Result<PairingLink> {
        use oneiron_authority::federation::{ScopeAxis, SensitivityCeiling};
        let scope = Scope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
            audience: ScopeAxis::All,
            verbs: [
                "vault.shares.view".to_owned(),
                "vault.notes.follow_citation".to_owned(),
            ]
            .into_iter()
            .collect(),
            sensitivity: SensitivityCeiling::TOP,
        };
        self.issue_pairing_link_in(
            issuer,
            scope,
            slip_lifetime_secs,
            PairingPrincipal::default(),
            None,
            None,
            Some((share_id, *actor, actor_class)),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn issue_pairing_link_in(
        &self,
        issuer: &HostSlipIssuer,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
        link_owner: Option<&crate::consent::AuthenticatedOwner>,
        answer: Option<(
            &crate::consent::AuthenticatedOwner,
            ActSurface,
            MachineOwnership,
        )>,
        share: Option<(
            crate::EntityId,
            crate::write_envelope::WriteActor,
            crate::edge::EdgeActorClass,
        )>,
    ) -> Result<PairingLink> {
        if slip_lifetime_secs == 0 {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
        let (principal, share_ref) = match share {
            None => (principal, None),
            Some((id, actor, class)) => {
                let now = self.instant_in_txn(&txn)?.secs();
                let share =
                    crate::share::authorize_share_link_in_txn(self, &txn, &id, &actor, now)?;
                (
                    PairingPrincipal {
                        holder_ref: Some(share.recipient_ref.to_hex()),
                        actor_class: Some(class.gate_actor_class().to_owned()),
                        ..PairingPrincipal::default()
                    },
                    Some(id),
                )
            }
        };
        let owner = link_owner
            .map(|owner| owner.revalidate_as_vault_owner_in_txn(self, &txn))
            .transpose()?;
        // The owner answers for a machine only while their credential is
        // live, judged in the transaction that stores the answer.
        let machine = match answer {
            None => None,
            Some((owner, surface, ownership)) => {
                let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
                Some(PendingMachine {
                    owner: actor,
                    by: ActBy::Owner,
                    surface,
                    kind: OwnerActKind::Pairing,
                    ownership,
                })
            }
        };
        require_host(&self.authority_fold_readonly_in_txn(&txn)?, issuer)?;
        let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, &txn)?;
        let slip_lifetime_secs = slip_lifetime_secs.min(ceiling.initial_owner_secs);
        self.validate_pairing_principal_in_txn(&txn, &principal, &scope)?;
        self.validate_pairing_facets_in_txn(
            &txn,
            &principal,
            &scope,
            principal.holder_ref.as_deref(),
        )?;
        let now = self.instant_in_txn(&txn)?.secs();
        let (code, row_key) = self.free_pairing_code_in_txn(&txn, issuer, now)?;
        let expires_at = now.saturating_add(CODE_TTL_SECS);
        // A vault with an attested checkpoint pins it for the joining device,
        // bound to this single-use link's fresh challenge (OF-469).
        let mut challenge = [0; 32];
        crate::world_keys::os_fill(&mut challenge)?;
        let pin = self.authority_checkpoint_pin_in_txn(&txn, challenge)?;
        let pin_ref = pin.as_ref().map(PairingPinRef::of).transpose()?;
        let comm = effective_slip_comm(principal.comm);
        let pending = PairingPending {
            expires_at,
            slip_lifetime_secs,
            scope,
            host_key: issuer.binding_key(),
            principal,
            share_ref,
            machine,
            pin,
            owner,
            invitation: None,
        };
        PAIRING_PENDING.put(&self.store, &mut txn, &row_key, &pending)?;
        txn.commit()?;
        Ok(PairingLink {
            code,
            expires_at,
            pin: pin_ref,
            comm,
        })
    }
    /// A fresh code and its row key: one no outstanding link holds at `now`.
    fn free_pairing_code_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        issuer: &HostSlipIssuer,
        now: u64,
    ) -> Result<(String, String)> {
        loop {
            let code = draw_code();
            let row_key = pairing_row_key(issuer, &code)?;
            let free = match PAIRING_PENDING.get(&self.store, txn, &row_key) {
                Ok(Some(pending)) => now >= pending.expires_at,
                Ok(None) => true,
                Err(_) => false,
            };
            if free {
                return Ok((code, row_key));
            }
        }
    }
    /// Stores, in the writer of `owner`'s act, an invitation pairing code
    /// (FIX 8745): a one-hour single-use link for `invitation`'s invitee,
    /// whose redemption binds that invitation to the redeeming key and mints
    /// the invitee's slip for it (`Vault::redeem_invitation_link_in_txn`).
    /// The owner passes the code on by any channel, as an invite link; it
    /// carries no verb and pairs no ordinary credential. The caller has
    /// checked `owner` and that the invitation is pending.
    pub(crate) fn issue_invitation_pairing_link_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        owner: crate::EntityId,
        invitation: PendingInvitationLink,
        invitation_expires_at: u64,
    ) -> Result<PairingLink> {
        require_host(&self.authority_fold_readonly_in_txn(txn)?, issuer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let (code, row_key) = self.free_pairing_code_in_txn(txn, issuer, now)?;
        let expires_at = now.saturating_add(CODE_TTL_SECS).min(invitation_expires_at);
        if expires_at <= now {
            return Err(invalid_authority());
        }
        let pending = PairingPending {
            expires_at,
            slip_lifetime_secs: invitation_expires_at.saturating_sub(now),
            scope: Scope {
                verbs: oneiron_authority::federation::ScopeAxis::Bottom,
                ..Scope::top()
            },
            host_key: issuer.binding_key(),
            principal: PairingPrincipal {
                holder_ref: Some(invitation.invitee.to_hex()),
                actor_class: Some(ACTOR_CLASS_HUMAN.to_owned()),
                ..PairingPrincipal::default()
            },
            machine: None,
            pin: None,
            owner: Some(owner),
            invitation: Some(invitation),
        };
        PAIRING_PENDING.put(&self.store, txn, &row_key, &pending)?;
        Ok(PairingLink {
            code,
            expires_at,
            pin: None,
            comm: effective_slip_comm(None),
        })
    }
}
