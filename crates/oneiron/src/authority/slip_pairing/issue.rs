//! Issuing a single-use pairing link, the owner's answer for a machine it
//! adds included.

use super::code::{draw_code, pairing_row_key};
use super::*;
use crate::authority::slip_vault::require_host;
use crate::check_in::{self, CheckInDecision, WidenAct, WidenCheckIn};

/// The saved verb a share's view link is, as check-in judges it.
const VIEW_LINK_VERB: &str = "vault.shares.issue_view_link";

/// A view link's share, as its writer authorizes and judges it.
struct ShareLinkAct {
    share: crate::EntityId,
    actor: crate::write_envelope::WriteActor,
    /// The recipient credential's class.
    class: crate::edge::EdgeActorClass,
    check_in_ref: Option<crate::EntityId>,
}

/// What one link's writer did.
enum IssuedLink {
    /// The link, and a share link's check-in decision.
    Issued(PairingLink, Option<CheckInDecision>),
    /// A member's link to a share another issued waits on this pending
    /// check-in, committed alone.
    Waits(crate::EntityId),
}

impl IssuedLink {
    /// The link and its check-in decision, or `CHECK_IN_PENDING` naming the
    /// check-in a share link waits on.
    fn into_judged(self) -> Result<(PairingLink, Option<CheckInDecision>)> {
        match self {
            Self::Issued(link, decision) => Ok((link, decision)),
            Self::Waits(id) => Err(crate::Error::CheckInPending(id.to_hex())),
        }
    }
}

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
            None,
        )
        .and_then(IssuedLink::into_judged)
        .map(|(link, _)| link)
    }
    /// [`Self::issue_pairing_link_for_principal`] made by the authenticated
    /// owner in-process on this install (its CLI or its own app,
    /// [`ActSurface::ThisInstall`]); [`Self::issue_owner_pairing_link_from_surface`]
    /// says what it does.
    pub fn issue_owner_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        scope: Scope,
        slip_lifetime_secs: u64,
        principal: PairingPrincipal,
    ) -> Result<PairingLink> {
        self.issue_owner_pairing_link_from_surface(
            issuer,
            owner,
            ActSurface::ThisInstall,
            scope,
            slip_lifetime_secs,
            principal,
        )
    }
    /// [`Self::issue_pairing_link_for_principal`] made by the authenticated
    /// owner from `surface`. The link records that owner, revalidated as it
    /// is stored. A link for a named agent's PERSON that no Grant row names
    /// yet also mints, in the same writer, the agent's default read Grant
    /// (Engine RULING PAIR-GRANT-DESIGN Q3/Q4): an owner act from `surface`,
    /// verbs `read` and `scope`'s other axes, with no expiry, wallet, repo
    /// bounds or verb classes, as an OAuth sign-in's Grant. A mint that fails
    /// refuses the link. Any other holder, and a link naming none, mints
    /// nothing.
    pub fn issue_owner_pairing_link_from_surface(
        &self,
        issuer: &HostSlipIssuer,
        owner: &crate::consent::AuthenticatedOwner,
        surface: ActSurface,
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
            Some(surface),
        )
        .and_then(IssuedLink::into_judged)
        .map(|(link, _)| link)
    }
    /// [`Self::issue_owner_pairing_link`] that never mints a Grant, for a
    /// holder the engine itself creates with no verb to read by (an artifact
    /// backend's principal).
    pub(crate) fn issue_owner_pairing_link_without_grant(
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
            None,
        )
        .and_then(IssuedLink::into_judged)
        .map(|(link, _)| link)
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
            None,
        )
        .and_then(IssuedLink::into_judged)
        .map(|(link, _)| link)
    }
    /// Issues a one-use link for the live share's own recipient. The issuer
    /// supplies the recipient's class; redemption supplies only its key.
    /// This credential can open the rendered view and its citations, not read
    /// vault records or enrol a machine. A link that check-in makes wait
    /// answers `CHECK_IN_PENDING` ([`Self::issue_share_view_link_judged`]).
    pub fn issue_share_view_link(
        &self,
        issuer: &HostSlipIssuer,
        actor: &crate::write_envelope::WriteActor,
        share_id: crate::EntityId,
        actor_class: crate::edge::EdgeActorClass,
        slip_lifetime_secs: u64,
    ) -> Result<PairingLink> {
        self.issue_share_view_link_judged(
            issuer,
            actor,
            share_id,
            actor_class,
            slip_lifetime_secs,
            None,
        )
        .map(|(link, _)| link)
    }
    /// [`Self::issue_share_view_link`], judged by check-in in the link's
    /// writer after every check that refuses it (ROLES-CHECKIN 2k8f;
    /// MEMBER-SHARE-OWN = B; `check_in::person_widen_check_in_in_txn`): the
    /// share's issuer links it at once (`own_item`); the vault's Owner on
    /// their own proof; a member who links a share another issued is judged
    /// under their role, and a Steward's or a Member's link waits
    /// (`CHECK_IN_PENDING`: the pending check-in commits alone, and no link
    /// is drawn) until the call that names the approved check-in as
    /// `check_in_ref`. Answers the link and its decision.
    ///
    /// # Errors
    ///
    /// As [`Self::issue_share_view_link`]; `CHECK_IN_PENDING` while the link
    /// waits; a `check_in_ref` no waiting link of this caller's names.
    pub fn issue_share_view_link_judged(
        &self,
        issuer: &HostSlipIssuer,
        actor: &crate::write_envelope::WriteActor,
        share_id: crate::EntityId,
        actor_class: crate::edge::EdgeActorClass,
        slip_lifetime_secs: u64,
        check_in_ref: Option<crate::EntityId>,
    ) -> Result<(PairingLink, Option<CheckInDecision>)> {
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
            Some(ShareLinkAct {
                share: share_id,
                actor: *actor,
                class: actor_class,
                check_in_ref,
            }),
            None,
        )
        .and_then(IssuedLink::into_judged)
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
        share: Option<ShareLinkAct>,
        default_grant_surface: Option<ActSurface>,
    ) -> Result<IssuedLink> {
        if slip_lifetime_secs == 0 {
            return Err(invalid_authority());
        }
        // The engine's write door, not a raw writer: a default Grant's owner
        // act and row commit in this writer beside the link.
        self.with_write_txn_grouped(|txn| {
            let (principal, share_ref, widen) = match share {
                None => (principal, None, None),
                Some(link) => {
                    let now = self.instant_in_txn(txn)?.secs();
                    let (share, issued) = crate::share::authorize_share_link_in_txn(
                        self,
                        txn,
                        &link.share,
                        &link.actor,
                        now,
                    )?;
                    let class = link.class.gate_actor_class();
                    let widen = WidenAct {
                        actor: link.actor.entity_ref(),
                        class: link.actor.actor_class(),
                        owns_item: issued,
                        verb: VIEW_LINK_VERB,
                        effect_digest: check_in::share_view_link_effect_digest(
                            &link.share,
                            class,
                            slip_lifetime_secs,
                        ),
                    };
                    (
                        PairingPrincipal {
                            holder_ref: Some(share.recipient_ref.to_hex()),
                            actor_class: Some(class.to_owned()),
                            ..PairingPrincipal::default()
                        },
                        Some(link.share),
                        Some((widen, link.check_in_ref)),
                    )
                }
            };
            let owner = link_owner
                .map(|owner| owner.revalidate_as_vault_owner_in_txn(self, &*txn))
                .transpose()?;
            // The owner answers for a machine only while their credential is
            // live, judged in the transaction that stores the answer.
            let machine = match answer {
                None => None,
                Some((owner, surface, ownership)) => {
                    let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
                    Some(PendingMachine {
                        owner: actor,
                        by: ActBy::Owner,
                        surface,
                        kind: OwnerActKind::Pairing,
                        ownership,
                    })
                }
            };
            require_host(&self.authority_fold_readonly_in_txn(txn)?, issuer)?;
            let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, txn)?;
            let slip_lifetime_secs = slip_lifetime_secs.min(ceiling.initial_owner_secs);
            self.validate_pairing_principal_in_txn(txn, &principal, &scope)?;
            self.validate_pairing_facets_in_txn(
                txn,
                &principal,
                &scope,
                principal.holder_ref.as_deref(),
            )?;
            // A share link is judged once every check above admits it, and
            // before any code is drawn.
            let decision = match widen {
                None => None,
                Some((widen, check_in_ref)) => match check_in::person_widen_check_in_in_txn(
                    self,
                    txn,
                    &widen,
                    check_in_ref.as_ref(),
                )? {
                    WidenCheckIn::Go(decision) => decision,
                    WidenCheckIn::Wait(id) => return Ok(IssuedLink::Waits(id)),
                },
            };
            let now = self.instant_in_txn(txn)?.secs();
            let (code, row_key) = self.free_pairing_code_in_txn(txn, issuer, now)?;
            let expires_at = now.saturating_add(CODE_TTL_SECS);
            // A vault with an attested checkpoint pins it for the joining device,
            // bound to this single-use link's fresh challenge (OF-469).
            let mut challenge = [0; 32];
            crate::world_keys::os_fill(&mut challenge)?;
            let pin = self.authority_checkpoint_pin_in_txn(txn, challenge)?;
            let pin_ref = pin.as_ref().map(PairingPinRef::of).transpose()?;
            let comm = effective_slip_comm(principal.comm);
            // The owner's link for a named agent mints its default read Grant
            // in this writer, so a failed mint refuses the link (Q4).
            if let (Some(surface), Some(link_owner)) = (default_grant_surface, link_owner)
                && let Some(holder) = principal
                    .holder_ref
                    .as_deref()
                    .and_then(|holder| crate::EntityId::from_hex(holder).ok())
            {
                self.mint_default_agent_grant_in_txn(txn, link_owner, surface, holder, &scope)?;
            }
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
            PAIRING_PENDING.put(&self.store, txn, &row_key, &pending)?;
            Ok(IssuedLink::Issued(
                PairingLink {
                    code,
                    expires_at,
                    pin: pin_ref,
                    comm,
                },
                decision,
            ))
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
            share_ref: None,
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
