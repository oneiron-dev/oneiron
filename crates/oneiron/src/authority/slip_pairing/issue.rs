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
        self.issue_pairing_link_in(issuer, scope, slip_lifetime_secs, principal, None, None)
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
        )
    }
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
    ) -> Result<PairingLink> {
        if slip_lifetime_secs == 0 {
            return Err(invalid_authority());
        }
        let mut txn = self.store.env.write_txn()?;
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
        let (code, row_key) = loop {
            let code = draw_code();
            let row_key = pairing_row_key(issuer, &code)?;
            let free = match PAIRING_PENDING.get(&self.store, &txn, &row_key) {
                Ok(Some(pending)) => now >= pending.expires_at,
                Ok(None) => true,
                Err(_) => false,
            };
            if free {
                break (code, row_key);
            }
        };
        let expires_at = now.saturating_add(CODE_TTL_SECS);
        // A vault with an attested checkpoint pins it for the joining device,
        // bound to this single-use link's fresh challenge (OF-469).
        let mut challenge = [0; 32];
        crate::world_keys::os_fill(&mut challenge)?;
        let pin = self.authority_checkpoint_pin_in_txn(&txn, challenge)?;
        let pin_ref = pin.as_ref().map(PairingPinRef::of).transpose()?;
        let pending = PairingPending {
            expires_at,
            slip_lifetime_secs,
            scope,
            host_key: issuer.binding_key(),
            principal,
            machine,
            pin,
            owner,
        };
        PAIRING_PENDING.put(&self.store, &mut txn, &row_key, &pending)?;
        txn.commit()?;
        Ok(PairingLink {
            code,
            expires_at,
            pin: pin_ref,
        })
    }
}
