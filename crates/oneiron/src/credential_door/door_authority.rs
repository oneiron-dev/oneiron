//! Canonical mint witnesses, atomic spend, and one-shot mint composition.

use super::door_types::{
    CredentialDoorError, DOOR_ONE_SHOT_MAX_LIFETIME_SECS, DoorResult, log_unreachable,
};
use super::{CredentialDoorService, DoorCredential};
use crate::authority::{AuthorityDoorSlip, AuthorityOp, FederationPactStatus};
use crate::federation::{FederationScopeBands, FederationScopeFacets};
use crate::secret_lease::VaultInstant;

#[cfg(test)]
fn check_log_available() -> DoorResult<()> {
    if super::authority_log_fault_hook::take_log_unreachable() {
        return Err(CredentialDoorError::AuthorityLogUnreachable);
    }
    Ok(())
}

impl CredentialDoorService {
    pub(super) fn witness_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &DoorCredential,
    ) -> DoorResult<()> {
        if credential.slip_id().starts_with("checkout:") {
            return self.witness_checkout_in_txn(txn, credential);
        }
        // Legacy transport-proved views remain non-minting. A signed-hash
        // handle and EVERY one-shot must be witnessed against the live log.
        if !credential.is_single_use() && credential.slip_id().len() != 64 {
            return Ok(());
        }
        #[cfg(test)]
        check_log_available()?;
        let hash = credential.mint_hash()?;
        let fold = self
            .vault()
            .authority_fold_readonly_in_txn(txn)
            .map_err(log_unreachable)?;
        let mint = fold
            .live_door_slip(&hash)
            .ok_or(CredentialDoorError::AuthorityRejected)?;
        if !credential.matches_mint(&mint.scope) {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        if let Some((grant, requested)) = &mint.scope.pact {
            let pact = fold
                .pact_for_grant(grant)
                .ok_or(CredentialDoorError::AuthorityRejected)?;
            if pact.status != FederationPactStatus::Active
                || fold
                    .federation_grant_bindings
                    .get(grant)
                    .is_none_or(|ids| ids.len() != 1)
            {
                return Err(CredentialDoorError::AuthorityRejected);
            }
            let effective = requested.intersect(&pact.effective_scope);
            if !requested.is_narrowing_of(&effective)
                || matches!(effective.facets, FederationScopeFacets::Bottom)
                || matches!(effective.bands, FederationScopeBands::Bottom)
            {
                return Err(CredentialDoorError::AuthorityRejected);
            }
        }
        Ok(())
    }

    /// Commits authority admission and any spend BEFORE an external effect.
    /// Failure after spending may burn a token; it never makes it reusable.
    pub(super) fn authorize(
        &self,
        credential: &DoorCredential,
        verb: &str,
        record: &str,
        channel: &str,
        now: VaultInstant,
    ) -> DoorResult<()> {
        let mut txn = self
            .vault()
            .store
            .env
            .write_txn()
            .map_err(log_unreachable)?;
        self.witness_in_txn(&txn, credential)?;
        self.evaluate_with_consent_in_txn(&mut txn, credential, verb, record, channel, now)?;
        if credential.is_single_use() {
            self.vault().append_local_door_op_in_txn(
                &mut txn,
                AuthorityOp::SpendDoorSlip {
                    mint_hash: credential.mint_hash()?,
                },
            )?;
        }
        txn.commit().map_err(log_unreachable)?;
        Ok(())
    }

    /// Rehydrates a signed slip for the registered principal the transport has
    /// independently authenticated. The non-secret hash alone is not proof.
    pub(crate) fn credential_for_principal(
        &self,
        hash: &[u8; 32],
        principal: &str,
    ) -> DoorResult<DoorCredential> {
        #[cfg(test)]
        check_log_available()?;
        let txn = self.vault().store.env.read_txn().map_err(log_unreachable)?;
        let fold = self
            .vault()
            .authority_fold_readonly_in_txn(&txn)
            .map_err(log_unreachable)?;
        let mint = fold
            .live_door_slip(hash)
            .ok_or(CredentialDoorError::AuthorityRejected)?;
        if principal != mint.scope.holder_ref {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        Ok(DoorCredential::from_mint(hash, &mint.scope))
    }

    /// Attenuates a signed parent into a short-lived exact-scope one-shot.
    /// The enrolled local device signs; authority fold is the final arbiter.
    pub(super) fn mint_one_shot(
        &self,
        presented: &DoorCredential,
        secret_ref: &str,
        effector: &str,
        lifetime_secs: u64,
    ) -> DoorResult<DoorCredential> {
        if lifetime_secs == 0 || lifetime_secs > DOOR_ONE_SHOT_MAX_LIFETIME_SECS {
            return Err(CredentialDoorError::OneShotLifetimeDenied {
                lifetime_secs,
                ceiling_secs: DOOR_ONE_SHOT_MAX_LIFETIME_SECS,
            });
        }
        #[cfg(test)]
        check_log_available()?;
        let now = self.door_instant()?;
        let admitted = self.admit_scope(effector, now)?;
        let mut txn = self
            .vault()
            .store
            .env
            .write_txn()
            .map_err(log_unreachable)?;
        self.witness_in_txn(&txn, presented)?;
        // Minting delegates authority. An operational consent override cannot
        // alter the parent's signed class or sneak expanded verbs into the log.
        match presented.evaluate("mint", secret_ref, admitted.effector().as_str(), now) {
            Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: super::door_types::DoorDenyReason::VerbNotInSlip,
            }) => {
                return Err(CredentialDoorError::Ask {
                    reason: super::door_types::DoorDenyReason::VerbNotInSlip,
                    effect: Box::new(presented.ask_effect(
                        "mint",
                        secret_ref,
                        admitted.effector().as_str(),
                    )?),
                });
            }
            result => result?,
        }
        if lifetime_secs > presented.remaining_secs(now)
            || presented.is_single_use()
            || !presented.ttl_cap.admits(lifetime_secs)
        {
            return Err(CredentialDoorError::AuthorityRejected);
        }
        admitted
            .clone()
            .into_lease(secret_ref, lifetime_secs, now.after(lifetime_secs))
            .reaffirm_in_txn(&self.vault().store, &txn)?;
        let scope = AuthorityDoorSlip {
            holder_ref: presented.holder_ref().to_owned(),
            verb_class: "door.redeem".to_owned(),
            records: [secret_ref.to_owned()].into(),
            channels: [admitted.effector().as_str().to_owned()].into(),
            parent: Some(presented.mint_hash()?),
            pact: self
                .vault()
                .authority_fold_readonly_in_txn(&txn)
                .map_err(log_unreachable)?
                .live_door_slip(&presented.mint_hash()?)
                .ok_or(CredentialDoorError::AuthorityRejected)?
                .scope
                .pact
                .clone(),
            issued_at: now.secs(),
            expires_at: now
                .secs()
                .checked_add(lifetime_secs)
                .ok_or(CredentialDoorError::AuthorityRejected)?,
            single_use: true,
        };
        let hash = self
            .vault()
            .append_local_door_op_in_txn(&mut txn, AuthorityOp::MintDoorSlip(scope.clone()))?;
        txn.commit().map_err(log_unreachable)?;
        Ok(DoorCredential::from_mint(&hash, &scope))
    }
}
