//! Consent joins only the missing verb axis, never identity, scope, or floors.

use super::door_types::{CredentialDoorError, DoorDenyReason, DoorResult};
use super::{CredentialDoorService, DoorCredential};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, ComposedEffect, ConsentDecision, EffectFacts,
    GrantBound, approve_once_authorization_in_txn, evaluate_consent, spend_approve_once_in_txn,
};
use crate::secret_lease::VaultInstant;

impl DoorCredential {
    pub(super) fn ask_effect(
        &self,
        verb: &str,
        record: &str,
        channel: &str,
    ) -> DoorResult<ComposedEffect> {
        let class = super::verb_class::class_for_verb(verb)
            .ok_or(CredentialDoorError::AuthorityRejected)?;
        let bound = GrantBound::action(
            ActorBound::new(self.holder_ref())?,
            ActionClass::new(class)?,
            ActionEnvelope::new(vec![
                format!("record:{record}"),
                format!("channel:{channel}"),
            ])?,
        )?;
        // The op kind binds the slip id and exact verb; the envelope binds the
        // record/channel. Length framing prevents concatenation collisions.
        let kind = format!(
            "door:{}:{}:{}:{}",
            self.slip_id().len(),
            self.slip_id(),
            verb.len(),
            verb
        );
        Ok(
            ComposedEffect::new(EffectFacts::new(kind)?.with_external_observers(true))
                .with_action_requirement(bound)?,
        )
    }
}

impl CredentialDoorService {
    pub(super) fn evaluate_with_consent_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        credential: &DoorCredential,
        verb: &str,
        record: &str,
        channel: &str,
        now: VaultInstant,
    ) -> DoorResult<()> {
        match credential.evaluate(verb, record, channel, now) {
            Ok(()) => Ok(()),
            Err(CredentialDoorError::UnauthorizedPrincipal {
                reason: DoorDenyReason::VerbNotInSlip,
            }) => {
                let effect = credential.ask_effect(verb, record, channel)?;
                let grants = self.vault().active_standing_consent_grants_in_txn(txn)?;
                if evaluate_consent(&effect, None, &grants) == ConsentDecision::Auto {
                    return Ok(());
                }
                let authorization =
                    approve_once_authorization_in_txn(&self.vault().store, txn, &effect.digest())?;
                if evaluate_consent(&effect, authorization.as_ref(), &grants)
                    == ConsentDecision::Auto
                {
                    if let Some(proof) = authorization {
                        spend_approve_once_in_txn(&self.vault().store, txn, &proof)?;
                    }
                    return Ok(());
                }
                Err(CredentialDoorError::Ask {
                    reason: DoorDenyReason::VerbNotInSlip,
                    effect: Box::new(effect),
                })
            }
            Err(error) => Err(error),
        }
    }
}
