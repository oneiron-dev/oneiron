//! The consent reads: grant rows, active standing grants, the evaluator door and the registry.

use super::*;

impl Vault {
    /// Reads one standing consent-grant row.
    pub fn consent_grant(&self, grant_ref: &str) -> Result<Option<ConsentGrantRow>> {
        let rtxn = self.store.env.read_txn()?;
        self.consent_grant_in_txn(&rtxn, grant_ref)
    }

    pub(crate) fn consent_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant_ref: &str,
    ) -> Result<Option<ConsentGrantRow>> {
        GRANTS.get(&self.store, txn, &grant_ref.to_owned())
    }

    /// Every ACTIVE standing grant, for the evaluator.
    ///
    /// Revoked rows are filtered here rather than at the call site so a
    /// revocation is immediate for every consumer.
    pub fn active_standing_consent_grants(&self) -> Result<Vec<StandingConsentGrant>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_standing_consent_grants_in_txn(&rtxn)
    }

    /// Transaction-composable [`Vault::active_standing_consent_grants`].
    ///
    /// Reads on the caller's transaction (read or write — an `RwTxn`
    /// derefs here), so a door composing the consent context INSIDE its own
    /// write txn sees the same snapshot the enclosing commit is decided on.
    pub fn active_standing_consent_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<StandingConsentGrant>> {
        load_active_standing_grants(&self.store, txn)
    }

    /// The DEC-0006 door: evaluates one composed effect against the owner's
    /// current remembered state and returns both the verdict and the Gate
    /// reason codes that explain it.
    ///
    /// This is what a write door calls to opt onto the unified consent path.
    /// It loads the ACTIVE grants itself, so a caller cannot pass a stale or
    /// hand-picked grant set, and it routes through the one evaluator, so no
    /// door re-implements the ladder. `pending_approve_once` is the exact
    /// engine-emitted digest of an approve-once receipt already in hand for this
    /// op, if any. Digest equality alone is not authority: this door reads the
    /// marker, evaluates the ladder, and changes an admitted marker to spent in
    /// one write transaction. A replay is refused before another `Auto` can be
    /// returned.
    ///
    /// The returned reason codes are empty exactly when the verdict is
    /// [`ConsentDecision::Auto`].
    pub fn evaluate_consent_for(
        &self,
        effect: &ComposedEffect,
        pending_approve_once: Option<&EffectDigest>,
    ) -> Result<ConsentEvaluation> {
        let mut wtxn = self.store.env.write_txn()?;
        let grants = self.active_standing_consent_grants_in_txn(&wtxn)?;
        let approve_once = pending_approve_once
            .map(|digest| approve_once_authorization_in_txn(&self.store, &wtxn, digest))
            .transpose()?
            .flatten();
        let context =
            crate::gate::ConsentGateContext::evaluate(effect, approve_once.as_ref(), &grants);
        if context.decision == ConsentDecision::Auto
            && let Some(authorization) = approve_once.as_ref()
        {
            spend_approve_once_in_txn(&self.store, &mut wtxn, authorization)?;
        }
        // DEC-0006 invariant 7: inside its scope, the owner's live bypass
        // grant replaces the floor's ask, and the act is receipted as
        // bypassed in this same transaction.
        if context.decision == ConsentDecision::Ask {
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, &wtxn)?.catastrophe_floor();
            let bypasses = super::super::bypass::live_bypasses_in_txn(&self.store, &wtxn)?;
            if let Some(bypass) =
                super::super::bypass::covering_bypass(effect, &floor, &bypasses, &grants)
            {
                self.record_bypassed_act_in_txn(&mut wtxn, bypass, effect.digest())?;
                let evaluation = ConsentEvaluation {
                    decision: ConsentDecision::Auto,
                    reason_codes: Vec::new(),
                    bypassed_by: Some(bypass.grant_ref.clone()),
                };
                wtxn.commit()?;
                return Ok(evaluation);
            }
        }
        let evaluation = ConsentEvaluation {
            decision: context.decision,
            reason_codes: crate::gate::consent_gate_reason_codes(&context),
            bypassed_by: None,
        };
        wtxn.commit()?;
        Ok(evaluation)
    }

    /// The unified consent registry — surface (b) of invariant 9.
    ///
    /// Review and one-tap revoke for BOTH domains in one place. There is no
    /// third surface and no settings screen: the in-moment ask (`genui.rs`) is
    /// surface (a), and this is surface (b).
    pub fn consent_registry(&self, query: ConsentRegistryQuery) -> Result<ConsentRegistry> {
        let mut rows: Vec<ConsentRegistryRow> = self
            .consent_grant_rows()?
            .iter()
            .filter(|row| query.include_revoked || row.is_active())
            .map(ConsentRegistryRow::from_row)
            .collect();
        // A contact's clearance row is its own authority (OF-365): the
        // registry projects it beside the grant rows, with its own revoke.
        let rtxn = self.store.env.read_txn()?;
        rows.extend(
            crate::disclosure::contact_clearances_in_txn(&self.store, &rtxn)?
                .iter()
                .filter(|(_, clearance)| {
                    query.include_revoked
                        || clearance.status == crate::disclosure::DisclosureScopeStatus::Active
                })
                .map(|(contact, clearance)| {
                    ConsentRegistryRow::from_contact_clearance(contact, clearance)
                }),
        );
        // A support grant (OF-606) is reviewed here too, projected from its
        // logged mint, with the support revoke door as its one-tap revoke.
        rows.extend(
            self.support_grant_rows_in_txn(&rtxn)?
                .iter()
                .filter(|grant| {
                    query.include_revoked
                        || grant.status == crate::authority::SupportGrantStatus::Active
                })
                .map(ConsentRegistryRow::from_support_grant),
        );
        // An owner's agent grant (FIX 5628) is reviewed here too, with the
        // agent grant revoke door as its one-tap revoke.
        rows.extend(self.agent_grant_registry_rows_in_txn(&rtxn, query.include_revoked)?);
        rows.extend(self.git_push_registry_rows_in_txn(&rtxn, query.include_revoked)?);
        // An agent's witness-read grant over a connector conversation
        // (FIX 10895), with its own one-tap revoke.
        rows.extend(
            self.connector_witness_read_registry_rows_in_txn(&rtxn, query.include_revoked)?,
        );
        drop(rtxn);
        rows.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.grant_ref.cmp(&right.grant_ref))
        });
        rows.truncate(query.limit);
        Ok(ConsentRegistry { rows })
    }
}
