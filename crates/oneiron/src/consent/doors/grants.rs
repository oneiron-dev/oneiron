//! The owner's consent acts: approve once, standing grants, denials, revokes and reuse receipts.

use super::*;

impl Vault {
    /// Approves exactly one pending operation, identified by its exact
    /// engine-computed digest.
    ///
    /// Consumes only that digest: an approve-once receipt authorizes this op,
    /// now, and covers no other op and no future op. It mints no standing row.
    /// The mint is REPLAY-REJECTED: a spent marker keyed by the digest is
    /// claimed in the SAME write transaction as the receipt, so a second
    /// `approve_once` over the same digest — the owner re-tapping an
    /// already-answered ask, or a replayed digest — is refused with
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent). LMDB serializes writers, so a
    /// concurrent mint sees the committed marker and rolls back.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent) when the digest was already
    /// approved, and [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated) transitively
    /// from the owner-stamp check.
    pub fn approve_once(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|wtxn| self.approve_once_in_txn(wtxn, owner, effect_digest))
    }

    /// Composes the exact consent receipt with the effect it authorizes.
    pub(crate) fn approve_once_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let decision_id = crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?);
        self.claim_approve_once_in_txn(wtxn, &effect_digest, decision_id)?;
        let receipt = ConsentReceipt::Approved {
            decision_id,
            grant: ConsentGrant::ApproveOnce(effect_digest),
        };
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// The ONLY persistence door for a standing consent grant.
    ///
    /// Requires an [`AuthenticatedOwner`], rejects catastrophe-class bounds
    /// (the floor is non-rememberable — invariant 7), and writes the row and
    /// its Gate receipt in ONE transaction. Reuse never mutates a bound: a
    /// wider bound is a NEW owner decision that lands as a NEW row with its
    /// own receipt, which is also what "approve-and-stop-asking on a
    /// scope-exceed ask" mints.
    pub fn create_standing_grant(
        &self,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn_grouped(|wtxn| self.create_standing_grant_in_txn(wtxn, owner, bound))
    }

    /// Transaction-composable [`Vault::create_standing_grant`].
    ///
    /// Exists so a caller whose PRECONDITION must hold at mint time can test
    /// it in the same transaction that writes the row: ONE-1748's graduation
    /// tap reads the scope's ramp posture here, so a stale tap cannot overtake
    /// the demotion that retracted the offer it is answering.
    pub(crate) fn create_standing_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bound: GrantBound,
    ) -> Result<ConsentReceipt> {
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        if let Some(class) = bound_catastrophe_class(&bound) {
            return Err(Error::Gate(GateError::ConsentCatastropheNotRememberable(
                crate::gate::consent_floor_refusal(class),
            )));
        }
        let grant = StandingConsentGrant::from_bound(bound)?;
        let row = ConsentGrantRow {
            grant: grant.clone(),
            status: ConsentGrantStatus::Active,
            owner_stamp: owner.stamp(),
            created_at: mutation_recorded_at,
            bypass: None,
        };
        let receipt = ConsentReceipt::Approved {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant: ConsentGrant::Standing(grant),
        };

        let grant_ref = row.grant_ref();
        // A same-bound re-mint is a NEW issuance, even with the same
        // AuthenticatedOwner. Its predecessor's reason and undo must not
        // authorize or revoke this replacement.
        super::super::owner_reason::retire_owner_reason_rules_in_txn(
            &self.store,
            wtxn,
            &grant_ref,
        )?;
        // Re-minting an identical bound is the owner re-affirming it; the row
        // is idempotent, and the receipt is still written so the act is
        // audit-visible.
        GRANTS.put(&self.store, wtxn, &grant_ref, &row)?;
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(receipt)
    }

    /// Denies one pending operation, recording the refusal in the receipt
    /// family so a denial is as legible as an approval.
    pub fn deny_consent(
        &self,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let receipt = self.deny_consent_in_txn(&mut wtxn, owner, effect_digest)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// Transaction-composable [`Vault::deny_consent`].
    pub(crate) fn deny_consent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let receipt = ConsentReceipt::Denied {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            effect_digest,
        };
        // A refusal is the owner's decision: self-heal reads each denial as
        // an owner signal, so it takes the owner tier like every receipt.
        owner.revalidate_in_txn(self, &*wtxn)?;
        self.append_consent_gate_decision_in_txn(wtxn, &owner.stamp(), &receipt, None)?;
        Ok(receipt)
    }

    /// Revokes a standing grant. Revocation is immediate: the row flips to
    /// [`ConsentGrantStatus::Revoked`] in the same transaction as its receipt,
    /// so no in-flight read can observe a revoked row as live.
    pub fn revoke_consent_grant(
        &self,
        owner: &AuthenticatedOwner,
        grant_ref: &str,
    ) -> Result<ConsentReceipt> {
        let key = grant_ref.to_owned();
        let mut wtxn = self.store.env.write_txn()?;
        let Some(mut row) = GRANTS.get(&self.store, &wtxn, &key)? else {
            return Err(Error::Gate(GateError::ConsentGrantNotFound));
        };
        row.status = ConsentGrantStatus::Revoked;
        GRANTS.put(&self.store, &mut wtxn, &key, &row)?;
        super::super::owner_reason::retire_owner_reason_rules_in_txn(
            &self.store,
            &mut wtxn,
            grant_ref,
        )?;
        let receipt = ConsentReceipt::Revoked {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(&mut wtxn, owner, &receipt)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// [`Self::revoke_consent_grant`] as one step of a larger owner act in
    /// the caller's write transaction (a pack's removal ends its setup
    /// grants). A row that is missing or no longer live writes nothing and
    /// returns `None`.
    pub(crate) fn revoke_consent_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        grant_ref: &str,
    ) -> Result<Option<ConsentReceipt>> {
        if !revoke_standing_grant_in_txn(&self.store, wtxn, grant_ref)? {
            return Ok(None);
        }
        let receipt = ConsentReceipt::Revoked {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
        };
        self.append_consent_receipt_in_txn(wtxn, owner, &receipt)?;
        Ok(Some(receipt))
    }

    /// Records quiet in-bound standing reuse — the post-hoc receipt an owner
    /// sees for an auto-shared facet or an auto-run action.
    ///
    /// The reuse itself is authorized by `evaluate_consent`; this door only
    /// records it, and never widens or touches the grant row.
    pub fn record_standing_grant_use(
        &self,
        grant_ref: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let mut wtxn = self.store.env.write_txn()?;
        let receipt = self.record_standing_grant_use_in_txn(&mut wtxn, grant_ref, effect_digest)?;
        wtxn.commit()?;
        Ok(receipt)
    }

    /// [`Self::record_standing_grant_use`] inside the caller's write
    /// transaction, for a door that runs the reuse in that same transaction:
    /// a secret reveal (OF-560) delivers its value beside its receipt.
    pub(crate) fn record_standing_grant_use_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grant_ref: &str,
        effect_digest: EffectDigest,
    ) -> Result<ConsentReceipt> {
        let Some(row) = GRANTS.get(&self.store, &*wtxn, &grant_ref.to_owned())? else {
            return Err(Error::Gate(GateError::ConsentGrantNotFound));
        };
        if !row.is_active() {
            return Err(Error::Gate(GateError::ConsentGrantRevoked));
        }
        let receipt = ConsentReceipt::Used {
            decision_id: crate::store::GateDecisionId::from_bytes(self.store.clock.ulid()?),
            grant_ref: grant_ref.to_owned(),
            effect_digest,
        };
        self.append_consent_gate_decision_in_txn(wtxn, &row.owner_stamp, &receipt, None)?;
        Ok(receipt)
    }
}
