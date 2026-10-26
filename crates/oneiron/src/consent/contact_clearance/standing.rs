//! The owner's disclosure-mode knob, trusted-set pre-clearance and the bound-use receipts.

use super::*;

impl Vault {
    /// The owner's disclosure-mode knob; `auto` when never set.
    pub fn disclosure_offer_mode(&self) -> Result<DisclosureOfferMode> {
        let txn = self.store.env.read_txn()?;
        Ok(DISCLOSURE_OFFER_MODE
            .get(&self.store, &txn, &())?
            .unwrap_or_default())
    }

    /// Sets the disclosure-mode knob. Only the authenticated owner turns it.
    pub fn set_disclosure_offer_mode(
        &self,
        owner: &AuthenticatedOwner,
        mode: DisclosureOfferMode,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            DISCLOSURE_OFFER_MODE.put(&self.store, txn, &(), &mode)?;
            Ok(())
        })
    }

    /// Trusted-set pre-clearance, the honest form of "always yes": the
    /// owner clears each named contact for `scope` in advance, in one
    /// transaction, each with its own receipt naming the set. It is real
    /// standing clearance granted by the owner, replacing each contact's
    /// current one; nothing per-disclosure is auto-approved for anyone else.
    pub fn preclear_contact_disclosure(
        &self,
        owner: &AuthenticatedOwner,
        set_name: &str,
        contacts: &[EntityId],
        scope: Scope,
    ) -> Result<Vec<DisclosureConfirmationReceipt>> {
        let distinct: std::collections::BTreeSet<_> = contacts.iter().collect();
        if contacts.is_empty()
            || contacts.len() > MAX_PRECLEAR_CONTACTS
            || distinct.len() != contacts.len()
        {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "a trusted set names 1..=256 distinct contacts",
            )));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut receipts = Vec::with_capacity(contacts.len());
            for contact in contacts {
                require_active_contact_in_txn(self, &*txn, contact)?;
                let prior =
                    crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, contact)?;
                let created_at = prior
                    .as_ref()
                    .filter(|clearance| clearance.status == DisclosureScopeStatus::Active)
                    .map_or(now, |clearance| clearance.created_at.min(now));
                let clearance = DisclosureScope {
                    scope: scope.clone(),
                    purpose: set_name.to_owned(),
                    status: DisclosureScopeStatus::Active,
                    created_at,
                    updated_at: now,
                };
                disclosure_grant_from_disclosure_scope(
                    &clearance,
                    &contact.to_hex(),
                    CONTACT_CLEARANCE_CLASS,
                )?;
                self.set_counterparty_disclosure_scope_in_txn(txn, contact, &clearance)?;
                let mut receipt = DisclosureConfirmationReceipt {
                    decision_id: GateDecisionId::from_bytes([0; 16]),
                    act: ContactClearanceAct::Precleared,
                    contact_ref: *contact,
                    proposal_ref: None,
                    ask_ref: None,
                    before_digest: contact_clearance_digest(prior.as_ref())?,
                    after_digest: contact_clearance_digest(Some(&clearance))?,
                    once_digest: None,
                };
                receipt.decision_id =
                    self.append_contact_clearance_receipt_in_txn(txn, Some(owner), &receipt)?;
                receipts.push(receipt);
            }
            Ok(receipts)
        })
    }

    /// The quiet bound-use receipt: one covered non-public disclosure reached
    /// `contact_ref` under its active clearance, recorded after the fact on
    /// the receipt family. It authorizes nothing and widens nothing; a
    /// contact with no active clearance refuses.
    pub fn record_contact_clearance_use(
        &self,
        contact_ref: &EntityId,
        disclosure_digest: EffectDigest,
    ) -> Result<GateDecisionId> {
        self.with_write_txn_grouped(|txn| {
            let clearance =
                crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, contact_ref)?
                    .ok_or(Error::Gate(GateError::ConsentGrantNotFound))?;
            if clearance.status != DisclosureScopeStatus::Active {
                return Err(Error::Gate(GateError::ConsentGrantRevoked));
            }
            let digest = contact_clearance_digest(Some(&clearance))?;
            let receipt = DisclosureConfirmationReceipt {
                decision_id: GateDecisionId::from_bytes([0; 16]),
                act: ContactClearanceAct::Used,
                contact_ref: *contact_ref,
                proposal_ref: None,
                ask_ref: Some(disclosure_digest.to_hex()),
                before_digest: digest,
                after_digest: digest,
                once_digest: None,
            };
            self.append_contact_clearance_receipt_in_txn(txn, None, &receipt)
        })
    }

    /// The quiet bound-use receipt of one spent `once` answer (FIX 1413): the
    /// assembly that spent it delivered the offer `proposal_ref` to
    /// `contact_ref` under that answer alone, so no standing clearance is
    /// asked for; the digests are the contact's clearance as it stands, none
    /// included. It names the proposal, authorizes nothing and widens
    /// nothing. Idempotent: a proposal whose Used receipt the ledger holds
    /// already gets no second one (`None`). Only the assembly that spent the
    /// single-use answer records it, so no two writers race to.
    pub(crate) fn record_once_contact_disclosure_use(
        &self,
        contact_ref: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<GateDecisionId>> {
        let named = format!("proposal:{proposal_ref}");
        let recorded = self
            .store
            .gate_decisions_for_grant_ref(&contact_clearance_ref(contact_ref))?
            .iter()
            .any(|record| {
                record
                    .reason_codes
                    .iter()
                    .any(|code| code == CONTACT_DISCLOSURE_REASON_USED)
                    && record
                        .system_notices
                        .iter()
                        .any(|notice| notice.body == named)
            });
        if recorded {
            return Ok(None);
        }
        self.with_write_txn_grouped(|txn| {
            let clearance =
                crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, contact_ref)?;
            let digest = contact_clearance_digest(clearance.as_ref())?;
            let receipt = DisclosureConfirmationReceipt {
                decision_id: GateDecisionId::from_bytes([0; 16]),
                act: ContactClearanceAct::Used,
                contact_ref: *contact_ref,
                proposal_ref: Some(proposal_ref.to_owned()),
                ask_ref: None,
                before_digest: digest,
                after_digest: digest,
                once_digest: None,
            };
            self.append_contact_clearance_receipt_in_txn(txn, None, &receipt)
                .map(Some)
        })
    }

    /// The `once` answers still deliverable to `contacts`, read in `txn`, in
    /// offer-reference order. An answer is void once its contact is gone or
    /// inactive, or once the owner narrowed, revoked or re-cleared the
    /// contact after the offer was filed: the newer act wins, as at confirm.
    /// A spent or missing marker is skipped, never an error. The offer's
    /// expiry bounded only the answer; the single-use marker bounds the
    /// delivery.
    pub(crate) fn once_contact_disclosures_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        contacts: &BTreeSet<EntityId>,
    ) -> Result<Vec<OnceContactDisclosure>> {
        let mut deliverable = Vec::new();
        for (proposal_ref, proposal) in self.settled_contact_disclosure_offers_in_txn(
            txn,
            ContactDisclosureOutcome::Once.as_str(),
        )? {
            let contact = &proposal.offer.contact_ref;
            if !contacts.contains(contact) {
                continue;
            }
            match require_active_contact_in_txn(self, txn, contact) {
                Ok(()) => {}
                Err(Error::EntityNotFound | Error::InvalidEntityType(_) | Error::Gate(_)) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
            let clearance =
                match crate::disclosure::contact_clearance_in_txn(&self.store, txn, contact) {
                    Ok(clearance) => clearance,
                    Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => continue,
                    Err(error) => return Err(error),
                };
            if contact_clearance_digest(clearance.as_ref())? != proposal.prior_clearance_digest {
                continue;
            }
            let authorization = match approve_once_authorization_in_txn(
                &self.store,
                txn,
                &proposal.once_digest(&proposal_ref)?,
            ) {
                Ok(Some(authorization)) => authorization,
                Ok(None) | Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => continue,
                Err(error) => return Err(error),
            };
            deliverable.push(OnceContactDisclosure {
                proposal_ref,
                proposal,
                authorization,
            });
        }
        Ok(deliverable)
    }
}
