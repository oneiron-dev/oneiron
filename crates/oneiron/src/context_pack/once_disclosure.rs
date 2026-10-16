//! Approve-once delivery (OF-365): the owner's `once` answer to a
//! contact-disclosure offer discloses that offer's Scope to that contact in
//! the one assembly that spends it, on the channel the offer named, and in
//! no later assembly.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::federation::Scope;
use crate::interlocutor::{InterlocutorClass, InterlocutorSet};
use crate::{Result, Vault};

impl Vault {
    /// Spends the `once` answers this assembly delivers and returns each
    /// answered contact's Scope, for
    /// [`DisclosureContext::resolve_with_once`](crate::DisclosureContext::resolve_with_once).
    ///
    /// An answer applies only to a KnownContact of `set`, only when its offer
    /// named one of `channels` (`consent::contact_disclosure_room_channel`,
    /// `consent::contact_disclosure_voice_channel`), and only when that
    /// contact itself was the offer's beneficiary. With an unknown party
    /// present nothing is spent. A contact with several answers waiting
    /// spends one, the first by offer reference; the rest stay for later
    /// assemblies. The check and the spend share one write
    /// transaction, so no two assemblies deliver the same answer. An assembly
    /// that fails after the spend loses the answer and the owner asks again:
    /// that fails closed.
    pub fn spend_once_contact_disclosures(
        &self,
        set: &InterlocutorSet,
        channels: &BTreeSet<String>,
    ) -> Result<BTreeMap<EntityId, Scope>> {
        let mut contacts = BTreeSet::new();
        for party in set.non_owner() {
            match (party.class(), party.contact_ref()) {
                (InterlocutorClass::KnownContact, Some(hex)) => {
                    contacts.insert(EntityId::from_hex(hex)?);
                }
                // Anyone else present holds the empty clearance, so the meet
                // is public-only: no answer could reach its contact, and
                // spending one would only lose it.
                _ => return Ok(BTreeMap::new()),
            }
        }
        if channels.is_empty() || contacts.is_empty() {
            return Ok(BTreeMap::new());
        }
        let delivers = |offer: &crate::consent::ContactDisclosureOffer| {
            channels.contains(&offer.channel) && offer.beneficiary_ref == offer.contact_ref.to_hex()
        };
        // Most assemblies have no answer waiting: they look on a reader and
        // never take the writer.
        {
            let txn = self.store.env.read_txn()?;
            if !self
                .once_contact_disclosures_in_txn(&txn, &contacts)?
                .iter()
                .any(|once| delivers(&once.proposal.offer))
            {
                return Ok(BTreeMap::new());
            }
        }
        self.with_write_txn_grouped(|wtxn| {
            let mut spent = BTreeMap::new();
            for once in self.once_contact_disclosures_in_txn(&*wtxn, &contacts)? {
                let offer = &once.proposal.offer;
                if !delivers(offer) || spent.contains_key(&offer.contact_ref) {
                    continue;
                }
                crate::consent::spend_approve_once_in_txn(&self.store, wtxn, &once.authorization)?;
                tracing::info!(
                    proposal_ref = %once.proposal_ref,
                    channel = %offer.channel,
                    "approve-once contact disclosure delivered"
                );
                spent.insert(offer.contact_ref, offer.scope.clone());
            }
            Ok(spent)
        })
    }
}
