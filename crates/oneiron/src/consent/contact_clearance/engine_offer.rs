//! The engine's own contact-disclosure offer for a PERSON's first entry into
//! a room (OF-365 P5, FIX 2288): an ask the owner answers, never an admit.

use super::*;

/// The id the engine files its own offers under: no agent speaks for them,
/// and the owner who settles them never filed them. No parts.
const ENGINE_OFFER_FILER: &[u8] = b"oneiron:contact-disclosure-engine-filer:v1";

/// What the owner reads on an entry offer the engine filed.
const PERSON_ENTRY_OFFER_PURPOSE: &str =
    "A person entered this room for the first time: what may they see?";

/// An entry offer's term: the longest a widen proposal may stay open.
const PERSON_ENTRY_OFFER_TERM_SECS: u64 = 3600;

impl Vault {
    /// [`Self::file_person_entry_disclosure_offer_in_txn`] in its own writer,
    /// for an entry door or host that records the entry first.
    pub fn file_person_entry_disclosure_offer(
        &self,
        contact: EntityId,
        room: &EntityId,
        scope: Scope,
        owner_ref: &str,
    ) -> Result<Option<WidenProposal>> {
        self.with_write_txn_grouped(|txn| {
            self.file_person_entry_disclosure_offer_in_txn(txn, contact, room, scope, owner_ref)
        })
    }

    /// Files, as the engine, the P5 offer for `contact`'s first entry into
    /// `room`: its clearance for `scope` on the room's channel, the contact
    /// the one party it reaches, for the owner `owner_ref` to answer at the
    /// entry's confirm. The offer confers nothing; only the owner's confirm
    /// settles it. Asks nothing (`None`) while the owner's disclosure mode
    /// is always-ask, as the owner starts every new clearance then, and for
    /// a contact already cleared (standing or pre-cleared), whose row
    /// already covers the entry. The contact must be live and active.
    pub(crate) fn file_person_entry_disclosure_offer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        contact: EntityId,
        room: &EntityId,
        scope: Scope,
        owner_ref: &str,
    ) -> Result<Option<WidenProposal>> {
        if DISCLOSURE_OFFER_MODE
            .get(&self.store, &*txn, &())?
            .unwrap_or_default()
            == DisclosureOfferMode::AlwaysAsk
        {
            return Ok(None);
        }
        require_active_contact_in_txn(self, &*txn, &contact)?;
        let prior = crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, &contact)?;
        if prior
            .as_ref()
            .is_some_and(|clearance| clearance.status == DisclosureScopeStatus::Active)
        {
            return Ok(None);
        }
        let offer = ContactDisclosureOffer {
            contact_ref: contact,
            scope,
            purpose: PERSON_ENTRY_OFFER_PURPOSE.to_owned(),
            channel: contact_disclosure_room_channel(room),
            beneficiary_ref: contact.to_hex(),
            ask_ref: None,
        };
        offer.validate()?;
        let proposal = ContactDisclosureProposal {
            prior_clearance_digest: contact_clearance_digest(prior.as_ref())?,
            offer,
        };
        let filer = WriteActor::new(
            EntityId::derive(ENGINE_OFFER_FILER, &[])?,
            EdgeActorClass::System,
        );
        let expires_at = self.store.clock.now_recorded_at() + PERSON_ENTRY_OFFER_TERM_SECS;
        self.file_contact_disclosure_offer_in_txn(
            txn,
            filer,
            &proposal,
            owner_ref,
            expires_at,
            Vec::new(),
        )
        .map(Some)
    }
}
