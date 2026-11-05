//! FIX 4325: the native credential slice for a trusted contact without an app
//! account: minting their holder-bound slip, and the read/accept/revoke doors
//! that take the opaque [`TrustedContactCredential`] instead of a generally
//! constructible proof.
//!
//! Mint binds the exact naming the person named (person/contact/version) under
//! the namer's own proof, in the naming's writer. The contact's key is
//! supplied by the caller; how the contact generated it and how the slip
//! reaches them (link, delivery, control proof) is OPEN: native mint is the
//! invitation producer, not a transport or identity closure. Acceptance via
//! the credential proves holder possession of the bound key plus the naming's
//! own liveness, not phone identity.
//!
//! Isolation: ordinary verification never mints a general
//! [`crate::authority::VerifiedSlip`] for a contact-bound slip
//! ([`CapabilitySlip::verify_trusted_contact`] is the
//! only verifier that admits one, and it mints only the opaque credential).
//! Every door below rechecks the credential in its acting transaction.

use std::collections::BTreeSet;

use super::trusted_contact::RELATIONS;
use super::trusted_contact::invalid;
use super::trusted_contact_notice::consent_change_guard;
use super::{
    TrustedContact, TrustedContactAcceptance, TrustedContactParty, TrustedContactRevocation,
};
use crate::Vault;
use crate::authority::{
    ACTOR_CLASS_HUMAN, CapabilitySlip, HostSlipIssuer, SlipClaims, TrustedContactCredential,
    TrustedContactSlipBinding, invalid_authority,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use oneiron_authority::federation::{Scope, ScopeAxis};

fn random_slip_id() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    id
}

fn not_a_party(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

impl Vault {
    /// Mints, in the naming's writer, the holder-bound slip of `contact` for
    /// the exact trusted-contact naming `person` named them at (FIX 4325):
    /// `version`, which must be the current version, unrevoked, both sides
    /// live PERSONs. It binds `holder_key`, the public key the contact
    /// generated on their own device; no private key is delivered anywhere.
    /// It holds for the contact PERSON, carries no verb (the contact's doors
    /// alone take it), and ends at `expires_at`, the caller's own expiry.
    /// The namer's proof authorizes the mint; how the slip reaches the
    /// contact is OPEN.
    pub fn mint_trusted_contact_slip(
        &self,
        person: &AuthenticatedOwner,
        contact: EntityId,
        version: u64,
        issuer: &HostSlipIssuer,
        holder_key: [u8; 32],
        expires_at: u64,
    ) -> Result<CapabilitySlip> {
        self.with_write_txn(|wtxn| {
            let person = person.revalidate_person_in_txn(self, wtxn)?;
            if contact == person || !crate::consent::person_is_live_in_txn(self, wtxn, &contact)? {
                return Err(invalid("a trusted contact is another live person"));
            }
            let relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no such trusted contact"))?;
            if relation.revoked.is_some() {
                return Err(invalid("this trusted-contact naming was revoked"));
            }
            if relation.version != version {
                return Err(invalid("this is not the current trusted-contact naming"));
            }
            let vault_id = self
                .authority_view_readonly_in_txn(wtxn)?
                .vault_id
                .ok_or_else(invalid_authority)?;
            let now = self.instant_in_txn(wtxn)?.secs();
            let scope = Scope {
                verbs: ScopeAxis::Bottom,
                ..Scope::top()
            };
            let claims = SlipClaims {
                slip_id: random_slip_id(),
                vault_id,
                parent_id: None,
                holder_ref: contact.to_hex(),
                binding_key: holder_key,
                scope,
                issued_at: now,
                expires_at,
                ttl_secs: expires_at.checked_sub(now).ok_or_else(invalid_authority)?,
                single_use: false,
                records: BTreeSet::new(),
                channels: BTreeSet::new(),
                actor_class: Some(ACTOR_CLASS_HUMAN.to_owned()),
                org_ref: None,
                grant_ref: None,
                invitation_ref: None,
                delegation: None,
                comm: None,
                trusted_contact: Some(TrustedContactSlipBinding { person, version }),
            };
            self.mint_slip_in_txn(wtxn, issuer, claims)
        })
    }

    /// The trusted-contact naming `credential` binds (FIX 4325): the exact
    /// relation row, unrevoked at the bound version, the credential still
    /// holding now. The contact inspects what they were shown before they
    /// accept or revoke it.
    pub fn trusted_contact_for_credential(
        &self,
        credential: &TrustedContactCredential,
    ) -> Result<TrustedContact> {
        let rtxn = self.store.env.read_txn()?;
        if !self.trusted_contact_holds_in_txn(&rtxn, credential)? {
            return Err(not_a_party(
                "this trusted-contact credential no longer holds",
            ));
        }
        let person = credential.person();
        let contact =
            EntityId::from_hex(credential.holder_ref()).map_err(|_| invalid_authority())?;
        let relation = RELATIONS
            .get(&self.store, &rtxn, &(person, contact))?
            .ok_or_else(|| not_a_party("no such trusted contact"))?;
        if relation.version != credential.version() || relation.revoked.is_some() {
            return Err(not_a_party("this is not the naming the contact was shown"));
        }
        Ok(relation)
    }

    /// The contact accepts `person`'s naming through their credential
    /// (FIX 4325): the naming the credential binds, as an adult. Only the
    /// bound contact's own holder proof accepts, and only while the naming
    /// still stands at that version in the acting transaction.
    pub fn accept_trusted_contact_with_credential(
        &self,
        credential: &TrustedContactCredential,
        adult: bool,
        now: u64,
    ) -> Result<TrustedContact> {
        if !adult {
            return Err(invalid("a trusted contact is an adult"));
        }
        self.with_write_txn(|wtxn| {
            if !self.trusted_contact_holds_in_txn(wtxn, credential)? {
                return Err(not_a_party(
                    "this trusted-contact credential no longer holds",
                ));
            }
            let person = credential.person();
            let contact =
                EntityId::from_hex(credential.holder_ref()).map_err(|_| invalid_authority())?;
            let mut relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no one named this person a trusted contact"))?;
            if relation.version != credential.version() || relation.revoked.is_some() {
                return Err(invalid("this is not the naming the contact was shown"));
            }
            relation.accepted = Some(TrustedContactAcceptance { at: now, adult });
            RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            Ok(relation)
        })
    }

    /// The contact ends the naming their credential binds (FIX 4325): the
    /// exact relation row, unrevoked at the bound version. A revoked relation
    /// never fires, a notice already staged from it is not sent, and an ask
    /// still open about it is superseded: this waits for a send already under
    /// way, and none starts once it returns. The person revokes through
    /// [`Self::revoke_trusted_contact`]; this door is the contact's own.
    pub fn revoke_trusted_contact_with_credential(
        &self,
        credential: &TrustedContactCredential,
        now: u64,
    ) -> Result<TrustedContact> {
        let _order = consent_change_guard(self);
        self.with_write_txn(|wtxn| {
            if !self.trusted_contact_holds_in_txn(wtxn, credential)? {
                return Err(not_a_party(
                    "this trusted-contact credential no longer holds",
                ));
            }
            let person = credential.person();
            let contact =
                EntityId::from_hex(credential.holder_ref()).map_err(|_| invalid_authority())?;
            let mut relation = RELATIONS
                .get(&self.store, wtxn, &(person, contact))?
                .ok_or_else(|| not_a_party("no such trusted contact"))?;
            if relation.version != credential.version() {
                return Err(invalid("this is not the naming the contact was shown"));
            }
            if relation.revoked.is_none() {
                relation.revoked = Some(TrustedContactRevocation {
                    at: now,
                    by: TrustedContactParty::Contact,
                });
                RELATIONS.put(&self.store, wtxn, &(person, contact), &relation)?;
            }
            super::trusted_contact::supersede_open_asks_in_txn(self, wtxn, person, contact, now)?;
            Ok(relation)
        })
    }
}
