//! Contact clearance: the owner's authenticated answer to one frozen
//! contact-disclosure offer (OF-365, the ILDF2 consent channel).
//!
//! A classifier, a companion or an agent can only OFFER. It files a frozen
//! [`ContactDisclosureProposal`] on the widen-proposal table beside every
//! other widen ([`super::widen`]). Only [`Vault::confirm_contact_disclosure`],
//! under an [`AuthenticatedOwner`], settles it, in one write transaction that
//! revalidates the owner, the active contact and the exact prior clearance:
//! `standing` writes the contact's canonical clearance Scope, its
//! owner-visible mirror and a Gate receipt; `once` mints an approve-once
//! marker for exactly this disclosure and persists no Scope; `deny` settles
//! with no clearance. The lineage that opened an offer cannot settle it.
//!
//! The contact's clearance row stays the one authority. The registry rows and
//! the consent bound are projections of it, never a second editable store;
//! narrowing and revoking rewrite that same row.

use std::collections::BTreeSet;

use rmpv::Value;

use super::AuthenticatedOwner;
use super::adapters::disclosure_grant_from_disclosure_scope;
use super::doors::approve_once_authorization_in_txn;
use super::effect::{ApproveOnceAuthorization, EffectDigest};
use super::grant::CONSENT_CONTENT_KIND;
use super::support::normalized_ref;
use super::widen::WidenProposal;
use crate::authority::VerifiedSlip;
use crate::batch::EntityMetadataHeader;
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus, encode_disclosure_scope_body};
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, GateError};
use crate::federation::Scope;
use crate::federation::scope_codec::{decode_scope_value, encode_scope_value};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};

/// Pinned label of the typed contact-disclosure widen payload.
pub const CONTACT_DISCLOSURE_WIDEN_KIND: &str = "propose_contact_disclosure";

/// The credential verb an agent offers under: the disclosure-widen verb.
const CONTACT_DISCLOSURE_OFFER_VERB: &str = "propose_disclosure_widen";

/// Pinned one-tap revoke command for a contact clearance registry row.
pub const CONTACT_CLEARANCE_REVOKE_COMMAND: &str = "consent.revoke_contact_disclosure";

/// Pinned class of the bound a contact clearance projects to.
pub const CONTACT_CLEARANCE_CLASS: &str = "contact_disclosure";

/// Gate reason code: the owner cleared a contact standing.
pub const CONTACT_DISCLOSURE_REASON_STANDING: &str = "gate.consent.contact_disclosure.standing";

/// Gate reason code: the owner narrowed a contact's clearance.
pub const CONTACT_DISCLOSURE_REASON_NARROWED: &str = "gate.consent.contact_disclosure.narrowed";

/// Gate reason code: the owner revoked a contact's clearance.
pub const CONTACT_DISCLOSURE_REASON_REVOKED: &str = "gate.consent.contact_disclosure.revoked";

/// Gate reason code: the owner pre-cleared a named trusted set.
pub const CONTACT_DISCLOSURE_REASON_PRECLEARED: &str = "gate.consent.contact_disclosure.precleared";

/// Gate reason code: one covered non-public disclosure reached a cleared
/// contact (a quiet bound-use receipt, never an authorization).
pub const CONTACT_DISCLOSURE_REASON_USED: &str = "gate.consent.contact_disclosure.used";

/// Most contacts one trusted-set pre-clearance names.
const MAX_PRECLEAR_CONTACTS: usize = 256;

/// The owner's disclosure-mode knob: a singleton row, default auto.
const DISCLOSURE_OFFER_MODE: SideTable<(), DisclosureOfferMode, Raw> =
    SideTable::new(&side_table::DISCLOSURE_OFFER_MODE);

const ONCE_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.contact_disclosure_once.v1";
const CLEARANCE_DIGEST_DOMAIN: &[u8] = b"oneiron.consent.contact_clearance.v1";
const PROPOSAL_KEYS: [&str; 7] = [
    "contact",
    "scope",
    "purpose",
    "channel",
    "beneficiary",
    "ask",
    "prior",
];

/// What an offerer asks the owner to clear for one contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactDisclosureOffer {
    /// The CID-7 contact the clearance is for.
    pub contact_ref: EntityId,
    /// The exact clearance Scope asked for.
    pub scope: Scope,
    /// Human-readable purpose, trimmed, 1..=512 bytes.
    pub purpose: String,
    /// The channel the disclosure travels on. A tap on one channel never
    /// clears another.
    pub channel: String,
    /// The one party the disclosure reaches: the singleton audience of the
    /// bound this clearance projects to.
    pub beneficiary_ref: String,
    /// The private TASK ask this offer rides, when one exists.
    pub ask_ref: Option<String>,
}

impl ContactDisclosureOffer {
    fn validate(&self) -> Result<()> {
        let refs = [
            ("contact disclosure channel", Some(&self.channel)),
            (
                "contact disclosure beneficiary",
                Some(&self.beneficiary_ref),
            ),
            ("contact disclosure ask", self.ask_ref.as_ref()),
        ];
        for (label, value) in refs {
            if let Some(value) = value
                && normalized_ref(label, value.clone())? != *value
            {
                return Err(invalid_offer());
            }
        }
        // The offer must project to the one typed bound a standing answer
        // would: a singleton audience over a non-empty canonical Scope.
        let clearance = DisclosureScope::new(self.scope.clone(), self.purpose.clone(), 0)?;
        disclosure_grant_from_disclosure_scope(
            &clearance,
            &self.beneficiary_ref,
            CONTACT_CLEARANCE_CLASS,
        )?;
        Ok(())
    }
}

/// One frozen offer: the [`ContactDisclosureOffer`] plus the contact's
/// clearance digest when it was filed. The owner confirms exactly this, and
/// a clearance changed since makes the offer stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactDisclosureProposal {
    pub offer: ContactDisclosureOffer,
    /// [`contact_clearance_digest`] of the row the offer was filed against;
    /// all zero when the contact had none.
    pub prior_clearance_digest: [u8; 32],
}

impl ContactDisclosureProposal {
    pub(super) fn to_value(&self) -> Result<Value> {
        let offer = &self.offer;
        Ok(Value::Map(vec![
            (
                Value::from("contact"),
                Value::Binary(offer.contact_ref.as_bytes().to_vec()),
            ),
            (
                Value::from("scope"),
                encode_scope_value(&offer.scope).map_err(|_| invalid_offer())?,
            ),
            (Value::from("purpose"), Value::from(offer.purpose.as_str())),
            (Value::from("channel"), Value::from(offer.channel.as_str())),
            (
                Value::from("beneficiary"),
                Value::from(offer.beneficiary_ref.as_str()),
            ),
            (
                Value::from("ask"),
                offer.ask_ref.as_deref().map_or(Value::Nil, Value::from),
            ),
            (
                Value::from("prior"),
                Value::Binary(self.prior_clearance_digest.to_vec()),
            ),
        ]))
    }

    pub(super) fn from_value(value: &Value) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(invalid_offer());
        };
        if entries
            .iter()
            .map(|(key, _)| key.as_str())
            .ne(PROPOSAL_KEYS.iter().map(|key| Some(*key)))
        {
            return Err(invalid_offer());
        }
        let [
            (_, Value::Binary(contact)),
            (_, scope),
            (_, purpose),
            (_, channel),
            (_, beneficiary),
            (_, ask),
            (_, Value::Binary(prior)),
        ] = entries.as_slice()
        else {
            return Err(invalid_offer());
        };
        let text = |value: &Value| value.as_str().map(str::to_owned).ok_or_else(invalid_offer);
        let contact_ref =
            EntityId::from_bytes(contact.as_slice().try_into().map_err(|_| invalid_offer())?)
                .map_err(|_| invalid_offer())?;
        let ask_ref = match ask {
            Value::Nil => None,
            ask => Some(text(ask)?),
        };
        let proposal = Self {
            offer: ContactDisclosureOffer {
                contact_ref,
                scope: decode_scope_value(scope).map_err(|_| invalid_offer())?,
                purpose: text(purpose)?,
                channel: text(channel)?,
                beneficiary_ref: text(beneficiary)?,
                ask_ref,
            },
            prior_clearance_digest: prior.as_slice().try_into().map_err(|_| invalid_offer())?,
        };
        proposal.offer.validate()?;
        Ok(proposal)
    }

    /// The approve-once digest a `once` answer to offer `proposal_ref` mints:
    /// exactly this contact, Scope, channel, beneficiary and ask. The
    /// assembly that discloses under it recomputes and spends it.
    pub fn once_digest(&self, proposal_ref: &str) -> Result<EffectDigest> {
        let mut payload = Vec::new();
        rmpv::encode::write_value(&mut payload, &self.to_value()?).map_err(|_| invalid_offer())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ONCE_DIGEST_DOMAIN);
        for field in [proposal_ref.as_bytes(), payload.as_slice()] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        Ok(EffectDigest::from_bytes(*hasher.finalize().as_bytes()))
    }
}

/// The owner's answer to one contact-disclosure offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactDisclosureOutcome {
    /// Disclose this once; no clearance persists.
    Once,
    /// Clear the contact for this Scope until the owner narrows or revokes it.
    Standing,
    /// Refuse; the contact keeps its current clearance.
    Deny,
}

impl ContactDisclosureOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Standing => "standing",
            Self::Deny => "deny",
        }
    }
}

/// Which owner act a [`DisclosureConfirmationReceipt`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactClearanceAct {
    /// An offer settled with the owner's answer.
    Settled(ContactDisclosureOutcome),
    /// The owner narrowed a standing clearance.
    Narrowed,
    /// The owner revoked a standing clearance.
    Revoked,
    /// The owner pre-cleared this contact as part of a named trusted set.
    Precleared,
    /// One covered non-public disclosure reached this cleared contact.
    Used,
}

impl ContactClearanceAct {
    const fn gate_outcome(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Settled(_) | Self::Narrowed | Self::Precleared | Self::Used => "approved",
        }
    }

    const fn reason_code(self) -> &'static str {
        match self {
            Self::Revoked => CONTACT_DISCLOSURE_REASON_REVOKED,
            Self::Narrowed => CONTACT_DISCLOSURE_REASON_NARROWED,
            Self::Settled(_) => CONTACT_DISCLOSURE_REASON_STANDING,
            Self::Precleared => CONTACT_DISCLOSURE_REASON_PRECLEARED,
            Self::Used => CONTACT_DISCLOSURE_REASON_USED,
        }
    }
}

/// The disclosure-mode knob (ILDF2 consent channel; default auto). No mode
/// moves the confirm surface: a new clearance still lands only on the
/// owner's authenticated confirm or the owner's own pre-clearance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DisclosureOfferMode {
    /// The companion never offers on its own; the owner starts every new
    /// clearance.
    AlwaysAsk,
    /// The companion may offer a clearance when it reads the room.
    #[default]
    Auto,
    /// The owner clears named trusted sets in advance
    /// ([`Vault::preclear_contact_disclosure`]); offers stay allowed. Never a
    /// blanket auto-approve.
    AlwaysYes,
}

impl DisclosureOfferMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysAsk => "always_ask",
            Self::Auto => "auto",
            Self::AlwaysYes => "always_yes",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "always_ask" => Some(Self::AlwaysAsk),
            "auto" => Some(Self::Auto),
            "always_yes" => Some(Self::AlwaysYes),
            _ => None,
        }
    }
}

impl RawValue for DisclosureOfferMode {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.as_str().as_bytes().to_vec())
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        std::str::from_utf8(raw)
            .ok()
            .and_then(Self::parse)
            .ok_or_else(|| invalid_offer().into())
    }
}

/// The owner's contact-clearance act as the Gate receipt family records it:
/// the offer and ask it answered, the contact, the clearance digest before
/// (the revert reference) and after, and the decision it landed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureConfirmationReceipt {
    pub decision_id: GateDecisionId,
    pub act: ContactClearanceAct,
    pub contact_ref: EntityId,
    pub proposal_ref: Option<String>,
    pub ask_ref: Option<String>,
    pub before_digest: [u8; 32],
    pub after_digest: [u8; 32],
    /// The approve-once digest a `once` answer minted, for the assembly that
    /// spends it.
    pub once_digest: Option<EffectDigest>,
}

/// The registry reference of one contact's clearance row.
#[must_use]
pub fn contact_clearance_ref(contact: &EntityId) -> String {
    format!("contact_clearance:{}", contact.to_hex())
}

/// The channel a text room's disclosure travels on: `room:<room hex>`. The
/// offer that files a disclosure and the assembly that delivers it both name
/// a room this way.
#[must_use]
pub fn contact_disclosure_room_channel(room: &EntityId) -> String {
    format!("room:{}", room.to_hex())
}

/// The channel a voice session's disclosure travels on:
/// `voice:<voice_session_ref>`.
#[must_use]
pub fn contact_disclosure_voice_channel(voice_session_ref: &str) -> String {
    format!("voice:{voice_session_ref}")
}

/// One `once` answer an assembly may still deliver: the settled offer, for a
/// live and active contact whose clearance is the one the offer was filed
/// against, with its approve-once marker still available.
pub(crate) struct OnceContactDisclosure {
    pub(crate) proposal_ref: String,
    pub(crate) proposal: ContactDisclosureProposal,
    pub(crate) authorization: ApproveOnceAuthorization,
}

/// Domain-separated digest of a contact's clearance row; all zero for none.
fn contact_clearance_digest(clearance: Option<&DisclosureScope>) -> Result<[u8; 32]> {
    let Some(clearance) = clearance else {
        return Ok([0; 32]);
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLEARANCE_DIGEST_DOMAIN);
    hasher.update(&encode_disclosure_scope_body(clearance)?);
    Ok(*hasher.finalize().as_bytes())
}

impl Vault {
    /// A verified agent offers a contact clearance. The offer confers no
    /// authority: only the owner's [`Vault::confirm_contact_disclosure`]
    /// settles it.
    pub fn offer_contact_disclosure(
        &self,
        credential: &VerifiedSlip,
        offer: ContactDisclosureOffer,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        let claims = credential.claims();
        if claims.single_use {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "single-use credential cannot file a contact-disclosure offer",
            )));
        }
        if claims.actor_class.as_deref() != Some("agent")
            || !credential.allows_verb(CONTACT_DISCLOSURE_OFFER_VERB)
        {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "agent credential lacks disclosure offer authority",
            )));
        }
        let agent = EntityId::from_hex(&claims.holder_ref).map_err(|_| {
            Error::Gate(GateError::InvalidConsentBound(
                "agent credential lacks entity binding",
            ))
        })?;
        self.file_contact_disclosure_offer(
            WriteActor::new(agent, EdgeActorClass::Agent),
            Some(credential),
            vec![claims.slip_id],
            offer,
            owner_ref,
            expires_at,
        )
    }

    /// The engine's own offer, from a classifier or a companion turn: `actor`
    /// is the live agent the offer speaks for, and no agent credential is
    /// fabricated for it. It is still only an offer.
    pub fn offer_contact_disclosure_as_engine(
        &self,
        actor: WriteActor,
        offer: ContactDisclosureOffer,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        self.file_contact_disclosure_offer(actor, None, Vec::new(), offer, owner_ref, expires_at)
    }

    fn file_contact_disclosure_offer(
        &self,
        actor: WriteActor,
        credential: Option<&VerifiedSlip>,
        opener_lineage: Vec<[u8; 32]>,
        offer: ContactDisclosureOffer,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        if actor.actor_class() != EdgeActorClass::Agent {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "contact-disclosure offerer must be an agent",
            )));
        }
        offer.validate()?;
        self.with_write_txn_grouped(|txn| {
            if let Some(credential) = credential
                && !self.capability_slip_is_live_in_txn(&*txn, credential)?
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "agent credential is no longer live",
                )));
            }
            let raw = self
                .store
                .port_entity_raw(&*txn, &actor.entity_ref())?
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
            if DISCLOSURE_OFFER_MODE
                .get(&self.store, &*txn, &())?
                .unwrap_or_default()
                == DisclosureOfferMode::AlwaysAsk
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "disclosure mode is always ask: only the owner starts a clearance",
                )));
            }
            require_active_contact_in_txn(self, &*txn, &offer.contact_ref)?;
            let prior = crate::disclosure::contact_clearance_in_txn(
                &self.store,
                &*txn,
                &offer.contact_ref,
            )?;
            let proposal = ContactDisclosureProposal {
                prior_clearance_digest: contact_clearance_digest(prior.as_ref())?,
                offer,
            };
            self.file_contact_disclosure_offer_in_txn(
                txn,
                &actor.entity_ref(),
                &proposal,
                owner_ref,
                expires_at,
                opener_lineage,
            )
        })
    }

    /// The owner's answer to one frozen contact-disclosure offer.
    ///
    /// One write transaction revalidates the owner, refuses the lineage that
    /// opened the offer, requires the offer to be this holder's, unexpired,
    /// unsettled and byte-identical to `expected_delta`, requires the contact
    /// to be live and active, and requires its clearance to be exactly the one
    /// the offer was filed against. Then `standing` writes the canonical
    /// clearance row, its mirror and a Gate receipt; `once` mints the
    /// approve-once marker for exactly this disclosure; `deny` records the
    /// refusal. Every answer settles the offer once.
    pub fn confirm_contact_disclosure(
        &self,
        owner: &AuthenticatedOwner,
        proposal_ref: &str,
        expected_delta: &[u8],
        outcome: ContactDisclosureOutcome,
    ) -> Result<DisclosureConfirmationReceipt> {
        self.with_write_txn_grouped(|txn| {
            self.confirm_contact_disclosure_in_txn(
                txn,
                owner,
                proposal_ref,
                expected_delta,
                outcome,
            )
        })
    }

    /// [`Self::confirm_contact_disclosure`] inside the caller's write
    /// transaction, for an owner door that settles the offer together with
    /// its own record.
    pub(crate) fn confirm_contact_disclosure_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        proposal_ref: &str,
        expected_delta: &[u8],
        outcome: ContactDisclosureOutcome,
    ) -> Result<DisclosureConfirmationReceipt> {
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let proposal = self.open_contact_disclosure_offer_in_txn(
            &*txn,
            owner,
            proposal_ref,
            expected_delta,
            now,
        )?;
        let offer = &proposal.offer;
        require_active_contact_in_txn(self, &*txn, &offer.contact_ref)?;
        let prior =
            crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, &offer.contact_ref)?;
        let before = contact_clearance_digest(prior.as_ref())?;
        if before != proposal.prior_clearance_digest {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "contact clearance changed since the offer was filed",
            )));
        }
        let mut receipt = DisclosureConfirmationReceipt {
            decision_id: GateDecisionId::from_bytes([0; 16]),
            act: ContactClearanceAct::Settled(outcome),
            contact_ref: offer.contact_ref,
            proposal_ref: Some(proposal_ref.to_owned()),
            ask_ref: offer.ask_ref.clone(),
            before_digest: before,
            after_digest: before,
            once_digest: None,
        };
        match outcome {
            ContactDisclosureOutcome::Standing => {
                let created_at = prior
                    .as_ref()
                    .filter(|clearance| clearance.status == DisclosureScopeStatus::Active)
                    .map_or(now, |clearance| clearance.created_at.min(now));
                let clearance = DisclosureScope {
                    scope: offer.scope.clone(),
                    purpose: offer.purpose.clone(),
                    status: DisclosureScopeStatus::Active,
                    created_at,
                    updated_at: now,
                };
                self.set_counterparty_disclosure_scope_in_txn(txn, &offer.contact_ref, &clearance)?;
                receipt.after_digest = contact_clearance_digest(Some(&clearance))?;
                receipt.decision_id =
                    self.append_contact_clearance_receipt_in_txn(txn, Some(owner), &receipt)?;
            }
            ContactDisclosureOutcome::Once => {
                let digest = proposal.once_digest(proposal_ref)?;
                receipt.decision_id = self.approve_once_in_txn(txn, owner, digest)?.decision_id();
                receipt.once_digest = Some(digest);
            }
            ContactDisclosureOutcome::Deny => {
                let digest = proposal.once_digest(proposal_ref)?;
                receipt.decision_id = self.deny_consent_in_txn(txn, owner, digest)?.decision_id();
            }
        }
        self.settle_widen_offer_in_txn(txn, proposal_ref, outcome.as_str(), receipt.decision_id)?;
        Ok(receipt)
    }

    /// Narrows a contact's standing clearance to `scope`, which must sit
    /// inside the current one. Narrowing takes authority away, so it needs no
    /// offer; it rewrites the one clearance row, its mirror and a receipt.
    pub fn narrow_contact_disclosure(
        &self,
        owner: &AuthenticatedOwner,
        contact_ref: &EntityId,
        scope: Scope,
    ) -> Result<DisclosureConfirmationReceipt> {
        self.rewrite_contact_clearance(
            owner,
            contact_ref,
            ContactClearanceAct::Narrowed,
            |current| {
                if !scope.is_narrowing_of(&current.scope) {
                    return Err(Error::Gate(GateError::InvalidConsentBound(
                        "a narrowed clearance must sit inside the current one",
                    )));
                }
                current.scope = scope;
                Ok(())
            },
        )
    }

    /// Revokes a contact's standing clearance. The row stays, Revoked, so it
    /// admits nothing (Scope bottom) and the registry shows its history; the
    /// generic consent-grant revoke does not reach it.
    pub fn revoke_contact_disclosure(
        &self,
        owner: &AuthenticatedOwner,
        contact_ref: &EntityId,
    ) -> Result<DisclosureConfirmationReceipt> {
        self.rewrite_contact_clearance(
            owner,
            contact_ref,
            ContactClearanceAct::Revoked,
            |current| {
                current.status = DisclosureScopeStatus::Revoked;
                Ok(())
            },
        )
    }

    fn rewrite_contact_clearance(
        &self,
        owner: &AuthenticatedOwner,
        contact_ref: &EntityId,
        act: ContactClearanceAct,
        rewrite: impl FnOnce(&mut DisclosureScope) -> Result<()>,
    ) -> Result<DisclosureConfirmationReceipt> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let Some(prior) =
                crate::disclosure::contact_clearance_in_txn(&self.store, &*txn, contact_ref)?
            else {
                return Err(Error::Gate(GateError::ConsentGrantNotFound));
            };
            if prior.status != DisclosureScopeStatus::Active {
                return Err(Error::Gate(GateError::ConsentGrantRevoked));
            }
            let mut clearance = prior.clone();
            rewrite(&mut clearance)?;
            clearance.updated_at = now.max(clearance.created_at);
            self.set_counterparty_disclosure_scope_in_txn(txn, contact_ref, &clearance)?;
            let mut receipt = DisclosureConfirmationReceipt {
                decision_id: GateDecisionId::from_bytes([0; 16]),
                act,
                contact_ref: *contact_ref,
                proposal_ref: None,
                ask_ref: None,
                before_digest: contact_clearance_digest(Some(&prior))?,
                after_digest: contact_clearance_digest(Some(&clearance))?,
                once_digest: None,
            };
            receipt.decision_id =
                self.append_contact_clearance_receipt_in_txn(txn, Some(owner), &receipt)?;
            Ok(receipt)
        })
    }

    /// The clearance act's receipt in the existing Gate receipt family: the
    /// row reference joins it to the registry, the after digest is its diff
    /// handle, and the before digest is the revert reference.
    fn append_contact_clearance_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: Option<&AuthenticatedOwner>,
        receipt: &DisclosureConfirmationReceipt,
    ) -> Result<GateDecisionId> {
        let actor = owner
            .map(|owner| owner.revalidate_in_txn(self, &*txn))
            .transpose()?;
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let hex = |digest: &[u8; 32]| crate::entity_id::bytes_to_hex_lower(digest);
        let mut receipt_reasons = vec![
            format!("contact:{}", receipt.contact_ref.to_hex()),
            format!("before:{}", hex(&receipt.before_digest)),
            format!("after:{}", hex(&receipt.after_digest)),
        ];
        receipt_reasons.extend(
            receipt
                .proposal_ref
                .iter()
                .map(|reference| format!("proposal:{reference}")),
        );
        receipt_reasons.extend(receipt.ask_ref.iter().map(|ask| format!("ask:{ask}")));
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: receipt.act.gate_outcome().into(),
            reason_codes: vec![receipt.act.reason_code().into()],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                CONSENT_CONTENT_KIND,
                receipt_reasons,
            ),
            actor_class: if actor.is_some() { "human" } else { "engine" }.into(),
            actor_ref: actor.map(|actor| actor.to_hex()),
            content_kind: CONSENT_CONTENT_KIND.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: Some(contact_clearance_ref(&receipt.contact_ref)),
            diff_handle: receipt.after_digest.to_vec(),
            read_frontier_hash: [0; 32],
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)?;
        Ok(decision_id)
    }
}

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

/// A clearance names a live, active CID-7 contact, read on the acting txn
/// from its claims (OF-272): a dropped contact row changes nothing.
fn require_active_contact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    contact: &EntityId,
) -> Result<()> {
    let record = vault
        .get_counterparty_contact_in_txn(txn, contact)?
        .ok_or(Error::EntityNotFound)?;
    if record.status != CounterpartyContactStatus::Active {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "contact clearance names an inactive contact",
        )));
    }
    Ok(())
}

fn invalid_offer() -> Error {
    Error::Gate(GateError::InvalidConsentBound(
        "contact-disclosure offer failed validation",
    ))
}
