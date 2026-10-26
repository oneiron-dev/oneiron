//! Executable lawful-basis requirements: a consent-class row's alternatives as data.
//!
//! A row's [`ConsentRequirement`] is the machine form of its `requirement`
//! sentence (FIX 9657). It holds when any one branch holds, and a branch holds
//! when every fact in it holds. The facts are generic mechanical primitives —
//! an explicit opt-in, a legal form in a row-supplied token set, the parts of a
//! soft opt-in — never a country: which jurisdiction needs which conjunction is
//! the row's data, so a counsel-reviewed change is a pack revision.

use serde::{Deserialize, Serialize};

use super::evaluate::{DispatchComplianceFacts, normalize_token};
use crate::entity_id::EntityId;

/// A consent-class row's lawful basis: the send has one when ANY branch holds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequirement {
    /// The alternative lawful bases. Never empty.
    pub any_of: Vec<ConsentBranch>,
}

/// One lawful basis: it holds when EVERY fact in it holds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentBranch {
    /// The facts this basis needs together. Never empty.
    pub all_of: Vec<ConsentFact>,
}

/// One mechanical fact a lawful basis can need.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "fact", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsentFact {
    /// The recipient's resolved consent record gives explicit, current consent
    /// that covers this channel and this sender.
    ExplicitOptIn,
    /// The recipient's recorded legal form is one of `tokens`, compared as
    /// normalized tokens. An unknown legal form is in no set.
    LegalFormIn {
        /// The legal forms this basis admits. Never empty.
        tokens: Vec<String>,
    },
    /// The recipient's legal form is recorded at all; which treatment it gets
    /// is another row's to say.
    LegalFormRecorded,
    /// The sender obtained the contact details from the recipient in
    /// connection with a completed sale to them.
    ObtainedInSale,
    /// The sender obtained the contact details in the course of a sale, or of
    /// negotiations for a sale, to the recipient.
    ObtainedInSaleOrNegotiation,
    /// The message markets only the sender's own similar products or services.
    SimilarOffering,
    /// The recipient has not refused or objected to this use of the details.
    NoObjection,
    /// A simple, free means of refusing was offered when the details were
    /// collected.
    OptOutOfferedAtCollection,
    /// This message carries a working means of refusing: the sending identity's
    /// message-element fact.
    OptOutInMessage,
    /// The sender is a charity and the message's sole purpose is furthering its
    /// charitable purposes.
    CharitablePurpose,
    /// The details were obtained while the recipient expressed interest in, or
    /// offered or gave support to, those purposes.
    ExpressedSupport,
    /// A resolved publication-context record proves all three of its facts.
    PublicationContext,
}

/// The recipient's resolved consent record, as the evaluator may see it.
///
/// Built only by hydration from an ACTIVE `crm.compliance.consent` claim on
/// this recipient that the dispatch evidence cites; with no such record every
/// field is `false` and only the facts outside a record can hold.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HydratedConsentFacts {
    /// The consent record that resolved.
    pub record_ref: Option<EntityId>,
    /// Explicit consent covering this dispatch's channel and sender.
    pub explicit_opt_in: bool,
    /// Details obtained in connection with a completed sale.
    pub obtained_in_sale: bool,
    /// Details obtained during negotiations for a sale.
    pub obtained_in_sale_negotiation: bool,
    /// The marketing is for the sender's own similar offerings.
    pub similar_offering: bool,
    /// The recipient has not refused or objected.
    pub no_objection: bool,
    /// A means of refusing was offered at collection.
    pub optout_offered_at_collection: bool,
    /// The sender is a charity furthering its charitable purposes.
    pub charitable_purpose: bool,
    /// The details came while the recipient expressed interest or support.
    pub expressed_support: bool,
}

impl ConsentRequirement {
    /// Whether `facts` satisfy any branch.
    pub(super) fn holds(&self, facts: &DispatchComplianceFacts) -> bool {
        self.any_of
            .iter()
            .any(|branch| branch.all_of.iter().all(|fact| fact.holds(facts)))
    }

    /// Whether this requirement admits only sends `weaker` also admits: each
    /// of its branches needs at least what some branch of `weaker` needs. A
    /// proof, never a guess; `false` means not proven.
    pub(super) fn implies(&self, weaker: &Self) -> bool {
        self.any_of.iter().all(|branch| {
            weaker
                .any_of
                .iter()
                .any(|held| held.all_of.iter().all(|need| branch.proves(need)))
        })
    }

    /// The structural defect that keeps this requirement from evaluating
    /// deterministically, if any: an empty alternative list never holds, an
    /// empty branch always does, and an empty token set admits nothing.
    pub(super) fn shape_defect(&self) -> Option<&'static str> {
        if self.any_of.is_empty() {
            return Some("consent requirement names no branch");
        }
        for branch in &self.any_of {
            if branch.all_of.is_empty() {
                return Some("consent branch names no fact");
            }
            for fact in &branch.all_of {
                if let ConsentFact::LegalFormIn { tokens } = fact
                    && (tokens.is_empty() || tokens.iter().any(|token| token.trim().is_empty()))
                {
                    return Some("legal-form fact needs non-blank tokens");
                }
            }
        }
        None
    }
}

impl ConsentBranch {
    /// Whether this branch's facts together prove `need`.
    fn proves(&self, need: &ConsentFact) -> bool {
        self.all_of.iter().any(|fact| fact.proves(need))
    }
}

impl ConsentFact {
    fn holds(&self, facts: &DispatchComplianceFacts) -> bool {
        let consent = &facts.consent;
        match self {
            Self::ExplicitOptIn => consent.explicit_opt_in,
            Self::LegalFormIn { tokens } => facts.legal_form.as_deref().is_some_and(|form| {
                let form = normalize_token(form);
                tokens.iter().any(|token| normalize_token(token) == form)
            }),
            Self::LegalFormRecorded => facts.legal_form.is_some(),
            Self::ObtainedInSale => consent.obtained_in_sale,
            Self::ObtainedInSaleOrNegotiation => {
                consent.obtained_in_sale || consent.obtained_in_sale_negotiation
            }
            Self::SimilarOffering => consent.similar_offering,
            Self::NoObjection => consent.no_objection,
            Self::OptOutOfferedAtCollection => consent.optout_offered_at_collection,
            Self::OptOutInMessage => facts.optout_mechanism_present,
            Self::CharitablePurpose => consent.charitable_purpose,
            Self::ExpressedSupport => consent.expressed_support,
            Self::PublicationContext => facts
                .jp_publication
                .is_some_and(|publication| publication.exemption_holds()),
        }
    }

    /// Whether this fact holding proves `need` holds.
    fn proves(&self, need: &Self) -> bool {
        match (self, need) {
            (Self::LegalFormIn { tokens }, Self::LegalFormIn { tokens: admitted }) => {
                tokens.iter().all(|token| {
                    let token = normalize_token(token);
                    admitted
                        .iter()
                        .any(|candidate| normalize_token(candidate) == token)
                })
            }
            (Self::LegalFormIn { .. }, Self::LegalFormRecorded)
            | (Self::ObtainedInSale, Self::ObtainedInSaleOrNegotiation) => true,
            _ => self == need,
        }
    }
}
