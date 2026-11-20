//! The language of a 1:1 campaign email's opt-out line (FIX
//! [CAMPAIGN-OPT-OUT-LINE-LOCALE]; ARCH-0059 #opt-out). The line is written
//! in the member's language, chosen from the jurisdiction the dispatch gate
//! reads for the member. Detection decides it once and keeps it on the
//! enrollment event, so every redrive of the event freezes the same envelope
//! bytes, and the intent id that hashes them (FIX 11670) never moves when the
//! member's jurisdiction claim does.

use crate::campaign::claims::PREDICATE_COMM_JURISDICTION;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::dispatch_compliance::observations::{
    rank_jurisdiction_observation, select_jurisdiction,
};
use crate::store::Store;

use super::codec::active_claim_bodies_in_txn;

/// A language the opt-out line is written in: one per jurisdiction of the
/// seeded compliance pack whose language is not English.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OptOutLanguage {
    /// English: the line every campaign email carried before, and the line
    /// for any jurisdiction without its own.
    #[default]
    English,
    /// Japanese, for `JP`.
    Japanese,
    /// German, for `EU/DE`.
    German,
    /// French, for `EU/FR`.
    French,
}

impl OptOutLanguage {
    /// The stored tag: the BCP 47 primary language subtag.
    #[must_use]
    pub(crate) const fn as_tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Japanese => "ja",
            Self::German => "de",
            Self::French => "fr",
        }
    }

    /// The language a stored tag names; `None` for any other tag.
    #[must_use]
    pub(crate) fn parse(tag: &str) -> Option<Self> {
        match tag {
            "en" => Some(Self::English),
            "ja" => Some(Self::Japanese),
            "de" => Some(Self::German),
            "fr" => Some(Self::French),
            _ => None,
        }
    }

    /// The language of a mail to a recipient in `jurisdiction`, a token the
    /// gate normalized.
    fn for_jurisdiction(jurisdiction: &str) -> Self {
        match jurisdiction {
            "JP" => Self::Japanese,
            "EU/DE" => Self::German,
            "EU/FR" => Self::French,
            _ => Self::English,
        }
    }
}

/// The opt-out language for mail to `subject`: the language of the newest
/// ACTIVE `comm.jurisdiction` observation, ties broken as the dispatch gate
/// breaks them; English when the subject has none.
///
/// An observation whose value does not decode is passed over here. The gate
/// refuses every send to that subject on it, so the language it would have
/// chosen never reaches a mail, and a broken claim must not stop a detection
/// pass.
///
/// # Errors
/// Storage errors as they occur.
pub(crate) fn recipient_opt_out_language_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<OptOutLanguage> {
    let bodies = active_claim_bodies_in_txn(store, txn, subject, PREDICATE_COMM_JURISDICTION)?;
    let observations = bodies
        .iter()
        .filter_map(|body| rank_jurisdiction_observation(body).ok())
        .collect();
    let selected = select_jurisdiction(observations);
    Ok(selected.map_or(OptOutLanguage::English, |(token, _)| {
        OptOutLanguage::for_jurisdiction(&token)
    }))
}
