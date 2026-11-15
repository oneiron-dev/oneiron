//! Rung 2 gets its FROM (ARCH-0062:145-147, ARCH-0063:48; INBOX-RESIDUE
//! PR-3b-1).
//!
//! When no slot fits, the page's own agent continues the conversation over
//! email. That email's FROM is the identity the vault's selection law picks
//! for scheduling among the agent's email identities: by default the agent's
//! own named work address (`builtin.scheduling_logistics`). The law never
//! falls through to another face, so a page whose agent holds no live
//! identity of that face does not offer rung 2 at all. It answers with the
//! owner's no-fit line and its slot links, and never asks for an email it
//! cannot use (RUNG2-NO-SENDER = A).
//!
//! The face of each identity is the host's ([`ChannelIdentityFaceClassifier`]),
//! as at every other selection: a face is a role, and no stored fact states
//! it.

use crate::channel_identity::{
    ChannelIdentityFaceClassifier, channel_identity_selection_candidates_in_txn,
};
use crate::channel_identity_selection::{
    ChannelIdentityFace, ChannelIdentitySelectionError, ChannelIdentitySelectionQuery,
    RelationshipContext, channel_identity_selection_rules_in_txn,
    resolve_channel_identity_selection,
};
use crate::{EntityId, Error, Result, Vault};

use super::publication::load_public_booking_page_in_txn;

/// The channel a rung-2 continuation is sent on.
pub const BOOKING_RUNG2_CHANNEL: &str = "email";

/// Every rung-2 send ref starts with this prefix.
pub const BOOKING_RUNG2_SEND_REF_PREFIX: &str = "booking-rung2:";

/// Why a page offers no rung 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung2Unavailable {
    /// The page has no live, published publication.
    PageNotLive,
    /// The publication serves no constraint front.
    NoConstraintFront,
    /// The front names no agent ([`super::agent_front::ConstraintFrontConfig::agent_ref`]).
    NoPageAgent,
    /// The page's agent holds no live email identity of the face the
    /// selection law names for scheduling: by default, no live named work
    /// address.
    NoNamedAddress,
}

/// Who sends a page's rung-2 email: the page's agent, wearing the identity
/// the selection law picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rung2Sender {
    pub page_ref: EntityId,
    pub agent_ref: EntityId,
    pub identity_ref: EntityId,
    pub facet_ref: Option<EntityId>,
    pub face: ChannelIdentityFace,
}

/// Whether a page offers rung 2 now, and from whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung2Offer {
    Offered(Rung2Sender),
    NotOffered(Rung2Unavailable),
}

/// The one ref of a session's rung-2 first send: its intent ref and its
/// idempotency key, so a retried press sends once.
#[must_use]
pub fn rung2_send_ref(page_ref: &EntityId, session_ref: &str) -> String {
    format!(
        "{BOOKING_RUNG2_SEND_REF_PREFIX}{}:{session_ref}",
        page_ref.to_hex()
    )
}

impl Vault {
    /// Whether `page_ref` offers rung 2 at `now`, and its FROM, read on one
    /// snapshot: the live publication's front names the page's agent, and the
    /// selection law picks, among that agent's email identities as
    /// `classify_face` classifies them, the scheduling face's active
    /// identity. A refusal of the law for want of a live identity of that
    /// face is [`Rung2Offer::NotOffered`], never another face.
    ///
    /// # Errors
    ///
    /// Storage errors, a stored publication that does not decode, and a
    /// stored selection rule set the law refuses.
    pub fn booking_rung2_offer(
        &self,
        page_ref: EntityId,
        now: u64,
        classify_face: &mut ChannelIdentityFaceClassifier<'_>,
    ) -> Result<Rung2Offer> {
        let txn = self.store.env.read_txn()?;
        let Some(publication) = load_public_booking_page_in_txn(self, &txn, page_ref, now)? else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::PageNotLive));
        };
        let Some(front) = publication.constraint_front else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoConstraintFront));
        };
        let Some(agent_ref) = front.agent_ref else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoPageAgent));
        };
        let candidates = channel_identity_selection_candidates_in_txn(
            &self.store,
            &txn,
            BOOKING_RUNG2_CHANNEL,
            &agent_ref,
            classify_face,
        )?;
        let decision =
            channel_identity_selection_rules_in_txn(&self.store, &txn).and_then(|rules| {
                resolve_channel_identity_selection(
                    &rules,
                    ChannelIdentitySelectionQuery {
                        relationship: RelationshipContext::SchedulingLogistics,
                        applicable_scopes: &[],
                        candidates: &candidates,
                        thread_pin: None,
                    },
                )
            });
        match decision {
            Ok(decision) => Ok(Rung2Offer::Offered(Rung2Sender {
                page_ref,
                agent_ref,
                identity_ref: decision.identity_ref,
                facet_ref: decision.facet_ref,
                face: decision.face,
            })),
            Err(
                ChannelIdentitySelectionError::NoCandidateForFace
                | ChannelIdentitySelectionError::NoRuleForRelationship
                | ChannelIdentitySelectionError::PinnedCandidateMissing
                | ChannelIdentitySelectionError::PinnedCandidateInactive
                | ChannelIdentitySelectionError::PinnedCandidateFaceMismatch,
            ) => Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoNamedAddress)),
            Err(ChannelIdentitySelectionError::Storage(error)) => Err(error),
            Err(error) => Err(Error::InvalidConfig(error.to_string())),
        }
    }
}
