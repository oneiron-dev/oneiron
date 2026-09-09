//! Authenticated ChannelIdentity autonomy, immutable bounds, and offer-only graduation.
//!
//! Authority lives in unified consent grants. These versioned vault-meta law rows
//! cannot be forged through generic claim writes. Envelope handles are content
//! addressed and immutable; posture is a pointer, never permission by itself.

mod autonomy;
mod codec;
mod envelopes;
mod graduation;
mod types;

pub use self::types::{
    CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION, ChannelIdentityActionEnvelope,
    ChannelIdentityAutonomyMode, ChannelIdentityAutonomyRequest, ChannelIdentityAutonomyRung,
    ChannelIdentityAutonomyState, ChannelIdentityEffectCandidate, ChannelIdentityGrantWindowUsage,
    DEFAULT_GRADUATION_UNCHANGED_STREAK, DraftReviewOutcome, GraduationEvidence, GraduationOffer,
    GraduationScopeKey, MailboxReadCandidate, MailboxReadEnvelope, PREDICATE_ACTION_ENVELOPE,
    PREDICATE_AUTONOMY_MODE, PREDICATE_GRADUATION_EVIDENCE, PREDICATE_MAILBOX_READ_ENVELOPE,
};

use self::codec::invalid_autonomy;

#[cfg(test)]
mod tests;

// The flat channel_identity_autonomy.rs module used to provide these names to
// the sibling test module through `use super::*`: its own private crate/std
// import header, and the private codec helpers the tests name bare. After the
// directory split the seam re-imports both so `tests.rs` resolves exactly as
// it did before.
#[cfg(test)]
use self::codec::{
    address, context, decode, encode, mode_from, mode_value, read_bound, read_value,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::access_grant::{AccessGrant, AccessGrantCapability};
#[cfg(test)]
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
#[cfg(test)]
use crate::channel_identity_selection::RelationshipContext;
#[cfg(test)]
use crate::consent::AuthenticatedOwner;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::outbound_grant::StandingOutboundGrantScope;
#[cfg(test)]
use crate::receipt::{ReceiptKind, ReceiptQuery};
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;
