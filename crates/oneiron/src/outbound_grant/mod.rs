//! Standing outbound grants for OF-367 RS6.2/RS6.5.
//!
//! A standing outbound grant is a standing consent Grant row (DEC-0006): the
//! owner mints it, its scope dial is its bound's one spelling, and it lives
//! until revoked, which fails it closed at once. Coverage of an effect is
//! the bound's containment of that effect. A channel identity's envelope
//! grant is its autonomy row's own Grant; only the atomic envelope door
//! here admits against it.

mod bound;
mod consume;
mod doors;
mod spelling;
mod verb_class;

pub use self::bound::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
};
pub use self::consume::{
    CHANNEL_IDENTITY_GRANT_USAGE_PREFIX, CHANNEL_IDENTITY_WINDOW_WAIT_REASON,
    ChannelIdentityGrantOutcome, ChannelIdentityWindowWait,
};
pub(crate) use self::consume::{
    ChannelIdentityGrantAdmission, ChannelIdentityGrantReservation, ChannelIdentityGrantRetention,
    admit_channel_identity_grant_in_txn,
};
pub(crate) use self::doors::{
    standing_outbound_grant_in_txn, standing_outbound_grants_for_principal_in_txn,
    standing_outbound_grants_in_txn,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::genui::GrantMintIntent;
#[cfg(test)]
use crate::outbound_consent::{DataClass, ScopedMcpGrantRef};
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::io::Cursor;
