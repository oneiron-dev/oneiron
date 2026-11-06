//! Time bounds used to project a room offer.

/// How long a room-wide card with no fixed deadline stays open after its
/// last engagement: a day (OF-530 ruling A).
pub(crate) const ROOM_OFFER_IDLE_SECS: u64 = 24 * 60 * 60;
