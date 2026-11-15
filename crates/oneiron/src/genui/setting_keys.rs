//! The genui module's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::workspace_roster::ROOM_OFFER_IDLE_SECS;

/// How long a voice grant offer may be confirmed after it is minted, in engine seconds: the value
/// of `genui.voice.offer_lifetime_secs`. Above zero: an offer that dies as it is minted is no
/// offer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct VoiceOfferLifetimeSecs(pub(crate) u32);

impl SettingValue for VoiceOfferLifetimeSecs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "genui.voice.offer_lifetime_secs is above zero: an offer that dies as it is \
                 minted is no offer"
                    .into(),
            ));
        }
        Ok(self)
    }
}

/// Ten minutes: the lifetime every voice offer had before the key.
const fn ten_minutes() -> VoiceOfferLifetimeSecs {
    VoiceOfferLifetimeSecs(600)
}

/// One second: the shortest lifetime, which an unreadable row reads as.
const fn one_second() -> VoiceOfferLifetimeSecs {
    VoiceOfferLifetimeSecs(1)
}

/// How long a room-wide offer card with no fixed deadline stays open with no engagement, in
/// engine seconds: the value of `genui.room_offer.idle_secs`. Above zero: a card that ends as it
/// is engaged takes no vote.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct RoomOfferIdleSecs(pub(crate) u64);

impl SettingValue for RoomOfferIdleSecs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "genui.room_offer.idle_secs is above zero: a card that ends as it is engaged \
                 takes no vote"
                    .into(),
            ));
        }
        Ok(self)
    }
}

/// The ruled day (OF-530 = A): how long every room-wide card stayed open with no engagement
/// before the key.
const fn a_day_idle() -> RoomOfferIdleSecs {
    RoomOfferIdleSecs(ROOM_OFFER_IDLE_SECS)
}

/// One second: the shortest wait, which an unreadable row reads as.
const fn a_second_idle() -> RoomOfferIdleSecs {
    RoomOfferIdleSecs(1)
}

crate::setting::setting_keys! {
    /// How long a voice disclosure grant offer may be confirmed after it is minted, in seconds.
    /// Ten minutes by default; past it the offer is pruned and the offer round repeats. The
    /// confirm itself does not change: the owner confirms the exact offered bound from a private,
    /// device-authenticated surface. Longer is the looser value, so only the owner lengthens it;
    /// an agent's change waits on the owner's answer (restriction wave 5, owner 16 Nov 00:44).
    pub(crate) VOICE_OFFER_LIFETIME: VoiceOfferLifetimeSecs = "genui.voice.offer_lifetime_secs" {
        kind: Kind::new(ten_minutes)
            .strictest(one_second)
            .tighter(lower_is_tighter::<VoiceOfferLifetimeSecs>),
    };
    /// How long a room-wide offer card with no fixed deadline stays open with no engagement (a
    /// reply, a vote or a mention), in seconds. A day by default, as the owner ruled (OF-530 =
    /// A); past it the card ages out and only its host's one-click reopening remains. A poster's
    /// fixed deadline still decides over it. The board, the offer listing, the votes, the
    /// answers and the reopening all read this one key. Longer is the looser value, so only the
    /// owner lengthens it; an agent's change waits on the owner's answer (restriction wave 5,
    /// owner 16 Nov 00:44).
    pub(crate) ROOM_OFFER_IDLE: RoomOfferIdleSecs = "genui.room_offer.idle_secs" {
        kind: Kind::new(a_day_idle)
            .strictest(a_second_idle)
            .tighter(lower_is_tighter::<RoomOfferIdleSecs>),
    };
}
