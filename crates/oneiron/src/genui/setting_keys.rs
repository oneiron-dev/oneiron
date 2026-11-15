//! The genui module's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

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
}
