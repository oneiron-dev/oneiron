//! The voice cascade's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use serde::{Deserialize, Serialize};

use super::{VOICE_IDENTITY_ASK_SECONDS, VOICE_ROOM_CANDIDATES_MAX};
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// How long a room speaker's "who is this?" ask stays open, in engine seconds: the value of
/// `voice.session.identity_ask_secs`. Above zero: an ask closed as it is raised is no ask.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct IdentityAskSecs(pub(crate) u32);

impl SettingValue for IdentityAskSecs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "voice.session.identity_ask_secs is above zero: an ask closed as it is raised is \
                 no ask"
                    .into(),
            ));
        }
        Ok(self)
    }
}

/// A day: how long every identity ask stayed open before the key.
const fn one_day() -> IdentityAskSecs {
    IdentityAskSecs(VOICE_IDENTITY_ASK_SECONDS)
}

/// One second: the shortest ask, which an unreadable row reads as.
const fn one_second() -> IdentityAskSecs {
    IdentityAskSecs(1)
}

/// The 32 contacts every identity ask offered at most before the key.
const fn thirty_two() -> u32 {
    VOICE_ROOM_CANDIDATES_MAX
}

/// No contact: the fewest, which an unreadable row reads as.
const fn none_offered() -> u32 {
    0
}

crate::setting::setting_keys! {
    /// How long the "who is this?" ask for a speaker a room's voice session could not place
    /// stays open, in seconds. A day by default; an ask nobody answers in time closes and the
    /// speaker stays unplaced. Longer is the looser value, so only the owner lengthens it; an
    /// agent's change waits on the owner's answer (restriction wave 5, owner 16 Nov 00:44).
    pub(crate) IDENTITY_ASK_SECS: IdentityAskSecs = "voice.session.identity_ask_secs" {
        kind: Kind::new(one_day)
            .strictest(one_second)
            .tighter(lower_is_tighter::<IdentityAskSecs>),
    };
    /// How many of the room's contacts, in the host's order, that ask offers to tap-pick. 32 by
    /// default; a room with more contacts offers only the first ones. More is the looser value,
    /// so only the owner raises it; an agent's change waits on the owner's answer (restriction
    /// wave 5, owner 16 Nov 00:44).
    pub(crate) ROOM_CANDIDATES_MAX: u32 = "voice.session.room_candidates_max" {
        kind: Kind::new(thirty_two)
            .strictest(none_offered)
            .tighter(lower_is_tighter::<u32>),
    };
}
