//! The outbound grant owner Setting keys (DESIGN 15-setting-primitive; restriction census C113,
//! owner 16 Nov 00:44: "we apply the optional freedom with good defaults everywhere"): rows the
//! setting catalogue reads from this file.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue};

/// The shipped place hold of a retained channel-identity action: 15 minutes.
pub(crate) const DEFAULT_WINDOW_WAIT_HOLD_SECS: u64 = 15 * 60;

/// The longest hold: a number every SDK carries exactly. The envelope's own window still bounds
/// the hold.
const MAX_WINDOW_WAIT_HOLD_SECS: u64 = (1 << 53) - 1;

/// Seconds a retained action keeps its place once the window its turn falls in opens: at most
/// [`MAX_WINDOW_WAIT_HOLD_SECS`]; zero lets the place lapse as that window opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct WindowWaitHoldSecs(pub(crate) u64);

impl SettingValue for WindowWaitHoldSecs {
    fn check(self) -> Result<Self> {
        if self.0 <= MAX_WINDOW_WAIT_HOLD_SECS {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a retained action keeps its place 0 to {MAX_WINDOW_WAIT_HOLD_SECS} seconds"
            )))
        }
    }
}

fn shipped_hold() -> WindowWaitHoldSecs {
    WindowWaitHoldSecs(DEFAULT_WINDOW_WAIT_HOLD_SECS)
}

crate::setting::setting_keys! {
    /// How long a channel-identity action that met a full envelope window keeps its place in
    /// line, in seconds after the window its turn falls in opens (15 minutes by default); a
    /// shorter window bounds it to the window itself. An action that does not come back by then
    /// loses its place to the actions behind it. The hold changes which waiting action takes a
    /// slot, never how many slots a window has, so the key has no tighter direction: only the
    /// owner sets it, and an agent's change waits on the owner's answer. A row that does not
    /// decode reads as the shipped 15 minutes.
    pub(crate) WINDOW_WAIT_HOLD: WindowWaitHoldSecs = "outbound.grant.window_wait_hold_secs" {
        kind: Kind::new(shipped_hold).strictest(shipped_hold),
    };
}
