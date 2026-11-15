//! The feeds owner Setting keys: rows the setting catalogue reads from this file.
//!
//! Each key ships a good default plus an owner opt-out. The default is exactly today's constant,
//! so nothing changes until the owner moves it. A raise is the loosening. Only the owner sets
//! these keys.

use serde::{Deserialize, Serialize};

use super::FEED_RETENTION_SECS;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// How long a cursor in a pruned source stays held without an acknowledgement, in seconds: one
/// hour to ten years.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct FeedRetentionSecs(pub(crate) u64);

impl SettingValue for FeedRetentionSecs {
    fn check(self) -> Result<Self> {
        if !(3_600..=315_360_000).contains(&self.0) {
            return Err(Error::InvalidConfig(
                "a feed retention is one hour to ten years".into(),
            ));
        }
        Ok(self)
    }
}

/// Seven days: the retention before the owner moves it, and what an unreadable row reads as.
fn feed_retention_default() -> FeedRetentionSecs {
    FeedRetentionSecs(FEED_RETENTION_SECS)
}

crate::setting::setting_keys! {
    /// How long a cursor in a pruned source stays held without an acknowledgement, in seconds;
    /// 604,800 (seven days) by default. A raise holds idle cursors longer, and is the looser
    /// value. Only the owner sets it.
    pub(crate) FEED_RETENTION_IDLE_SECS: FeedRetentionSecs = "feeds.retention.idle_secs" {
        kind: Kind::new(feed_retention_default)
            .strictest(feed_retention_default)
            .tighter(lower_is_tighter::<FeedRetentionSecs>),
    };
}
