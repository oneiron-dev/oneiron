//! One-time tagging arming on an already-open vault (ARCH-0036 live setup).
//!
//! A vault opened with no `[oneironer]` section has
//! [`crate::VaultConfig::tagging`] `None`: witnesses commit no markers and
//! [`crate::tagging::TaggingReconciler::new`] refuses it. First-run setup
//! attaches the tagger after open, so it arms the open vault here instead of
//! reopening it. Arming is one-time: a second call with any config leaves
//! the first arming in force and reports it did nothing.

use crate::Vault;
use crate::config::tagging::TaggingMarkerConfig;
use crate::error::Result;

impl Vault {
    /// Arms the tagging marker with `marker` when neither the open config
    /// nor an earlier call armed one. Returns whether this call armed it.
    /// A refused marker arms nothing, and the earlier arming stays.
    pub fn arm_tagging_once(&self, marker: TaggingMarkerConfig) -> Result<bool> {
        marker.validate()?;
        if self.config.tagging.is_some() {
            return Ok(false);
        }
        Ok(self.tagging_arm.set(marker).is_ok())
    }

    /// The marker witnesses commit under: the late arming, else the open
    /// config's. `None` commits no marker.
    pub(crate) fn tagging_marker_config(&self) -> Option<TaggingMarkerConfig> {
        self.tagging_arm
            .get()
            .cloned()
            .or_else(|| self.config.tagging.clone())
    }
}
