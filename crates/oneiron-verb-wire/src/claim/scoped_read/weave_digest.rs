//! Moved from `crates/oneiron/src/claim/scoped_read/weave_digest.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestFeedback;
pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestSettingAnswer;
pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestSettingChange;
pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestSettingChangeStatus;
pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestSettingUndo;
pub use crate::claim::scoped_read::weave_digest::settings::WeaveDigestSettings;
use serde::Deserialize;
use serde::Serialize;

pub const SCHEDULE_PREFIX: &[u8] = b"weave:schedule:v1:";

/// The producer of a weave digest's inbox NOTIFICATION; `source.result` is
/// the digest's period, its `scheduled_for` second.
pub const WEAVE_DIGEST_NOTIFICATION_PRODUCER: &str = "weave.digest";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveDigestCadence {
    Daily,
    Weekly,
}

impl WeaveDigestCadence {
    fn seconds(self) -> u64 {
        match self {
            Self::Daily => 86_400,
            Self::Weekly => 604_800,
        }
    }
}

/// Why the timer left a schedule row: until when, and the refusal that held
/// it. An owner's due notice holds its row with no refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveScheduleHold {
    pub until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub because: Option<String>,
}
pub mod settings;
