//! Moved from `crates/oneiron/src/failure_ladder/custom_review.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;
use serde::Deserialize;
use serde::Serialize;

pub const VERSION: u8 = 1;

/// Version-one agent observability taxonomy; not the failure ladder's routing class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum FailureSignalClass {
    RefusalOverreach,
    TaskFailure,
    UserFrustration,
    MemoryMiss,
    MemoryIntrusion,
    PersonaBreak,
    LatencyAbandon,
    SilentDegradation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    System,
    Custom,
}

/// Content-free tier-1 projection. The local member refs never cross this door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierOneFailureCount {
    pub taxonomy_version: u8,
    pub agent_kind: AgentKind,
    pub class: FailureSignalClass,
    pub count: u64,
}

impl RawValue for FailureSignalClass {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![VERSION, *self as u8])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [VERSION, 0] => Ok(Self::RefusalOverreach),
            [VERSION, 1] => Ok(Self::TaskFailure),
            [VERSION, 2] => Ok(Self::UserFrustration),
            [VERSION, 3] => Ok(Self::MemoryMiss),
            [VERSION, 4] => Ok(Self::MemoryIntrusion),
            [VERSION, 5] => Ok(Self::PersonaBreak),
            [VERSION, 6] => Ok(Self::LatencyAbandon),
            [VERSION, 7] => Ok(Self::SilentDegradation),
            [VERSION, 8] => Ok(Self::Other),
            _ => Err(Error::CorruptedIndex("custom-agent failure").into()),
        }
    }
}
