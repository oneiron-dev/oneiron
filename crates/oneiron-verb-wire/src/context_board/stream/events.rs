//! Moved from `crates/oneiron/src/context_board/stream/events.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionScope {
    MyTasks,
    MyChildren,
    ConsultsToMe,
    Memories,
    Worlds,
    Presence,
    Counts,
    /// A read of my diary waits on my review (FIX 2879).
    DiaryReviews,
    /// A room turn addresses me, or its thread's open TASK is mine (FIX
    /// 15647).
    RoomTurns,
}

impl SubscriptionScope {
    pub const ALL: [Self; 9] = [
        Self::MyTasks,
        Self::MyChildren,
        Self::ConsultsToMe,
        Self::Memories,
        Self::Worlds,
        Self::Presence,
        Self::Counts,
        Self::DiaryReviews,
        Self::RoomTurns,
    ];
}
