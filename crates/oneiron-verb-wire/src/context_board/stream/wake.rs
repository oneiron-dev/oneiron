//! Moved from `crates/oneiron/src/context_board/stream/wake.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One pending wake, minted from a committed TASK, from a pending
/// diary-read review (FIX 2879), or from a staged room wake (FIX 15647).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct WakeEnvelope {
    /// The envelope id, `<task id>:<arrived|failed>:<revision>` (ARCH-0067
    /// `#wake-envelope-id`). The revision names the committed TASK state the
    /// event was minted from, so a task that fails, reopens and fails again
    /// queues two envelopes with two ids, and an acknowledgement names one
    /// occurrence. A review wake's id is its review's INBOX handle,
    /// `diary-read:<agent>:<request>`; a room wake's is
    /// `room-wake:<turn>:<agent>`.
    pub event_ref: String,
    /// The TASK a TASK wake names; empty on a review wake, which names its
    /// review in `review_ref` instead, and on a room wake, which names its
    /// room and turn.
    pub task_ref: String,
    pub actor_ref: String,
    pub line: String,
    /// The diary-read request a review wake names, waiting on `actor_ref`'s
    /// answer through `self.memory.diary.review`. Absent on every TASK wake.
    /// The wake carries no reader, reason or diary content and grants no read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_ref: Option<String>,
    /// The room a room wake names (FIX 15647), where `turn_ref` addresses
    /// `actor_ref` or holds its thread's open TASK for it. Absent on every
    /// other wake. The wake carries no speaker and none of the turn, and
    /// grants no read: the agent reads the room through its own reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_ref: Option<String>,
    /// The turn a room wake names, in `room_ref`. Absent on every other wake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_ref: Option<String>,
}
