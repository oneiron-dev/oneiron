//! Moved from `crates/oneiron/src/context_board/tasks/projection.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::failure_ladder::task_terminal::TaskTerminalDisposition;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// A consult TASK that is a child run's comm widen ask (FIX 3901): the run
/// that asks, the reach it holds and the reach it asks for. Its answer goes
/// through the consult's own answer door, as any consult's does.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsultWidening {
    /// The asking child run's attempt, as 32 hex.
    pub child: String,
    /// The reach the child addressed with when it asked: its spawn dial or
    /// an earlier approval (FIX 10413). `None` only on an ask reserved before
    /// that reach was kept, with no earlier approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<oneiron_authority::authority::CommReach>,
    /// The reach it asks to widen to.
    pub to: oneiron_authority::authority::CommReach,
}

impl ConsultWidening {
    /// The board token: `widening=<from>-><to>`, or `widening=<to>` when the
    /// reach it asked from is not known.
    #[must_use]
    pub fn token(&self) -> String {
        match self.from {
            Some(from) => format!("widening={}->{}", from.as_str(), self.to.as_str()),
            None => format!("widening={}", self.to.as_str()),
        }
    }
}
