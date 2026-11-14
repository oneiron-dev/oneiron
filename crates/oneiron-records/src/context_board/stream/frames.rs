//! Moved from `crates/oneiron/src/context_board/stream/frames.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::context_board::stream::frames::BoardStreamFrame;
pub use oneiron_verb_wire::context_board::stream::frames::DeltaRow;
pub use oneiron_verb_wire::context_board::stream::frames::FrameKind;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StreamConnectionId(pub String);
