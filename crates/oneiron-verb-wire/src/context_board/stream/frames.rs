//! Moved from `crates/oneiron/src/context_board/stream/frames.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BoardStreamFrame {
    pub epoch: u64,
    pub kind: FrameKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum FrameKind {
    Keyframe(String),
    Delta(Vec<DeltaRow>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeltaRow {
    pub key: String,
    pub line: String,
}
