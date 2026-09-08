//! The context-board API: POST /v1/core/context-board hydrates the assembled context — session prefix, optional retrieval with its MEMORIES projection, and the per-session cursor (ARCH-0067 §2).
//!
//! Step two: `EmptyContext`/`memories` when retrieval is skipped: today `memories: None`; the tail always renders MEMORIES once the renderer lands.

mod cursor;
mod memories;
mod prefix;

pub(crate) use cursor::*;
pub(crate) use memories::*;
pub(crate) use prefix::*;
