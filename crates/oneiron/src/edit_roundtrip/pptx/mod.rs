//! Narrow, byte-preserving modern PowerPoint comment edits.
//!
//! This module does not render slides or claim Office application validation.
//! Callers retain the returned proposal and use the existing artifact settlement door.

mod archive;
mod comments;
mod identities;
mod links;
mod package;
mod proposal;
mod xml;

pub use comments::comment_patch;
pub(crate) use comments::unknown_anchor_threads;
pub use identities::{inspect_pptx, rebind_locator};
pub use package::*;
pub use proposal::{run_comment_roundtrip, verify_comment_proposal};

#[cfg(test)]
pub(crate) mod tests;
