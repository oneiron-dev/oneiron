//! Narrow, byte-preserving modern PowerPoint comment edits and the slide and
//! shape identities they anchor to.
//!
//! Pure bytes in, bytes out: no clock, no entropy of its own, no store. The
//! caller supplies every ceiling and the entropy a fresh slide creation ID is
//! drawn from, and owns annotation storage, review and settlement. This
//! module does not render slides or claim Office application validation.

mod archive;
mod comments;
mod identities;
mod links;
mod model;
mod xml;

pub use comments::{comment_patch, unknown_anchor_threads};
pub use identities::{inspect_pptx, rebind_shape};
pub use model::*;
