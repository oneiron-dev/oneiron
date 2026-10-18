//! Narrow, byte-preserving modern PowerPoint comment edits.
//!
//! The writer and inspector are the docedit organ's
//! (`oneiron_docedit::pptx_comments`, served on its contract as
//! `pptx.comments`); this module is the engine's door onto them: engine
//! identities, policy budgets, proposals and their replay.
//! This module does not render slides or claim Office application validation.
//! Callers retain the returned proposal and use the existing artifact settlement door.

mod comments;
mod identities;
mod limits;
mod package;
mod proposal;

pub use comments::comment_patch;
#[cfg(test)]
pub(crate) use comments::unknown_anchor_threads;
pub(crate) use comments::unknown_anchor_threads_with_limits;
pub(crate) use identities::inspect_pptx_with_limits;
pub use identities::{inspect_pptx, rebind_locator};
pub use limits::PptxOperationalLimits;
pub use package::*;
pub(crate) use proposal::verify_comment_proposal_with_limits;
pub use proposal::{run_comment_roundtrip, verify_comment_proposal};

#[cfg(test)]
pub(crate) mod tests;
