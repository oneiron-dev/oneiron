//! Moved from `crates/oneiron/src/code_run/team_submit.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `self.team.submit`: the leader submits one pinned output of a team it
/// started for the owner's acceptance review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamSubmitInput {
    /// The team, as `self.team.start` answered its `teamRef`.
    pub team: String,
    /// The output under review, one of: an existing blob artifact version,
    /// `blob:<artifact hex>:<version>`; a finalized code revision,
    /// `code:<revision hex>`; one exact revision of a live CLAIM,
    /// `claim:<entity hex>@<revision hex>`; or one exact version of the
    /// common document a live record other than a CLAIM owns (a NOTE, a
    /// MESSAGE, a SUMMARY), `document:<entity hex>@<revision hex>`. Ids are
    /// full 32-hex ids; a revision is the 32-hex revision a pinned read
    /// names. Never a head, a latest or a short ref.
    pub output_revision: String,
}
