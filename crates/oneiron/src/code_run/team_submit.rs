//! `self.team.submit` (OF-540): what a team's leader submits for the owner's
//! review, and what the host answers. The leader, the review and its binding
//! are the host's; the guest names only the team and the output. An output
//! is a blob version, a code revision, or (FIX 2783) one exact revision of a
//! CLAIM or of a record's common document.

use serde::{Deserialize, Serialize};

pub(crate) use crate::gate::team_review::TEAM_DELIVERABLE_REVIEW_PREDICATE;

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

/// What `self.team.submit` answered: the review the owner answers. Submitted
/// is not accepted; the owner's answer settles the team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamSubmitAnswer {
    pub team: String,
    /// The output under review, as the host pinned it.
    pub output_revision: String,
    /// The review claim the owner answers, hex.
    pub review_claim: String,
    /// The leader had already submitted this output: the review stands as
    /// it was first written, unchanged.
    pub already_submitted: bool,
}
