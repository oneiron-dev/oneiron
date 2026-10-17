//! `self.team.submit` (OF-540): what a team's leader submits for the owner's
//! review, and what the host answers. The leader, the review and its binding
//! are the host's; the guest names only the team and the output.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// The predicate of the review a submit writes: whether the team's output,
/// as pinned, is accepted. The Gate's default manifest declares it critical,
/// so the review waits for the owner.
pub(crate) const TEAM_DELIVERABLE_REVIEW_PREDICATE: &str = "team.deliverable.acceptance";

/// The one output kind a submit pins: an existing blob artifact's exact
/// version, `blob:<artifact hex>:<version>`.
const BLOB_OUTPUT_KIND: &str = "blob";

/// `self.team.submit`: the leader submits one pinned output of a team it
/// started for the owner's acceptance review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamSubmitInput {
    /// The team, as `self.team.start` answered its `teamRef`.
    pub team: String,
    /// The output under review: one existing blob artifact version,
    /// `blob:<artifact hex>:<version>`. Never a head or a latest.
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

/// One pinned blob artifact version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlobOutputRevision {
    pub(crate) artifact: EntityId,
    pub(crate) version: u64,
}

impl BlobOutputRevision {
    /// Parses `blob:<artifact hex>:<version>`. Any other kind, a head, or a
    /// malformed id or version is `None`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let (Some(kind), Some(artifact), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        if kind != BLOB_OUTPUT_KIND || !version.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            artifact: EntityId::from_hex(artifact).ok()?,
            version: version.parse().ok()?,
        })
    }

    /// The canonical spelling the review and its binding keep.
    pub(crate) fn canonical(self) -> String {
        format!(
            "{BLOB_OUTPUT_KIND}:{}:{}",
            self.artifact.to_hex(),
            self.version
        )
    }
}
