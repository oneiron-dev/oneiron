//! `self.team.submit` (OF-540): what a team's leader submits for the owner's
//! review, and what the host answers. The leader, the review and its binding
//! are the host's; the guest names only the team and the output.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// The predicate of the review a submit writes: whether the team's output,
/// as pinned, is accepted. The Gate's default manifest declares it critical,
/// so the review waits for the owner.
pub(crate) const TEAM_DELIVERABLE_REVIEW_PREDICATE: &str = "team.deliverable.acceptance";

/// An existing blob artifact's exact version, `blob:<artifact hex>:<version>`.
const BLOB_OUTPUT_KIND: &str = "blob";

/// A finalized code revision, `code:<revision hex>`.
const CODE_OUTPUT_KIND: &str = "code";

/// `self.team.submit`: the leader submits one pinned output of a team it
/// started for the owner's acceptance review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamSubmitInput {
    /// The team, as `self.team.start` answered its `teamRef`.
    pub team: String,
    /// The output under review: one existing blob artifact version,
    /// `blob:<artifact hex>:<version>`, or one finalized code revision,
    /// `code:<revision hex>`. Never a head or a latest.
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

/// One pinned output a submit names. Each kind keeps its own spelling, so
/// two kinds never share a canonical string, nor the review derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputRevision {
    /// An existing blob artifact's exact version.
    Blob { artifact: EntityId, version: u64 },
    /// A finalized code revision: a commit or a revert.
    Code { revision: EntityId },
}

impl OutputRevision {
    /// Parses `blob:<artifact hex>:<version>` or `code:<revision hex>`.
    /// Any other kind, an extra part, a head or a latest, or a malformed id
    /// or version is `None`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let output = match parts.next()? {
            BLOB_OUTPUT_KIND => {
                let (artifact, version) = (parts.next()?, parts.next()?);
                if !version.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                Self::Blob {
                    artifact: EntityId::from_hex(artifact).ok()?,
                    version: version.parse().ok()?,
                }
            }
            CODE_OUTPUT_KIND => Self::Code {
                revision: EntityId::from_hex(parts.next()?).ok()?,
            },
            _ => return None,
        };
        parts.next().is_none().then_some(output)
    }

    /// The canonical spelling the review and its binding keep, its ids in
    /// lowercase hex.
    pub(crate) fn canonical(self) -> String {
        match self {
            Self::Blob { artifact, version } => {
                format!("{BLOB_OUTPUT_KIND}:{}:{version}", artifact.to_hex())
            }
            Self::Code { revision } => format!("{CODE_OUTPUT_KIND}:{}", revision.to_hex()),
        }
    }

    /// The entity the output is: the blob artifact, or the code revision.
    pub(crate) const fn subject(self) -> EntityId {
        match self {
            Self::Blob { artifact, .. } => artifact,
            Self::Code { revision } => revision,
        }
    }
}
