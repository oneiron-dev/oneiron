//! `self.team.submit` (OF-540): what a team's leader submits for the owner's
//! review, and what the host answers. The leader, the review and its binding
//! are the host's; the guest names only the team and the output. An output
//! is a blob version, a code revision, or (FIX 2783) one exact revision of a
//! CLAIM or of a record's common document.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::vault::RevisionRef;

pub(crate) use crate::gate::team_review::TEAM_DELIVERABLE_REVIEW_PREDICATE;

/// An existing blob artifact's exact version, `blob:<artifact hex>:<version>`.
const BLOB_OUTPUT_KIND: &str = "blob";

/// A finalized code revision, `code:<revision hex>`.
const CODE_OUTPUT_KIND: &str = "code";

/// One exact revision of a live CLAIM, `claim:<entity hex>@<revision hex>`.
const CLAIM_OUTPUT_KIND: &str = "claim";

/// One exact version of the common document a live record other than a
/// CLAIM owns, `document:<entity hex>@<revision hex>`.
const DOCUMENT_OUTPUT_KIND: &str = "document";

/// Separates the entity from its exact revision in the claim and document
/// forms.
const REVISION_SEPARATOR: char = '@';

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

/// One pinned output a submit names. Each kind keeps its own spelling, so
/// two kinds never share a canonical string, nor the review derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputRevision {
    /// An existing blob artifact's exact version.
    Blob { artifact: EntityId, version: u64 },
    /// A finalized code revision: a commit or a revert.
    Code { revision: EntityId },
    /// One exact revision of a live type-0 CLAIM.
    Claim {
        entity: EntityId,
        revision: RevisionRef,
    },
    /// One exact version of the common document a live record other than a
    /// CLAIM owns.
    Document {
        entity: EntityId,
        revision: RevisionRef,
    },
}

impl OutputRevision {
    /// Parses `blob:<artifact hex>:<version>`, `code:<revision hex>`,
    /// `claim:<entity hex>@<revision hex>` or
    /// `document:<entity hex>@<revision hex>`. Any other kind, an extra
    /// part, a head or a latest, a short ref, or a malformed id, version or
    /// revision is `None`.
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
            kind @ (CLAIM_OUTPUT_KIND | DOCUMENT_OUTPUT_KIND) => {
                let (entity, revision) = parts.next()?.split_once(REVISION_SEPARATOR)?;
                let entity = EntityId::from_hex(entity).ok()?;
                let revision = RevisionRef::from_hex(revision).ok()?;
                if kind == CLAIM_OUTPUT_KIND {
                    Self::Claim { entity, revision }
                } else {
                    Self::Document { entity, revision }
                }
            }
            _ => return None,
        };
        parts.next().is_none().then_some(output)
    }

    /// The canonical spelling the review and its binding keep, its ids and
    /// revisions in lowercase hex.
    pub(crate) fn canonical(self) -> String {
        match self {
            Self::Blob { artifact, version } => {
                format!("{BLOB_OUTPUT_KIND}:{}:{version}", artifact.to_hex())
            }
            Self::Code { revision } => format!("{CODE_OUTPUT_KIND}:{}", revision.to_hex()),
            Self::Claim { entity, revision } => format!(
                "{CLAIM_OUTPUT_KIND}:{}{REVISION_SEPARATOR}{}",
                entity.to_hex(),
                revision.to_hex()
            ),
            Self::Document { entity, revision } => format!(
                "{DOCUMENT_OUTPUT_KIND}:{}{REVISION_SEPARATOR}{}",
                entity.to_hex(),
                revision.to_hex()
            ),
        }
    }

    /// The entity the review is about: the blob artifact, the code
    /// revision, the CLAIM, or the record that owns the document.
    pub(crate) const fn subject(self) -> EntityId {
        match self {
            Self::Blob { artifact, .. } => artifact,
            Self::Code { revision } => revision,
            Self::Claim { entity, .. } | Self::Document { entity, .. } => entity,
        }
    }
}
