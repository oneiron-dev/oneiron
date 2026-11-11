//! One pinned output a submit names.

use crate::entity_id::EntityId;
use crate::vault::RevisionRef;

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
    pub(super) const fn subject(self) -> EntityId {
        match self {
            Self::Blob { artifact, .. } => artifact,
            Self::Code { revision } => revision,
            Self::Claim { entity, .. } | Self::Document { entity, .. } => entity,
        }
    }
}
