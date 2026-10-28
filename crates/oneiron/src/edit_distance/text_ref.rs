//! ED-00 text by reference (FIX 7818): a finalized proposal keeps refs into
//! its retained document, and every endpoint or change text is read back
//! through it, never from a stored copy.
//!
//! The document is the proposal's own Loro document with its whole op log,
//! retained beside the record under the artifact's key. Reads go through
//! [`EntityDoc::from_snapshot`] and [`EntityDoc::text_at`], the entity
//! document plane's retained-history reads. A version the document no longer
//! holds reads as [`TextRead::Unavailable`]: never a guessed or stale string,
//! and never an error that fails the listing around it.

use heed::RoTxn;

use super::{FinalizedProposalText, LoroOpRef, OpSpan, PROPOSAL_ARTIFACT, ProposalArtifactRef};
use crate::Vault;
use crate::entity_doc::EntityDoc;
use crate::error::{Error, Result};

/// One stored proposal artifact: the ref-only record, and the retained
/// document its refs resolve in.
#[derive(Debug, Clone)]
pub(crate) struct StoredProposal {
    pub(crate) record: FinalizedProposalText,
    /// The proposal document as a Loro snapshot with its whole op log;
    /// `None` when the side-row wall withheld it at finalize.
    pub(crate) document: Option<Vec<u8>>,
}

/// Why a referenced text cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextUnavailable {
    /// The side-row wall withheld the document at finalize: its history held
    /// a secret no handle can replace.
    Withheld,
    /// The document, or the version the ref names, no longer reads: erased,
    /// compacted past, or undecodable.
    Unreadable,
}

/// A text a ref names, or the typed reason it cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextRead {
    /// The text at the named version.
    Text(String),
    /// The named version is gone.
    Unavailable(TextUnavailable),
}

impl TextRead {
    /// The text, when it reads.
    #[must_use]
    pub fn into_text(self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text),
            Self::Unavailable(_) => None,
        }
    }
}

/// A finalized proposal with its retained document opened once, for any
/// number of reads.
pub struct RetainedProposal {
    /// The ref-only record.
    pub record: FinalizedProposalText,
    document: std::result::Result<EntityDoc, TextUnavailable>,
}

impl RetainedProposal {
    pub(crate) fn open(stored: StoredProposal) -> Self {
        let document = match stored.document {
            Some(bytes) => {
                EntityDoc::from_snapshot(&bytes).map_err(|_| TextUnavailable::Unreadable)
            }
            None => Err(TextUnavailable::Withheld),
        };
        Self {
            record: stored.record,
            document,
        }
    }

    /// The retained document, or why it cannot be read.
    ///
    /// # Errors
    ///
    /// The [`TextUnavailable`] reason the document does not read.
    pub fn document(&self) -> std::result::Result<&EntityDoc, TextUnavailable> {
        self.document.as_ref().map_err(|reason| *reason)
    }

    /// The text at `frontier` of this proposal's document.
    #[must_use]
    pub fn text_at(&self, frontier: &LoroOpRef) -> TextRead {
        match self.document() {
            Ok(document) => document.text_at(frontier.as_bytes()).map_or(
                TextRead::Unavailable(TextUnavailable::Unreadable),
                TextRead::Text,
            ),
            Err(reason) => TextRead::Unavailable(reason),
        }
    }

    /// The text as proposed.
    #[must_use]
    pub fn proposed_text(&self) -> TextRead {
        self.text_at(&self.record.proposed_ref)
    }

    /// The text as finalized.
    #[must_use]
    pub fn final_text(&self) -> TextRead {
        self.text_at(&self.record.final_ref)
    }

    /// The text on either side of one recorded change.
    #[must_use]
    pub fn change_texts(&self, span: &OpSpan) -> (TextRead, TextRead) {
        (
            self.text_at(&span.before_ref),
            self.text_at(&span.after_ref),
        )
    }
}

/// Persists a finalized proposal artifact and its document (a Loro snapshot
/// with the whole op log), keyed by its artifact ref.
///
/// **Write-once, read-before-write.** An artifact ref survives
/// `from_snapshot`, so two clones of one artifact can each finalize their own
/// divergent history under the SAME key. The divergence is surfaced: an equal
/// record is idempotent (a retried finalize is not an error, and the document
/// first retained stays), a different one is an error.
///
/// The side-row wall reads the document as opaque bytes, so a secret in its
/// history can take no handle there and the wall refuses it (OF-067). The
/// record then lands without the document and its texts read as
/// [`TextUnavailable::Withheld`]: a finalize never fails for it, and no raw
/// secret is kept.
pub fn put_finalized_proposal_text(
    vault: &Vault,
    record: &FinalizedProposalText,
    document: &[u8],
) -> Result<()> {
    let key = record.artifact_ref.entity_id();
    vault.with_write_txn_grouped(|wtxn| {
        match PROPOSAL_ARTIFACT.get(&vault.store, &*wtxn, &key)? {
            Some(stored) if stored.record == *record => return Ok(()),
            Some(_) => {
                return Err(Error::InvariantViolation(
                    "proposal artifact is already finalized with a different record",
                ));
            }
            None => {}
        }
        let stored = |document: Option<Vec<u8>>| StoredProposal {
            record: record.clone(),
            document,
        };
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        match PROPOSAL_ARTIFACT.put(
            vault,
            &mut savepoint,
            &key,
            &stored(Some(document.to_vec())),
        ) {
            Ok(()) => Ok(savepoint.commit()?),
            Err(Error::Gate(_)) => {
                drop(savepoint);
                PROPOSAL_ARTIFACT.put(vault, wtxn, &key, &stored(None))
            }
            Err(error) => Err(error),
        }
    })
}

/// Reads the finalized proposal artifact stored under `artifact_ref`.
pub fn finalized_proposal_text(
    vault: &Vault,
    artifact_ref: ProposalArtifactRef,
) -> Result<Option<FinalizedProposalText>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(PROPOSAL_ARTIFACT
        .get(&vault.store, &rtxn, &artifact_ref.entity_id())?
        .map(|stored| stored.record))
}

/// The finalized proposal under `artifact` with its retained document, in
/// the caller's transaction; `None` when no artifact is stored there.
///
/// # Errors
///
/// Storage errors, and an undecodable record row.
pub(crate) fn retained_proposal_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: ProposalArtifactRef,
) -> Result<Option<RetainedProposal>> {
    Ok(PROPOSAL_ARTIFACT
        .get(&vault.store, txn, &artifact.entity_id())?
        .map(RetainedProposal::open))
}

/// [`retained_proposal_in_txn`] in its own read transaction.
///
/// # Errors
///
/// As [`retained_proposal_in_txn`].
pub fn retained_proposal(
    vault: &Vault,
    artifact: ProposalArtifactRef,
) -> Result<Option<RetainedProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    retained_proposal_in_txn(vault, &rtxn, artifact)
}
