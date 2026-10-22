//! A Memory handle's per-file repo read that may ask for real bytes (FIX
//! 7608 slice 2b-ii-A, GAP-B / FIX 8960).
//!
//! A handle whose host proved the actual recipient (an agent, never the
//! credential's owner standing in for one) may ask, per file and with a
//! why, for a marked file's stored bytes through the shipped file reveal.
//! Every other handle reads as before: the owner at the owner's own door
//! reads stored bytes with no why, consent or claim walk added, and a
//! masked handle with no why or no proven recipient reads the projection.
//! Bulk and hydration reads never come here: they stay mask-only.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B wires the per-file why readers"
)]

use super::super::{Memory, MemoryResult};
use crate::error::Result;
use crate::origin::secret_marks::RepoBlobMarks;
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::origin::secret_projection::reveal::{
    RepoFileRevealRead, RepoReadDoor, read_repo_file_with_reveal,
};
use crate::origin::secret_projection::{RepoBodyProjection, RepoSecretAudience, project_repo_blob};
use crate::secret_custody::{RepoFileOriginal, RepoFileReadDisclosure};

impl Memory<'_> {
    /// Binds this handle to an MCP tool call or run whose actual recipient
    /// the host proved: its repo reads are masked, as
    /// [`Self::for_repo_tool_recipient`]'s, and a per-file read that says
    /// why may ask the owner for that file's real bytes as `recipient`. It
    /// admits nothing: the engine revalidates the recipient and the live
    /// grant at every read. Room and turn handles built from this one keep
    /// it.
    #[must_use]
    pub fn for_repo_reveal_recipient(mut self, recipient: RepoRevealRecipient) -> Self {
        self.repo_tool_recipient.bind(recipient);
        self
    }

    /// CALL 3 for this handle: a per-file read's `why` asks the owner only
    /// when this handle reads masked and its host proved the recipient;
    /// otherwise the read is today's.
    ///
    /// # Errors
    /// A present `why` the file read's own validation refuses.
    pub(crate) fn repo_file_disclosure(&self, why: Option<&str>) -> Result<RepoFileReadDisclosure> {
        let asker = self
            .repo_tool_recipient
            .actual()
            .map(RepoRevealRecipient::asker);
        RepoFileReadDisclosure::from_optional_why(why, asker)
    }

    /// One per-file read of the ORIGINAL `original` whose readable marks are
    /// `marks`, through `door`: the stored bytes for a reader of stored
    /// bytes, else the masked reader's read with `why` (CALL 3) through the
    /// file reveal. `readmit` re-admits the door's pins after the reveal's
    /// receipts commit.
    ///
    /// # Errors
    /// The read's own, a refused `why`, or a store failure.
    pub(crate) fn repo_file_read_sighted<F, R>(
        &self,
        original: &RepoFileOriginal,
        marks: &RepoBlobMarks,
        why: Option<&str>,
        door: RepoReadDoor,
        read_exact: F,
        readmit: R,
    ) -> MemoryResult<RepoFileRevealRead>
    where
        F: FnOnce() -> Result<Vec<u8>>,
        R: FnOnce() -> Result<()>,
    {
        if !self.repo_reads_masked()? {
            let exact = read_exact()?;
            return Ok(RepoFileRevealRead {
                projection: RepoBodyProjection::Exact(exact),
                proof: None,
                byte_route: None,
            });
        }
        let disclosure = self.repo_file_disclosure(why)?;
        if disclosure == RepoFileReadDisclosure::Masked {
            let projection =
                project_repo_blob(self.vault, marks, &RepoSecretAudience::Masked, read_exact)?;
            return Ok(RepoFileRevealRead {
                projection,
                proof: None,
                byte_route: None,
            });
        }
        Ok(read_repo_file_with_reveal(
            self.vault, original, marks, disclosure, door, read_exact, readmit,
        )?)
    }
}
