//! A publication pass that stays pending before it seals anything (FIX
//! 8825): its policy did not read, so no head is sealed under a guessed one.
//! The status read names why until a pass publishes; the next pass reads the
//! policy then current again.

use super::{Publication, PublicationState, record_status};
use crate::error::Result;
use crate::store::Store;

impl Store {
    /// Records that a publication pass stayed pending for `detail`, which
    /// names no secret, before it sealed anything, and returns the
    /// publication recorded. Nothing is recorded where there is nothing to
    /// publish, where another install took the lineage over, and for an
    /// archived vault, whose custody is its replacement's.
    pub(crate) fn note_publication_pending(&self, detail: &str) -> Result<Publication> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Publication::nothing());
        };
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(Publication::nothing());
        }
        let mut publication = self.custody_publication()?;
        if matches!(
            publication.state,
            PublicationState::Nothing | PublicationState::Fenced
        ) {
            return Ok(publication);
        }
        publication.state = PublicationState::TargetPending;
        publication.detail = Some(detail.to_owned());
        record_status(&custody.journal()?, &publication)?;
        Ok(publication)
    }
}
