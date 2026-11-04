//! The AUTHORITY_LOG rows an ingest with no carrier document judges each
//! arriving one beside (FIX 11959): its caller gathers them from the rows it
//! holds, as [`IngestCtx::with_residence`] gathers a carrier's.

use super::IngestCtx;
use crate::sync::selector::authority_beside::AuthorityBeside;

impl IngestCtx<'_> {
    /// Judges each arriving AUTHORITY_LOG row beside `authority`, the rows its
    /// caller holds: a recovery snapshot's, a hydrated endpoint's window, a
    /// quota replay's window. History that arrives in two or more rows then
    /// lands as it does through a carrier.
    pub(in crate::sync) fn with_authority_beside(mut self, authority: AuthorityBeside) -> Self {
        self.authority_beside = Some(authority);
        self
    }
}
