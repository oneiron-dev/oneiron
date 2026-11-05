//! A checkpoint reader joins its queue snapshot to native session visibility.

use super::OffRecordSession;
use crate::{Result, store::SessionStoreView};

impl OffRecordSession<'_> {
    pub(crate) fn checkpoint_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<SessionStoreView<'_>> {
        self.entry.overlay.synchronize_publication()?;
        self.participant_in_txn(txn)?;
        self.read_view()
    }
}
