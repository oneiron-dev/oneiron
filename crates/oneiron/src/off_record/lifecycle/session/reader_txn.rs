//! Reader-ledger updates carried from a sealed room into the base vault.

use super::*;
use crate::side_table::RoutedDbs;

impl OffRecordSession<'_> {
    /// Writes a reader transaction's rows along its route. A base writer
    /// retires just its changed full keys from the sealed overlay after
    /// commit, before another reader writer can observe the composed ledger.
    pub(crate) fn routed_reader_txn<T>(
        &self,
        route: &SessionWriteRoute,
        f: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<(T, Vec<Vec<u8>>)>,
    ) -> Result<T> {
        route.require_recording(&self.session_ref)?;
        if route.target() != RouteTarget::Base {
            return self.routed_side_txn(route, |txn, read, write| {
                f(txn, read, write).map(|(answer, _)| answer)
            });
        }
        self.with_saver_write_txn_after_commit(
            self.saver_check_for(route)?,
            |txn| {
                // Install inside the base writer: base -> publication permit.
                // The installed segment closes its group before another member
                // can wait on that permit inside the same shared commit.
                let retirement = route.install_base_row_retirement()?;
                route.revalidate()?;
                let view = self.vault.store.session_view(self.entry.overlay.clone())?;
                let (answer, keys) =
                    f(txn, RoutedDbs::Session(&view), RoutedDbs::Base(self.vault))?;
                Ok((retirement, answer, keys))
            },
            |(retirement, answer, keys)| retirement.commit(keys).map(|()| answer),
        )
    }
}
