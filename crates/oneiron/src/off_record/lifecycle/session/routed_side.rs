//! A session's routed side-table transactions (moved out of the session
//! module whole), and the one a run's reply body takes to be admitted where
//! it is published (FIX 6647, FIX 5718 part 3).
//!
//! That admission is the vault's own: the base vault decides it on either
//! route, and its custody door mints only on an on-record stretch, whose
//! rows are written in base. An off-record room holds no custody of its own
//! yet, so a reply there that holds a fresh key is withheld until room-local
//! custody exists.

use super::OffRecordSession;
use crate::batch::secret_scan::AdmissionCustody;
use crate::error::Result;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};

impl OffRecordSession<'_> {
    /// One transaction over side tables on a route the caller captured, in
    /// which `f` reads every row through the composed view and writes along
    /// the route: [`Self::side_table_compare_and_put_routed`]'s two arms with
    /// the body handed over. `f` gets the base write transaction too, so a
    /// base row it writes (a spend scope) commits with the routed ones.
    ///
    /// While the room is off record the reads and writes are the view's,
    /// staged into one segment that commits with the base transaction. Once
    /// it is on record they write base, and only while the saver holds; the
    /// reads stay composed, since a row may still be one an earlier
    /// off-record run of the room wrote.
    pub(crate) fn routed_side_txn<T>(
        &self,
        route: &SessionWriteRoute,
        f: impl FnOnce(
            &mut heed::RwTxn<'_>,
            crate::side_table::RoutedDbs<'_>,
            crate::side_table::RoutedDbs<'_>,
        ) -> Result<T>,
    ) -> Result<T> {
        use crate::side_table::RoutedDbs;
        route.require_recording(&self.session_ref)?;
        match route.target() {
            RouteTarget::Discard => unreachable!("anonymous recording refused above"),
            RouteTarget::Overlay => {
                let overlay = self.entry.overlay.clone();
                self.vault.with_write_txn_grouped_after_commit(
                    |wtxn| {
                        let segment = overlay.install_txn_segment()?;
                        self.participant_in_txn(wtxn)?;
                        route.revalidate()?;
                        let view = self.vault.store.session_view(overlay.clone())?;
                        let answer = f(wtxn, RoutedDbs::Session(&view), RoutedDbs::Session(&view))?;
                        Ok((segment, answer))
                    },
                    |(segment, answer)| segment.commit().map(|()| answer),
                )
            }
            RouteTarget::Base => self.with_saver_write_txn(self.saver_check_for(route)?, |wtxn| {
                route.revalidate()?;
                let view = self.vault.store.session_view(self.entry.overlay.clone())?;
                f(wtxn, RoutedDbs::Session(&view), RoutedDbs::Base(self.vault))
            }),
        }
    }

    /// One composed read of side tables over overlay ∪ base, while the
    /// handle's participant is in the room, checked in the read.
    pub(crate) fn routed_side_read<T>(
        &self,
        f: impl FnOnce(&heed::RoTxn<'_>, crate::side_table::RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        let view = self.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        f(&rtxn, crate::side_table::RoutedDbs::Session(&view))
    }

    /// [`Self::routed_side_txn`] for a body the side-row wall admits in that
    /// transaction before it is published along `route` (FIX 6647, FIX 5718
    /// part 3): `f` also gets the custody that admission takes there. The
    /// base vault decides it on either arm; its door mints only when `route`
    /// writes base. No room-derived record or fingerprint reaches base.
    pub(crate) fn routed_admission_txn<T>(
        &self,
        route: &SessionWriteRoute,
        f: impl FnOnce(
            &mut heed::RwTxn<'_>,
            crate::side_table::RoutedDbs<'_>,
            crate::side_table::RoutedDbs<'_>,
            AdmissionCustody<'_>,
        ) -> Result<T>,
    ) -> Result<T> {
        self.routed_side_txn(route, |wtxn, read, write| {
            let custody = AdmissionCustody::routed(self.vault, &write);
            f(wtxn, read, write, custody)
        })
    }
}
