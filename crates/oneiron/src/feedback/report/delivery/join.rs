//! One IMPORTS + installed-packs snapshot per delivery run (FIX 11632).
//!
//! One snapshot per run: the run's lanes all read the same IMPORTS and
//! installed-packs collections, instead of each lane walking both tables.
//! A mid-run import or install is visible on the next run; frozen lanes
//! never re-read and held lanes revisit every run.

use super::super::routing::IMPORTS;
use crate::skill_hub::HubImportReceipt;
use crate::skill_hub::pack_catalog::PackInstallReceipt;
use crate::{Error, Result, Vault};

/// The canonical import receipts and installed packs one run's lanes all
/// read: one IMPORTS walk + one PACK_INSTALL walk per run, instead of one
/// pair of walks per lane. Borrowed by the `_in` resolvers; lanes still
/// apply their own publisher/artifact/skill filters and uniqueness rules.
pub(super) struct ReportImportJoin {
    pub(super) receipts: Vec<HubImportReceipt>,
    pub(super) packs: Vec<PackInstallReceipt>,
}

impl Vault {
    /// One IMPORTS walk plus one installed-packs walk for the run's lanes.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn report_import_join(&self) -> Result<ReportImportJoin> {
        let txn = self.store.env.read_txn()?;
        let receipts = IMPORTS
            .iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, receipt)| receipt))
            .collect::<Result<Vec<_>>>()?;
        drop(txn);
        let packs = self.installed_packs()?;
        Ok(ReportImportJoin { receipts, packs })
    }

    /// The run's join, built on first need inside `cell` and handed to `f`.
    /// On build error returns `Err` and leaves `cell` empty so the next
    /// lane retries; lanes that need no scan never build it.
    ///
    /// # Errors
    ///
    /// Storage errors from the join build, and whatever `f` raises.
    pub(super) fn with_report_import_join<R>(
        &self,
        cell: &std::cell::RefCell<Option<ReportImportJoin>>,
        f: impl FnOnce(&ReportImportJoin) -> Result<R>,
    ) -> Result<R> {
        let needs_build = cell.borrow().is_none();
        if needs_build {
            let join = self.report_import_join()?;
            *cell.borrow_mut() = Some(join);
        }
        let borrowed = cell.borrow();
        let Some(join) = borrowed.as_ref() else {
            return Err(Error::InvariantViolation(
                "report import join missing after build",
            ));
        };
        f(join)
    }
}
