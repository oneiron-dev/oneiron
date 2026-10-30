//! A live workbook's formula cells as an export would compute them
//! (FIX 11982, FIX 12052).
//! Entry: `Vault::live_recalc`.
//!
//! A live workbook body keeps a formula cell's last computed value until an
//! export recalculates it. So the live reads an ask makes, and the reads a
//! held answer's split and a standing question's arrival compare, run through
//! the export's own projection and recalculation, the path
//! [`Vault::preview_xlsx_body`] takes, and each formula cell reads its value
//! from the recalculated workbook. A formula cell then differs exactly when
//! the value an export would give differs, and an ask reads the value an
//! export of the same body lands.
//!
//! Every read of one call recalculates at one time, in the default zone (UTC,
//! FIX 790), so NOW() and TODAY() alone never set two reads apart. When a read
//! does not recalculate (the engine refuses the workbook, or it does not
//! project), every read of the call keeps the values the body holds, as
//! before, and the artifact is logged once.
//!
//! Cost: a read of a sheet that holds a formula projects the whole body onto
//! the imported package and recalculates the whole workbook; a compare does
//! that for both of its reads. A sheet with no formula reads as before.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// The artifacts whose live workbook did not recalculate, logged once each.
static UNCOMPUTED: Mutex<BTreeSet<EntityId>> = Mutex::new(BTreeSet::new());

impl Vault {
    /// `live`, a read of `artifact`'s workbook body, projected onto its
    /// imported package and recalculated at `at` in `zone`, as an export
    /// lands it: the bytes, the change count, the engine that recalculated it
    /// and what the projection adapted. `None` when it equals `base`, the
    /// body as imported.
    pub(super) fn project_xlsx_body(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        base: &XlsxBody,
        live: &XlsxBody,
        at: u64,
        zone: &OfficeRecalcZone,
    ) -> Result<Option<(Vec<u8>, usize, Option<CalcEngineStamp>, Vec<String>)>> {
        let changes = xlsx::changes(base, live)?;
        if changes.is_empty() {
            return Ok(None);
        }
        let limits = self.docedit_package_limits()?;
        let projected = project_xlsx(
            &self.body_source(artifact, head)?,
            &changes,
            limits,
            &crate::office_body::document_resources(),
        )
        .map_err(|error| {
            document_error(
                error.resource(),
                "the body could not be projected onto its package",
            )
        })?;
        let (bytes, recalc) = recalc_xlsx(&projected.bytes, limits, at, zone)?;
        Ok(Some((bytes, changes.len(), recalc, projected.effects)))
    }

    /// `bodies`, reads of `artifact`'s live workbook, with each formula cell
    /// valued as an export of that read would compute it, when the sheet
    /// named `sheet` (any sheet when `None`) holds a formula in one of them.
    /// Never refuses: a read that does not recalculate leaves them all as
    /// they were.
    pub(super) fn live_recalc(
        &self,
        artifact: &EntityId,
        sheet: Option<&str>,
        bodies: &mut [XlsxBody],
    ) {
        let computes = |body: &XlsxBody| {
            body.sheets
                .iter()
                .filter(|entry| sheet.is_none_or(|name| entry.name == name))
                .any(|entry| entry.cells.values().any(computed))
        };
        if !bodies.iter().any(computes) {
            return;
        }
        match self.recalculated_books(artifact, bodies) {
            Ok(books) => {
                for (body, book) in bodies.iter_mut().zip(books) {
                    take_values(body, book);
                }
            }
            Err(error) => {
                if UNCOMPUTED
                    .lock()
                    .is_ok_and(|mut logged| logged.insert(*artifact))
                {
                    tracing::warn!(
                        artifact = %artifact.to_hex(),
                        %error,
                        "live workbook not recalculated; its formula cells read their last computed values"
                    );
                }
            }
        }
    }

    /// Each of `bodies` projected and recalculated as an export at one time
    /// would land it, read back. `Err` when any of them does not
    /// recalculate.
    fn recalculated_books(
        &self,
        artifact: &EntityId,
        bodies: &[XlsxBody],
    ) -> Result<Vec<XlsxBook>> {
        let head = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let base = {
            let txn = self.store.env.read_txn()?;
            let (_, doc) = self.loro_body(
                &txn,
                artifact,
                OfficeBodyKind::Xlsx,
                Some(&head.import_frontier),
            )?;
            xlsx::read(&doc)?
        };
        let limits = self.docedit_package_limits()?;
        let at = self.now_recorded_at();
        let zone = OfficeRecalcZone::default();
        let mut books = Vec::with_capacity(bodies.len());
        for body in bodies {
            let (bytes, recalc) =
                match self.project_xlsx_body(artifact, &head, &base, body, at, &zone)? {
                    Some((bytes, _, recalc, _)) => (bytes, recalc),
                    None => {
                        recalc_xlsx(&self.body_source(artifact, &head)?, limits, at, &zone)?
                    }
                };
            if recalc.is_none() {
                return Err(invalid(
                    "the formula engine did not recalculate the workbook",
                ));
            }
            let book = read_xlsx_cells(&bytes, limits, &crate::office_body::document_resources())
                .map_err(|error| {
                    document_error(
                        error.resource(),
                        "the recalculated workbook could not be read",
                    )
                })?;
            books.push(book);
        }
        Ok(books)
    }
}

/// Whether `cell` holds a computed result: a formula, or a member of an
/// array formula's range or a data table, which its formula fills.
fn computed(cell: &BodyCell) -> bool {
    cell.formula.is_some()
        || matches!(
            cell.locked,
            Some(XlsxLock::ArrayFormula | XlsxLock::DataTable)
        )
}

/// `body` with each computed cell valued as the recalculated `book` holds it;
/// a cell or sheet the book does not hold keeps its value.
fn take_values(body: &mut XlsxBody, book: XlsxBook) {
    let mut sheets: BTreeMap<String, BTreeMap<(u32, u32), XlsxValue>> = book
        .sheets
        .into_iter()
        .map(|sheet| {
            let cells = sheet
                .cells
                .into_iter()
                .map(|cell| ((cell.row, cell.col), cell.value))
                .collect();
            (sheet.name, cells)
        })
        .collect();
    for sheet in &mut body.sheets {
        let Some(values) = sheets.get_mut(&sheet.name) else {
            continue;
        };
        for (at, cell) in &mut sheet.cells {
            if !computed(cell) {
                continue;
            }
            if let Some(value) = values.remove(at) {
                cell.value = value;
            }
        }
    }
}
