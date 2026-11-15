//! The weekly return-table pass (L2-37 PR-1; ARCH-0067 #idle-fold-policy: "E+'s tables are
//! rebuilt weekly").
//!
//! It reads the trailing eight weeks of wait rows (the research window was 61.9 days), counts a
//! wait still open a day after it parked as never (the reference's top edge, 86,400 s), and
//! writes one cell per session kind, wait class, four-hour band and weekend: the sorted return
//! gaps and the never count, the reference's `Dist`. A reader backs off from a thin cell to its
//! band, its kind and all by merging the cells' sorted lists, so no second table is kept. Rows
//! older than the window are deleted. No model is called and nothing is proposed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{IdleSessionKind, IdleWaitClass, WAITS, band_of};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{Result, Vault};

/// The return cells. Key: [session kind, wait class, band, weekend].
const CELLS: SideTable<[u8; 4], IdleReturnCell, Named> =
    SideTable::new(&side_table::IDLE_FOLD_RETURN_CELLS);
/// When the pass last rebuilt the cells, in unix seconds. Key: ().
const BUILT: SideTable<(), u64, Raw> = SideTable::new(&side_table::IDLE_FOLD_RETURN_CELLS_BUILT);

/// The pass runs nightly with the Coach's other jobs and rebuilds once a week.
const REBUILD_EVERY_SECS: u64 = 7 * 86_400;
/// The waits the cells are built from: the trailing eight weeks.
const WINDOW_SECS: u64 = 8 * 7 * 86_400;
/// A wait open longer than a day, or one that came back after more than a day, counts as never.
const NEVER_AFTER_SECS: u64 = 86_400;

/// One cell: how long each wait of its key took to come back, and how many never did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdleReturnCell {
    /// Ascending.
    pub(crate) returned_after_secs: Vec<u32>,
    pub(crate) never: u32,
}

fn cell_key(kind: IdleSessionKind, class: IdleWaitClass, band: u8, weekend: bool) -> [u8; 4] {
    [kind.code(), class.code(), band, u8::from(weekend)]
}

/// Rebuilds the return cells from the wait rows at `now_secs`, unless they were rebuilt less
/// than a week before; `true` when it rebuilt. The band is read on the owner's clock, the
/// reminder route's zone or offset at each park, else UTC.
pub(crate) fn rebuild_return_tables(vault: &Vault, now_secs: u64) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        if BUILT
            .get(&vault.store, txn, &())?
            .is_some_and(|built| now_secs.saturating_sub(built) < REBUILD_EVERY_SECS)
        {
            return Ok(false);
        }
        let route = vault.commitment_reminder_route_in_txn(txn)?;
        let now_ms = now_secs.saturating_mul(1_000);
        let window_start_ms = now_secs.saturating_sub(WINDOW_SECS).saturating_mul(1_000);
        let mut cells: BTreeMap<[u8; 4], IdleReturnCell> = BTreeMap::new();
        for key in WAITS.scan_keys(&vault.store, txn, &[])? {
            let Some(mut wait) = WAITS.get_lenient(&vault.store, txn, &key)? else {
                continue;
            };
            if wait.parked_at_ms < window_start_ms {
                WAITS.delete(&vault.store, txn, &key)?;
                continue;
            }
            let returned_after_secs = match wait.returned_at_ms {
                Some(returned_at_ms) => {
                    let secs = returned_at_ms.saturating_sub(wait.parked_at_ms) / 1_000;
                    u32::try_from(secs)
                        .ok()
                        .filter(|_| secs <= NEVER_AFTER_SECS)
                }
                None if wait.never => None,
                None if now_ms.saturating_sub(wait.parked_at_ms) > NEVER_AFTER_SECS * 1_000 => {
                    wait.never = true;
                    WAITS.put(&vault.store, txn, &key, &wait)?;
                    None
                }
                // Still waiting, and not for a day yet: how it ends is not known.
                None => continue,
            };
            let parked_secs = wait.parked_at_ms / 1_000;
            let offset = route
                .as_ref()
                .and_then(|route| route.utc_offset_minutes_at(parked_secs))
                .unwrap_or(0);
            let (band, weekend) = band_of(parked_secs, offset);
            let cell = cells
                .entry(cell_key(wait.session_kind, wait.wait_class, band, weekend))
                .or_default();
            match returned_after_secs {
                Some(secs) => cell.returned_after_secs.push(secs),
                None => cell.never = cell.never.saturating_add(1),
            }
        }
        for key in CELLS.scan_keys(&vault.store, txn, &[])? {
            CELLS.delete(&vault.store, txn, &key)?;
        }
        for (key, mut cell) in cells {
            cell.returned_after_secs.sort_unstable();
            CELLS.put(&vault.store, txn, &key, &cell)?;
        }
        BUILT.put(&vault.store, txn, &(), &now_secs)?;
        Ok(true)
    })
}

/// The waits E+ reads for a wait of `kind` and `class` parked in `band` and `weekend`, at
/// `elapsed_secs` into it (L2-37 PR-2): the first level of the reference's back-off whose waits
/// still waiting then reach the class's floor, its cells merged. A wait on a person backs off
/// from its own cell to its band, its session kind and every person wait (min 30, `user_Eplus`);
/// a wait on a tool states no length here (FIX [IDLE-FOLD-STATED-LENGTH-NO-SITE]), so it reads
/// its session kind's tool waits and then every tool wait (min 20, `tool_E`). `None` when even
/// the last level is below the floor: RULING L2-37-COLD-START = A reads that as Expire.
pub(crate) fn backed_off_cell(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait: (IdleSessionKind, IdleWaitClass),
    (band, weekend): (u8, bool),
    elapsed_secs: u64,
) -> Result<Option<IdleReturnCell>> {
    let (kind, class) = wait;
    let mut cells = Vec::new();
    for key in CELLS.scan_keys(&vault.store, txn, &[])? {
        if key[1] != class.code() {
            continue;
        }
        if let Some(cell) = CELLS.get_lenient(&vault.store, txn, &key)? {
            cells.push((key, cell));
        }
    }
    let own_kind = |key: &[u8; 4]| key[0] == kind.code();
    let own_band = |key: &[u8; 4]| own_kind(key) && key[2] == band;
    let own_cell = |key: &[u8; 4]| own_band(key) && key[3] == u8::from(weekend);
    let every = |_: &[u8; 4]| true;
    let (floor, levels): (u64, Vec<&dyn Fn(&[u8; 4]) -> bool>) = match class {
        IdleWaitClass::User => (30, vec![&own_cell, &own_band, &own_kind, &every]),
        IdleWaitClass::Tool => (20, vec![&own_kind, &every]),
    };
    for level in levels {
        let mut merged = IdleReturnCell::default();
        for (_, cell) in cells.iter().filter(|(key, _)| level(key)) {
            merged
                .returned_after_secs
                .extend_from_slice(&cell.returned_after_secs);
            merged.never = merged.never.saturating_add(cell.never);
        }
        merged.returned_after_secs.sort_unstable();
        if super::e_plus::still_waiting(&merged, elapsed_secs) >= floor {
            return Ok(Some(merged));
        }
    }
    Ok(None)
}

/// The cell of one session kind, wait class, band and weekend, as the last rebuild wrote it.
#[cfg(oneiron_test_support)]
pub(crate) fn return_cell(
    vault: &Vault,
    kind: IdleSessionKind,
    class: IdleWaitClass,
    band: u8,
    weekend: bool,
) -> Result<Option<IdleReturnCell>> {
    let txn = vault.store.env.read_txn()?;
    CELLS.get(&vault.store, &txn, &cell_key(kind, class, band, weekend))
}
