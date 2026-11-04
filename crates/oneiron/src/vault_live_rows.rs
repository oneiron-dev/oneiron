//! The vault's live rows: the inherent `Vault` methods that set and read the
//! rows in [`crate::live_rows`] (defined in `oneiron-base`), and the vault's
//! [`LiveRowsHolder`] for `LiveLine::enter`.

use std::sync::PoisonError;

use crate::Vault;
use crate::live_rows::{LiveRowCrossing, LiveRows, LiveRowsCell, LiveRowsHolder};

impl Vault {
    /// Sets this vault's live rows and wait deadline. Work already waiting
    /// keeps the deadline it started with; a bound takes effect at the next
    /// open and the next close.
    pub fn set_live_rows(&self, rows: LiveRows) {
        *self
            .live_rows
            .rows
            .write()
            .unwrap_or_else(PoisonError::into_inner) = rows;
    }

    /// The live rows in force.
    pub fn live_rows(&self) -> LiveRows {
        self.live_rows.rows()
    }

    /// Points this vault's row crossings at the host's question door. With
    /// none set, a crossing is logged.
    pub fn set_live_row_crossing(&self, crossing: Option<LiveRowCrossing>) {
        *self
            .live_rows
            .crossing
            .write()
            .unwrap_or_else(PoisonError::into_inner) = crossing;
    }
}

impl LiveRowsHolder for Vault {
    fn live_rows_cell(&self) -> &LiveRowsCell {
        &self.live_rows
    }
}
