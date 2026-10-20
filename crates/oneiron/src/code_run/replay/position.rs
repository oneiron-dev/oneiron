//! A replay cursor that starts part way into its record (PR-S1): a shadow
//! arm replays one captured step from the bridge log's length at the
//! step's start. Positions stay absolute: each row is matched at its own
//! index, as from the start, with its stamps as recorded, and nothing is
//! sliced or numbered again.

use std::cell::Cell;

use super::super::support::invalid_code_run_replay;
use super::{CodeRunReplayCursor, CodeRunReplayRecord};
use crate::{Error, Result};

impl<'a> CodeRunReplayCursor<'a> {
    /// A cursor over `record` whose next call is the one at `bridge_start`,
    /// its absolute index. A position at the log's end is a cursor with no
    /// call left; [`Self::consumed`] stays absolute.
    ///
    /// # Errors
    ///
    /// A position past the record's bridge log.
    pub fn from_position(record: &'a CodeRunReplayRecord, bridge_start: u64) -> Result<Self> {
        let index = usize::try_from(bridge_start)
            .map_err(|_| Error::ArithmeticOverflow("code-run replay position"))?;
        if index > record.bridge_calls.len() {
            return Err(invalid_code_run_replay(
                "code-run replay position past the bridge log",
            ));
        }
        Ok(Self {
            record,
            next: Cell::new(index),
        })
    }
}
