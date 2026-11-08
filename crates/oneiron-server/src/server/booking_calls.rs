//! Authenticated booking calls, counted per actor in the current minute
//! (FIX 128-131). A count is a measurement, never a window: past its
//! `[limits]` row the row asks, and the call is served. Anonymous visitors
//! spend the owner's anti-abuse windows instead, which persist through the
//! vault; nothing here is persisted or refused.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use oneiron::limit_ask::EngineLimit;

/// Seconds in the minute a call is counted in.
const MINUTE_SECS: u64 = 60;

/// Every authenticated actor's calls under each row in one minute.
#[derive(Default)]
struct MinuteCounts {
    minute: u64,
    calls: HashMap<(EngineLimit, [u8; 32]), u64>,
}

/// The authenticated booking calls this server has counted this minute.
#[derive(Default)]
pub(crate) struct AuthenticatedBookingCalls {
    counts: Mutex<MinuteCounts>,
}

impl AuthenticatedBookingCalls {
    /// Counts one call by `actor` under `row` at `now_secs`, and returns
    /// the actor's calls under that row in that minute, this one included.
    /// A new minute starts every count again from zero.
    pub(crate) fn count(&self, row: EngineLimit, actor: &[u8; 32], now_secs: u64) -> u64 {
        let minute = now_secs / MINUTE_SECS;
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.minute != minute {
            counts.minute = minute;
            counts.calls.clear();
        }
        let calls = counts.calls.entry((row, *actor)).or_insert(0);
        *calls = calls.saturating_add(1);
        *calls
    }
}
