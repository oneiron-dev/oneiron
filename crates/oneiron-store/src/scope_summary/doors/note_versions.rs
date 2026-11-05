//! A NOTE set's summary at serve and admission (FIX 6321, SCAN C028 parity
//! for NOTEs): its body pins each NOTE it covers at the version the Dreamer
//! read, the stored body's revision and the admitted projection's
//! fingerprint, and every serve reads each one again through the Dreamer's
//! own read and projection.
//!
//! A NOTE the Dreamer no longer reads as a summary source (now private, a
//! scratchpad not yet sealed, Disabled, erased or archived) withholds the
//! summary, as an erased or revised MESSAGE does: its words are not shown
//! again. A NOTE that is only edited keeps the summary served, marked stale
//! with a typed reason ([`SummaryStale`]); its re-derivation is the one the
//! edit's commit boundary queues (`rederive_changed_in_txn`).

use crate::scope_summary::codec::ScopeSummaryBody;
use crate::scope_summary::codec::invalid;
use crate::scope_summary::status::SummaryStale;
use heed::RoTxn;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// What one pinned NOTE reads as now.
pub enum NoteNow {
    /// The version the summary was composed from.
    Unchanged,
    /// Still a source the Dreamer reads, at another version.
    Edited,
    /// No longer a source the Dreamer reads.
    Unread,
}
