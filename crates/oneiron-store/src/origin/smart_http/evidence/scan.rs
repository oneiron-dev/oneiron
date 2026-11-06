//! What a receive-pack outcome says of its push's scan (FIX 8032): the
//! summary the intent's writer records in the transaction that writes the
//! push's marks, the outcome fields that carry it, and the check a reader of
//! the outcome holds it to. A clean outcome is written as every outcome was
//! before marks; a marked one says so at its own schema, with how many marks
//! the push's writer added. Neither names a key, an excerpt, a member, or a
//! hash of any of them.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::write_envelope::claim_body::ClaimBody;
use oneiron_base::error::Result;

/// The schema a clean or unscanned outcome is written at, as before marks.
pub const OUTCOME_SCHEMA: u16 = 1;
/// The schema a marked outcome is written at: its `scan` says `marked`, and
/// its `mark_count` follows.
pub const MARKED_OUTCOME_SCHEMA: u16 = 2;

/// What the landed door's scan of one admitted push came to, as its intent
/// records it in the transaction that writes the push's marks. It is the
/// outcome's only source for the scan: a recovered push's door report is
/// rebuilt clean whatever its scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceivePackScanSummary {
    /// The scan found no key.
    Clean,
    /// The door admitted the push with its keys marked (FIX 7608). The
    /// door's disposition makes it marked, never its count.
    Marked {
        /// How many `repo.secret_mark` facts the intent's transaction newly
        /// wrote: one per source and placement, spans and opaque residue
        /// alike.
        mark_count: u64,
    },
}
