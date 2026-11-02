//! A media stream's end, reported to its offer's health (FIX 1743, OF-305).
//! A stream takes its offer's probation slot as a request does and holds
//! it to its end, so a recovering offer opens one stream at a time, and
//! its end counts as a request's: one that answered toward recovery, one
//! that failed as its provider down. A stream cancelled only frees the
//! slot, crediting nothing.
use oneiron::llm::run_admission::MediaStreamLease;

use super::super::cooldown::ProbePermit;

/// `lease`, reporting its end to `probe`: none for a managed worker, whose
/// supervisor says when it serves.
pub(super) fn reported(lease: MediaStreamLease, probe: Option<ProbePermit>) -> MediaStreamLease {
    let Some(probe) = probe else {
        return lease;
    };
    lease.with_end_report(move |answered| {
        if answered {
            probe.answered();
        } else {
            probe.down();
        }
    })
}
