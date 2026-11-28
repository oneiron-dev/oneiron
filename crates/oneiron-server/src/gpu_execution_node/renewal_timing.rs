//! How early a session's renewal must reach the node before its run's stop time (row W1). The
//! node's journal and scope (`jobs`, Unix only) hold a renewal to these bounds, and the issuer's
//! lead floor (`gpu_host`), which builds on every target, adds them, so both read one value.

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How long before a run's stop time (its cutoff less the stop grace) the
/// scope still takes a renewal (row W1). The systemd scope's handoff runs
/// in a control handler that lives at most 30 s, and the old cutoff timer
/// fires half a second before its stop time; a renewal this early has its
/// record written before the old timer can fire.
pub const RENEW_BEFORE_STOP_NS: u64 = 31_000_000_000;

/// How long before the run's stop time (its cutoff less the stop grace) a
/// renewal must be journaled: the scope's own bound
/// ([`RENEW_BEFORE_STOP_NS`]), plus 4 s for the journal write and the ask to
/// the scope. A renewal later than that finds a run that is being cut off:
/// it continues nothing, and the scope is never asked to take a renewal it
/// would refuse.
pub const RENEWAL_MARGIN_NS: u64 = RENEW_BEFORE_STOP_NS + 4 * NANOS_PER_SEC;
