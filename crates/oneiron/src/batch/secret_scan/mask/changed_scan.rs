//! Core half of `batch::secret_scan::mask::changed_scan`: its store-layer items live in `oneiron_store::batch::secret_scan::mask::changed_scan` and are
//! re-exported here. The door's second read of a plan's copy, op by op, is
//! `seal_whole::plan_seals`.

pub(crate) use oneiron_store::batch::secret_scan::mask::changed_scan::*;
