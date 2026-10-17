//! The served host's side of the built-in connector packs (OF-519): the
//! connection checks only a served host can run.

mod checks;

pub(crate) use checks::HostConnectionChecks;
