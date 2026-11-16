//! oneiron-dreamer — the Dreamer's maintenance jobs outside the engine
//! (untangle 6.9c, S69-RUN = A).
//!
//! A job here chooses; the engine judges and writes. Each job reads and
//! commits only through the [`oneiron_remote::OneironClient`] its host binds
//! to one admitted attempt (`OneironClient::for_dreamer_attempt`), so the
//! engine proves the attempt's lease and the Dreamer's live reach at every
//! call. The crate's normal dependencies are `oneiron-remote`, `serde` and
//! `serde_json` only; `scripts/ci/check_dreamer_crate_deps.sh` holds that
//! line in CI.

pub mod strength_archive;
