//! Supervisor ⇄ vault child-process contract: wire types, credential framing,
//! limits. Both sides of the seam build against this crate so framing bugs
//! cannot diverge: the node supervisor (Hypnos) on one side, and every
//! vault-process implementation on the other (the engine's managed serve
//! mode, the conformance stub, or any self-hosted supervisor speaking the
//! same protocol).
//!
//! Versioning: crate SemVer and wire compatibility are separate things. The
//! wire is governed by [`CONTRACT_VERSION`]; any incompatible wire change
//! (new required field, new enum variant a peer must understand) bumps it.
//! Consumers pin this crate at an exact revision and run cross-repo
//! conformance before moving the pin.

mod ctl;
mod ledger;
mod limits;
mod secrets;
mod version;
mod wake;

/// The commitment RECURRENCE vocabulary (CMT-2, ONE-1539).
///
/// Strictly additive and strictly nested: the root [`Schedule`] above is the
/// wake-ledger's one-shot instruction to the supervisor and is untouched, so
/// [`CONTRACT_VERSION`] does not move. This module is the shared *recurrence*
/// vocabulary — one implementation, two consumers (ARCH-0060 [CAL-03]): a
/// commitment series, and an ICS poll cadence expressed as an interval on this
/// same enum rather than as a second recurrence primitive ([CAL-02]).
///
/// Nothing here reaches the wire today. It lives in the contract crate so the
/// vocabulary a vault persists and a supervisor would one day schedule against
/// cannot fork into two spellings.
pub mod commitment;

#[cfg(test)]
mod tests;

pub use self::ctl::{CtlRequest, CtlResponse, ShedBlockerWire, ShedCause, ShedStatus};
pub use self::ledger::{LedgerAck, LedgerUpdate};
pub use self::limits::{
    CREDENTIALS_LEN, DEK_LEN, MAX_CTL_LINE, MAX_LEDGER_ENTRIES, MAX_REASON_TAG, MAX_WAKE_ID,
    READY_BYTE, TOKEN_LEN,
};
pub use self::secrets::{
    Credentials, TokenHex, from_hex, hex, read_credentials, write_credentials,
};
pub use self::version::{CONTRACT_VERSION, SLIM_CONTRACT_VERSION, supports_slim};
pub use self::wake::{
    Schedule, UnixTs, WakeEntry, now_ts, valid_vault_name, validate_wake_entries,
};

// The flat lib.rs module used to provide these names to the sibling test
// module through `use super::*`: the serde derive macros the frozen v1
// schema enums name bare. After the directory split the seam re-imports
// them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use serde::{Deserialize, Serialize};
