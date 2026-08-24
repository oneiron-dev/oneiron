//! AUTHORITY_LOG record substrate.
//!
//! Type 122 is a fold-verified maintenance log. Replay doors validate the
//! record shape and embedded origin signature only; authority semantics stay in
//! [`fold_authority_log`], where the roster is derived from peer-signed log
//! entries rather than from a server-issued registry.
//!
//! Concern map (see each file's header for its contract):
//!
//! | file | concern |
//! |------|---------|
//! | `constants` | pinned schema version, domains, role bits, wire keys, limits |
//! | `crypto` | key material, signature envelope, transcript verification |
//! | `confirm` | owner-confirm and critical-write-confirm types |
//! | `federation_pact` | federation lifecycle/pact types, transcript, digests |
//! | `device` | device authority material and consent-role predicates |
//! | `log_entry_op` | op vocabulary, signed entry envelope, hashing, ids |
//! | `fold_state` | folded-state data model and the two-state merge |
//! | `first_seen_clock` | first-seen sidecar keys and process-local clocks |
//! | `fold_engine` | top-level fold orchestration |
//! | `fork_resolution` | equivocation/fork detection, ranking, quarantine |
//! | `entry_transition` | per-entry transition and consent/quorum predicates |
//! | `op_apply` | applies one op to a fold state |
//! | `wire_encode` / `wire_decode` | the `rmpv` codec, edited in lockstep |
//! | `vault_api` | `impl Vault` read/write doors |
//!
//! `fork_resolution` and `entry_transition` are mutually recursive and must be
//! read together for any fork or quorum correctness work.

mod confirm;
mod constants;
mod crypto;
mod device;
mod entry_transition;
mod federation_pact;
mod first_seen_clock;
mod fold_engine;
mod fold_state;
mod fork_resolution;
mod log_entry_op;
mod op_apply;
mod vault_api;
mod wire_decode;
mod wire_encode;

#[cfg(test)]
mod tests;

// Re-exports reproduce the pre-split `crate::authority::` surface exactly: each
// glob carries every item of its file at that item's own visibility, so `pub`
// stays `pub` at this path and `pub(crate)` stays `pub(crate)`, with no
// hand-maintained name list to drift out of date. The globs are also the
// module's internal wiring — sibling files and `tests` share one scope through
// `use super::*`, so the file boundaries below do not change name resolution.
pub use confirm::*;
pub use constants::*;
pub use crypto::*;
pub use device::*;
pub use federation_pact::*;
pub use fold_engine::*;
pub use fold_state::*;
pub use log_entry_op::*;

// Crate-internal doors (first-seen sidecars and clock domains) consumed by
// `batch`, `batch::export`, `facade`, `store` and `federation`.
pub(crate) use first_seen_clock::*;

// Module-internal only: nothing here leaves `authority`.
use entry_transition::*;
use fork_resolution::*;
use op_apply::*;
use wire_decode::*;
use wire_encode::*;
