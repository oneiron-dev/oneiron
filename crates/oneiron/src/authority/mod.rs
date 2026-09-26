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
//! | `first_seen_clock` | first-seen sidecar keys and the per-vault clock |
//! | `fold_engine` | top-level fold orchestration |
//! | `fork_resolution` | equivocation/fork detection, ranking, quarantine |
//! | `entry_transition` | per-entry transition and consent/quorum predicates |
//! | `op_apply` | applies one op to a fold state |
//! | `wire_encode` / `wire_decode` | the `rmpv` codec, edited in lockstep |
//! | `vault_api` | `impl Vault` read/write doors |
//!
//! `fork_resolution` and `entry_transition` are mutually recursive and must be
//! read together for any fork or quorum correctness work.

pub use crate::gate::manifest_authenticity::ManifestContribution;

mod causal_write;
mod checkpoint;
mod claim_write;
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
mod history_transfer;
mod ingest_observation;
mod log_entry_op;
mod observation_policy;
mod op_apply;
mod readonly_fold;
mod recovery_ceremony;
mod sequence_ancestry;
mod sequence_observation;
mod slip;
mod slip_pairing;
mod slip_replay;
mod slip_state;
mod slip_vault;
mod slip_wire;
mod stale_roster;
mod tier_floor;
mod vault_api;
mod wire_decode;
mod wire_encode;
mod write_authorization;

#[cfg(test)]
mod tests;

// Re-exports reproduce the pre-split `crate::authority::` surface exactly: each
// glob carries every item of its file at that item's own visibility, so `pub`
// stays `pub` at this path and `pub(crate)` stays `pub(crate)`, with no
// hand-maintained name list to drift out of date. The globs are also the
// module's internal wiring — sibling files and `tests` share one scope through
// `use super::*`, so the file boundaries below do not change name resolution.
pub use causal_write::CausalWriteDisposition;
pub use checkpoint::*;
pub use confirm::*;
pub use constants::*;
pub use crypto::*;
pub use device::*;
pub use federation_pact::*;
pub use fold_engine::*;
pub use fold_state::*;
pub use history_transfer::{VaultRecoveryRequest, recover_vaults_independently};
pub use ingest_observation::*;
pub use log_entry_op::*;
pub use observation_policy::*;
pub use recovery_ceremony::*;
pub use slip::*;
pub use slip_pairing::{
    PairingDescriptor, PairingLink, PairingPrincipal, format_pairing_link,
    pairing_binding_transcript, parse_pairing_link,
};
pub use slip_replay::{holder_proof, holder_proof_challenge};
pub use slip_state::{FoldedSlip, SlipAuthorityState};
pub use slip_vault::HostSlipIssuer;

// Crate-internal doors (first-seen sidecars and the observation clock) consumed by
// `batch`, `batch::export`, `facade`, `store` and `federation`.
pub(crate) use claim_write::{
    check_materialized_claim_causality, claim_causal_admitted, row_causal_admitted,
};
pub(crate) use first_seen_clock::*;
use readonly_fold::authority_log_rows_in_txn;
pub(crate) use readonly_fold::{
    AuthorityCachedFold, AuthorityView, advance_authority_cache_generation,
    authority_fold_readonly_for_store_in_txn, authority_view_readonly_for_store_in_txn,
};
pub(crate) use sequence_observation::record_authority_sequence_observation_in_txn;

// Module-internal only: nothing here leaves `authority`.
use entry_transition::*;
use fork_resolution::*;
use observation_policy::authority_observation_policy_in_txn;
use op_apply::*;
use sequence_observation::{AuthorityLocalObservations, authority_local_observations_in_txn};
use stale_roster::{apply_stale_roster_window, next_stale_roster_deadline};
use tier_floor::*;
use wire_decode::*;
use wire_encode::*;
