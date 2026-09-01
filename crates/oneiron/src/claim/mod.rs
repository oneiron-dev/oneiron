//! CLAIM body ABI + typed Claim API (ARCH-0003, pinned decisions D11/D17/D18).
//!
//! Type byte 0 is the single SEMANTIC entity type. Its MessagePack body is a
//! pinned storage ABI: the key set in [`CLAIM_BODY_KEYS`] (D11 short keys) is
//! the ON-DISK vocabulary. ARCH-0003's camelCase `Claim` shape is the
//! app-layer view; the engine never stores camelCase keys.
//!
//! Every type-0 write on every path (`Vault::put_entity`, `BatchBuilder`,
//! `TxnBatchBuilder`, sync replay via `apply_ops`) is structurally validated
//! here (D18). Bodies of all OTHER type bytes stay opaque at the storage
//! layer. Validation is fail-closed: a body that does not decode to a
//! MessagePack map carrying exactly the pinned vocabulary with all required
//! fields well-typed is rejected with [`crate::Error::InvalidClaimBody`] and
//! nothing is written.
//!
//! The predicate gate (D17) is part of body validation: predicates must match
//! the pinned grammar (≥2 segments of `[a-z][a-z0-9_]*` joined by `.`, total
//! ≤128 bytes) or the write fails with [`crate::Error::InvalidPredicate`]. The
//! `edge.*`, `skill.*` and `actor.*` namespaces are engine-reserved: public
//! writes are rejected with [`crate::Error::ReservedPredicate`]. Crate-private
//! provenance, skill-hub and actor-claim doors own local writes, while the
//! `sync` feature's replicated-put
//! door (`put_replicated`) admits rematerialization; every door still runs
//! full structural validation. Well-formed UNKNOWN predicates are accepted — the crate is
//! predicate-agnostic for semantics (ARCH-0003 §G.1). Crate-owned
//! well-known predicates are listed in [`CLAIM_PREDICATE_REGISTRY`] and carry
//! the first-segment layer prefix `core`, `companion`, `eiri`, or `commitment`; that is a
//! schema/code-review convention, not a package split, plugin runtime,
//! consent matrix, or semantic dispatch registry.
//!
//! File map (declarations and re-exports only live here):
//!
//! * `core_types` — [`ClaimBody`], [`ClaimSubject`], the pinned key set, the
//!   codec, and the structural-validation dispatcher. The hub; kept whole.
//! * `status` — the approval / lifecycle / source status axes.
//! * `decay` — the pure read-side aging-class `access_factor` contract.
//! * `predicate_grammar` — namespaces, registry, D17 grammar, reserved gate.
//! * `predicate_validators` — the per-predicate structural checks this module
//!   owns rather than delegating to a domain module.
//! * `lexical_query_hint` — `core.lexical.query_hint` codec primitives.
//! * `source_trust` — scope-map provenance/taint/sensitivity + read admission.
//! * `scoped_read` — the policy-gated actor-keyed read lane.
//! * `put` / `read` / `lifecycle` — the `Vault` write, read and
//!   supersession/retraction/demotion doors.
//! * `expression_preference` — the typed expression-preference write surface.

mod core_types;
mod decay;
mod expression_preference;
mod lexical_query_hint;
mod lifecycle;
mod predicate_grammar;
mod predicate_validators;
mod put;
mod read;
mod scoped_read;
mod source_trust;
mod status;

pub use core_types::*;
pub use decay::*;
pub use lexical_query_hint::*;
pub use predicate_grammar::*;
pub use predicate_validators::*;
pub(crate) use read::*;
pub use scoped_read::*;
pub use source_trust::*;
pub use status::*;

#[cfg(test)]
mod tests;
