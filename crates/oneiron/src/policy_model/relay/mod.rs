//! The hosted relay boundary: where OUR infrastructure touches someone else's
//! content, and the only place the hosted legal plane is ever evaluated.
//!
//! The rule that shapes this file is that a sovereign machine owns its box. A
//! vault's own claim that it "already classified this" is not evidence to us,
//! and a vault that never routes through us is never evaluated by us at all.
//! What we do get to enforce is the legal policy of the hosted service doing
//! the relaying — bound to that service's attested identity, versioned, and
//! attributed to the service rather than to the vault owner. The binding is
//! structural: the attested identity travels inside the witness and SELECTS
//! the policy from the edge-service registry, so no relay entry point takes a
//! policy (or a jurisdiction) as a caller argument.
//!
//! # What the engine brings, and what it does not
//!
//! The engine brings NO policy. Not a pattern, not a category list, not a line
//! of prompt. The hosted service registers its own policy document, its own
//! rows and its own pattern rules; the engine stores them, hashes them, sends
//! the document to the classifier the host configured, reads the answer under
//! the contract the document declared, and receipts what happened.
//!
//! # The halt contract
//!
//! A `Block` or `RouteToHelp` halts the relay. A `Warn` does not — the original
//! bytes still go out, with the notice alongside. And a DEGRADED pass halts
//! wherever a hosted legal policy was in play: the hosted plane is fail-closed,
//! so a policy going unanswered must stop the relay rather than be answered
//! with an unexamined allow. A pass goes unanswered four ways — the safeguard
//! model failed, its answer was unreadable, the pass required a model call and
//! had no tier to make it with, or the policy in force declared no output
//! contract to read an answer under. An owner-plane-only degrade never halts;
//! the owner's plane is sovereign and has nothing underneath it.
//!
//! That is the DEFAULT, and it stays the engine's own position. Whether an
//! outage in the host's own model tier should stop the host's own relay is the
//! host's exposure to weigh, so [`HostedOutagePolicy`] lets it choose
//! availability instead — for MODEL-AVAILABILITY degrades only, and never for
//! a verdict that could not be attested. See that type for the full split.

mod boundary;
mod hosted;
mod outcome;
mod registry;
mod trust;

// Path shim: two moved bodies spell `super::planes::…` (byte-identical to the
// flat module, where `super` was `policy_model`). One level deeper `super` is
// this module, so it re-exports the name to keep those paths resolving.
use super::planes;

pub use self::outcome::{
    DualPlanePass, InMemoryVaultSideVerdicts, RelayBoundaryDegrade, RelayBoundaryPass,
    RelayClassifiedPass, RelayResolution, RelaySafeguardTier, VaultSideVerdictSource,
};
pub use self::registry::EdgeServiceRegistry;
pub use self::trust::{
    AttestedRelayDomain, AuthenticatedConnectionIdentity, ConnectionClass, HostedEdgeAttestation,
    RelayTrustDomain,
};

// Only the crate's own relay tests name these through `super::relay::…`
// (`policy_model/tests.rs` builds `RelayReceipt` literals and pins the
// `HostedDomain` mapping); no production path does.
#[cfg(test)]
pub(super) use self::boundary::RelayReceipt;
#[cfg(test)]
pub(super) use self::outcome::RelayReceiptRow;
#[cfg(test)]
pub(super) use self::registry::HOSTED_LEGAL_JURISDICTION_MAX_LEN;
#[cfg(test)]
pub(super) use self::trust::HostedDomain;
