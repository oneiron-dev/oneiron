//! M8 forward test oracle — authored by the path opener (ONE-1685) for the
//! M8-A / M8-B remainder tickets. CONTRACT-level red tests, each behind
//! `#[ignore = "armed by ONE-XXXX"]`.
//!
//! Arming protocol (owner path-opener pattern): the arming ticket removes
//! the `#[ignore]`, adapts SIGNATURES (including replacing the
//! `unimplemented!()` ARMING-SEAM helpers below with the real engine
//! surfaces), and NEVER weakens an assert. Count-asserts throughout —
//! never `any()`.
//!
//! The one oracle left here, ONE-1691's intent ledger (`r1691_ledger`), is
//! armed: its ARMING-SEAM helper drives the real `execute_outbound_effect`
//! through a recording transport.
//!
//! Armed-ticket-owned axes (no contract-level oracle is expressible today;
//! proving each is the ARMING ticket's job, not a stub test's):
//! * ONE-1687: creation-time SYNC suppression of a fenced summary — the
//!   sync queue has no per-entity write feed to count yet;
//! * ONE-1690: the stdio child's OS sandbox (env/FD/fs allowlist);
//! * ONE-1690: destination TLS-verify + the human-shown resolved endpoint;
//! * ONE-1690: identity-PIN (deferred by the ticket itself — a
//!   registry-rebind needs a compromised host, outside the gate's threat
//!   model).

mod r1691_ledger;
mod shared;
