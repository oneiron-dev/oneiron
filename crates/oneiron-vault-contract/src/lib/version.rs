//! Wire version constants and SLIM gating.

/// First contract version carrying the SLIM rung. The v1 -> v2 bump is
/// additive-only: every v1 request and response keeps byte-identical semantics
/// except `Ping.contract_version`, which now reports 2 as the negotiation signal;
/// v1 peers are never sent a v2-only request.
pub const SLIM_CONTRACT_VERSION: u32 = 2;

/// The wire version this crate speaks. v3 adds the typed ctl refusal
/// ([`CtlResponse::Refused`](crate::CtlResponse::Refused)): a vault frozen for
/// reap answers a write it refuses with the bound it names, where v2 answered
/// `Ok { ok: false }`. v3 also carries the vault's live training setting
/// ([`ManagedTrainingSetting`](crate::ManagedTrainingSetting)) on every ledger
/// report, required on `LedgerUpdate` and `PrepareReap` alike, and how the
/// vault came up ([`ManagedReadiness`](crate::ManagedReadiness)) on every
/// `Ping`. Supervisor and vault move to v3 together; no v2 reader is kept.
pub const CONTRACT_VERSION: u32 = 3;

/// True when a peer advertising `version` accepts the SLIM ctl surface.
/// Supervisors ping first and send `Shed` only when this holds. With a v1 peer,
/// they skip the shed rung and retain the existing reap protocol.
#[must_use]
pub const fn supports_slim(version: u32) -> bool {
    version >= SLIM_CONTRACT_VERSION
}
