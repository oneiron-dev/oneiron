//! Policy classification over two planes.
//!
//! The engine ships no opinion of its own about a vault's content. Everything
//! it can decide comes from one of exactly two planes:
//!
//! * **owner policy** — rows the vault owner wrote, in the vault's own policy
//!   manifest. Opt-in and OFF by default; when it is off, nothing classifies
//!   and no safeguard model is called. This is the only plane a local or
//!   self-hosted vault ever evaluates.
//! * **hosted legal** — a versioned, jurisdiction-scoped policy belonging to a
//!   hosted relay service, bound to that service's attested identity. It is
//!   evaluated ONLY where our own infrastructure relays someone's content, and
//!   its notices are attributed to the hosted service, never to the vault
//!   owner. Content that never transits us is never evaluated against it.
//!
//! No enforcement arm rewrites content. A verdict either lets the original
//! bytes through (with a notice, for `Warn`) or withholds them entirely
//! (`Block`, `RouteToHelp`) — the engine never hands a reader a substitute it
//! silently authored.

mod binding;
mod classify;
mod enforce;
mod notice;
mod planes;
mod prompt;
mod receipt;
mod relay;
mod request;
mod tripwire;
mod verdict;

pub use binding::PolicyContentBinding;
pub use enforce::{
    PolicyBargeInKill, PolicyEnforcementAction, PolicyEnforcementVoice, PolicyHelpRouting,
    PolicyModelEnforcement,
};
pub use planes::{
    HostedLegalAction, HostedLegalPolicy, HostedLegalRow, PolicyPlane, PolicyRubricRow,
};
pub use prompt::PolicyClassifyPrompt;
pub use relay::{
    AttestedRelayDomain, AuthenticatedConnectionIdentity, ConnectionClass, EdgeServiceRegistry,
    HostedEdgeAttestation, InMemoryVaultSideVerdicts, RelayFloorDegrade, RelayFloorPass,
    RelayTrustDomain, VaultSideVerdictSource, relay_floor_pass_or_hosted_fallback,
};
pub use request::{PolicyClassifyRequest, PolicyClassifySubject, PolicyModelConfig};
pub use verdict::{
    HostedLegalCategory, HostedPlaneAttestation, PolicyClassifyDecision, PolicyClassifyVerdict,
    PolicyConfidence, PolicyHedgeBucket, PolicyVerdictCategory,
};

#[cfg(test)]
mod tests;
