//! Policy classification over two planes.
//!
//! # The engine ships no policy
//!
//! Not a keyword, not a category list, not a line of prompt. Every moderation
//! input is SUBSTRATE-OWNER CONFIGURATION: the patterns, the policy document
//! the classifier reads, the model binding that reads it, the generation
//! parameters, and how much of the traffic gets classified at all. A future
//! admin panel drives all of it through configuration alone, without an engine
//! release — which is only true because none of it is compiled in.
//!
//! What the engine owns is the machinery around that: it stores the
//! configuration, hashes it, sends it, parses the answer under the contract the
//! owner declared, routes the verdict to the right plane, and receipts what
//! happened. Everything it can decide comes from one of exactly two planes:
//!
//! * **owner policy** — the vault owner's own document, rows and patterns, in
//!   the vault's policy manifest. Opt-in and OFF by default; when it is off,
//!   nothing classifies and no safeguard model is called. This is the only
//!   plane a local or self-hosted vault ever evaluates, and it is SOVEREIGN:
//!   it fails open, because nothing sits underneath it.
//! * **hosted legal** — a versioned, jurisdiction-scoped policy belonging to a
//!   hosted relay service, bound to that service's attested identity. It is
//!   evaluated ONLY where our own infrastructure relays someone's content, and
//!   its notices are attributed to the hosted service, never to the vault
//!   owner. It is FAIL-CLOSED: a pass that could not get an answer halts the
//!   relay. Content that never transits us is never evaluated against it.
//!
//! # Patterns are a signal, not a verdict
//!
//! A regular expression sees characters, not meaning, and the compounds that
//! matter are unbounded — so a pattern is unreliable in both directions. That
//! is why [`PolicyPatternRole::Escalate`] is the default: a hit asks the
//! safeguard model to look, and the model's verdict wins, including when it
//! overrules the pattern to `Allow`. A pattern decides on its own only where
//! the substrate owner declared it a hard rule, which is also the only coverage
//! that survives a model outage.
//!
//! # Receipts are the improvement loop
//!
//! Every pass that carries a signal is receipted with the ids of the patterns
//! that fired, the role that acted, how the verdict was reached, and — under a
//! rationale-bearing output contract — the model's own rule ids, confidence and
//! stated reason. That is what a substrate owner reads to find the pattern that
//! keeps escalating clean content and the definition their document left vague.
//! Aggregating and retaining those rows is the host's concern; the engine
//! writes them and stops there.
//!
//! # One document per plane, both planes at once
//!
//! Each plane carries exactly one policy document. When the same content needs
//! a verdict from both, the two model calls are issued CONCURRENTLY (see
//! [`classify_both_planes`]) — they are independent questions against
//! different documents, so asking them in series would only spend latency.
//!
//! No enforcement arm rewrites content. A verdict either lets the original
//! bytes through (with a notice, for `Warn`) or withholds them entirely
//! (`Block`, `RouteToHelp`) — the engine never hands a reader a substitute it
//! silently authored.
//!
//! # Where this is going (design notes, no code)
//!
//! Two expansions are anticipated and the configuration shapes are grown with
//! serde defaults so neither forces a break:
//!
//! * **A council of safeguard models.** Several bindings classifying the same
//!   content under the same document, with a quorum rule the substrate owner
//!   sets. The pieces that make this cheap already exist — the pass is async,
//!   the two-plane join is written, and a verdict already carries the binding
//!   that produced it.
//! * **Prebaked-taxonomy adapters.** LlamaGuard- and ShieldGemma-style models
//!   carry a FIXED taxonomy and their own prompt template, so they do not read
//!   a policy document at all. Those belong to a distinct binding KIND with its
//!   own rendering, not to the bring-your-own-policy path here, and mixing the
//!   two would silently reintroduce a factory taxonomy this design exists to
//!   keep out.
//!
//! [`PolicyPatternRole::Escalate`]: crate::PolicyPatternRole::Escalate
//! [`classify_both_planes`]: crate::Vault::classify_both_planes

mod binding;
mod classify;
mod concurrent;
mod contract;
mod enforce;
mod notice;
mod pattern;
mod planes;
mod prompt;
mod receipt;
mod relay;
mod request;
mod verdict;

pub use binding::PolicyContentBinding;
pub use contract::{PolicyModelAnswer, PolicyOutputContract};
pub use enforce::{
    PolicyBargeInKill, PolicyEnforcementAction, PolicyEnforcementVoice, PolicyHelpRouting,
    PolicyModelEnforcement,
};
pub use pattern::{
    POLICY_PATTERN_ID_MAX_LEN, POLICY_PATTERN_MAX_LEN, POLICY_PATTERN_RULES_MAX, PolicyPatternRole,
    PolicyPatternRule,
};
pub use planes::{
    HostedLegalAction, HostedLegalPolicy, HostedLegalRow, POLICY_DOCUMENT_MAX_LEN,
    POLICY_HOSTED_CATEGORY_MAX_LEN, PolicyPlane, PolicyRubricRow,
};
pub use prompt::PolicyClassifyPrompt;
pub use relay::{
    AttestedRelayDomain, AuthenticatedConnectionIdentity, ConnectionClass, DualPlanePass,
    EdgeServiceRegistry, HostedEdgeAttestation, InMemoryVaultSideVerdicts, RelayBoundaryDegrade,
    RelayBoundaryPass, RelayClassifiedPass, RelayResolution, RelaySafeguardTier, RelayTrustDomain,
    VaultSideVerdictSource,
};
pub use request::{
    HostedOutagePolicy, PolicyClassifyRequest, PolicyClassifySubject, PolicyGenerationParams,
    PolicyModelConfig, PolicyReasoningEffort, RelayClassifierMode,
};
pub use verdict::{
    HostedPlaneAttestation, PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence,
    PolicyHedgeBucket, PolicyPassAudit, PolicyVerdictCategory,
};

#[cfg(test)]
mod tests;
