//! Predicate vocabulary and the D17 grammar gate: namespace constants, the
//! crate-owned well-known predicate registry, the reserved-namespace rule, and
//! the validators every predicate string passes through.

use super::*;

/// Predicate namespace for productizable memory-API records.
pub const PREDICATE_NAMESPACE_CORE: &str = "core";

/// Predicate namespace for relationship-aware companion extensions.
pub const PREDICATE_NAMESPACE_COMPANION: &str = "companion";

/// Predicate namespace for host-defined persona extensions.
pub const PREDICATE_NAMESPACE_PERSONA: &str = "persona";

/// Predicate namespace for commitment claim records.
pub const PREDICATE_NAMESPACE_COMMITMENT: &str = "commitment";

/// Layer namespace prefixes allowed for crate-owned predicate ids.
pub const PREDICATE_LAYER_NAMESPACES: [&str; 4] = [
    PREDICATE_NAMESPACE_CORE,
    PREDICATE_NAMESPACE_COMPANION,
    PREDICATE_NAMESPACE_PERSONA,
    PREDICATE_NAMESPACE_COMMITMENT,
];

/// First segments of the predicate families the engine itself defines and
/// writes outside the four layers and the reserved doors (sender reputation
/// under `channel_identity`, calendar, booking, CRM and the rest). With those
/// two they are the namespaces a pack may not take: not as its name, not in
/// a declaration, and on neither side of a shipped migration map. Append a
/// namespace when the engine starts writing a new family.
pub const ENGINE_PREDICATE_NAMESPACES: [&str; 45] = [
    "affect",
    "agent",
    "annotation",
    "blob",
    "booking",
    "brief",
    "calendar",
    "campaign",
    "channel_identity",
    "charter",
    "code",
    "clipboard",
    "comm",
    "conversation",
    "coping",
    "counterparty_contact",
    "critic_reliability",
    "crm",
    "delivery_window",
    "disclosure",
    "dreamer",
    "entity",
    "facet",
    "federation",
    "import",
    "judgment",
    "learning",
    "linkedin",
    "maintenance",
    "merge",
    "note",
    "pattern",
    "person",
    "plugin",
    "preference",
    "profile",
    "project",
    "provider",
    "repo",
    "review",
    "room",
    "state",
    "tasks",
    "vault",
    "voice",
];

/// Claim-module well-known predicate registry.
///
/// This is only the crate-owned schema list used by structural validators and
/// namespace-convention tests. Unknown well-formed predicates remain accepted.
///
/// APPEND-ONLY, and the length is a consequence rather than a budget: this is a
/// concurrent-append surface (ONE-1538 commitment predicates and ONE-1421
/// expression predicates land on their own schedules), so a rebase that drops
/// a row is a defect. Every entry present must keep its structural-validator
/// seat in `validate_claim_body_and_decode`.
pub const CLAIM_PREDICATE_REGISTRY: [&str; 11] = [
    PREDICATE_LEXICAL_QUERY_HINT,
    PREDICATE_COMPANION_EXPRESSION,
    PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED,
    PREDICATE_COREFERENCE_STATUS,
    PREDICATE_COREFERENCE_SHARE_CONSENT,
    PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
    PREDICATE_COMPANION_EXPRESSION_REGISTER,
    PREDICATE_COMPANION_EXPRESSION_KEIGO,
    PREDICATE_COMPANION_EXPRESSION_STYLE,
    crate::commitment::PREDICATE_COMMITMENT_RECORD,
];

pub use crate::write_envelope::claim_predicate::{
    MAX_PREDICATE_BYTES, RESERVED_PREDICATE_NAMESPACE,
};
pub(super) use crate::write_envelope::claim_predicate::{
    is_edge_reserved_predicate, is_engine_owned_reserved_predicate,
};
pub(crate) use crate::write_envelope::claim_predicate::{
    is_predicate_prefix, is_reserved_predicate, validate_predicate, validate_session_tag,
};

/// Claim predicate binding a Loro peer id (the device CRDT client id) to the
/// [`crate::write_envelope::WriteActor`] behind it (ED-00, ONE-1756).
///
/// Engine-reserved by construction: it sits in the `actor.*` namespace, so the
/// generic public Claim API rejects it and
/// [`crate::edit_distance::register_peer_actor`] — writing through
/// `put_reserved_claim_in_txn` — is the only author. That is what lets op
/// replay treat a binding as evidence of who a peer is rather than as a
/// caller's assertion. Deliberately NOT in [`CLAIM_PREDICATE_REGISTRY`]: the
/// registry admits only public `core.*`/`companion.*`/`persona.*` predicates.
pub const PREDICATE_ACTOR_PEER_BINDING: &str = "actor.peer_binding";

/// Claim predicate resolving an opaque actor stamp token (FIX 10930): the
/// claim's id IS the token a commit message and its receipt name in place of
/// the actor, as do a document's birth and authorship entries (FIX 11964),
/// its subject the actor, its value the actor's class.
///
/// Engine-reserved by its `actor.*` namespace, exactly like
/// [`PREDICATE_ACTOR_PEER_BINDING`], and written only by the engine's
/// `provenance::actor_stamp_in_txn` through `put_reserved_claim_in_txn`. It replicates as a binding does, so every
/// device of the vault resolves a stamp another wrote; an actor's erase
/// hard-erases it, and every stamp naming it then names no one. Never in
/// [`CLAIM_PREDICATE_REGISTRY`].
pub const PREDICATE_ACTOR_STAMP_TOKEN: &str = "actor.stamp_token";

/// Predicate families a Dreamer-authored write is ISOLATED into at the gate.
///
/// The distinction is what a wrong head costs. A persona-core head answers
/// "who is the companion", so a single conversation must never be able to
/// rewrite it. A mirroring-prone head is one a generator is apt to echo back
/// out of the transcript it just read, which is why its writes are owner
/// decisions rather than automatic ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerIsolationClass {
    /// The companion's own identity surface.
    PersonaCore,
    /// Opinions, beliefs, values and affect.
    MirroringProne,
}

/// Predicate prefixes whose heads are persona-core.
pub const PERSONA_CORE_PREFIXES: [&str; 3] = ["companion.", "persona.identity.", "core.identity."];

/// Predicate prefixes whose heads are mirroring-prone.
pub const MIRRORING_PRONE_PREFIXES: [&str; 4] =
    ["core.opinion.", "core.belief.", "core.value.", "affect."];

/// Classifies `predicate` into its isolation class, or `None` when neither
/// table matches.
///
/// Persona-core is tested FIRST, so a predicate carried by both tables is
/// persona-core: overlap resolves to the stricter class here, once, rather
/// than at each call site. Pure prefix arithmetic on the predicate string —
/// no clock, no randomness, no I/O, no registry or manifest lookup — so the
/// same predicate classifies the same way at every door.
///
/// Both tables are anchored at the FRONT and every entry carries its trailing
/// dot, so `companionship.tone` and `core.values.list` stay outside them.
#[must_use]
pub fn dreamer_isolation_class(predicate: &str) -> Option<DreamerIsolationClass> {
    if PERSONA_CORE_PREFIXES
        .iter()
        .any(|p| predicate.starts_with(p))
    {
        return Some(DreamerIsolationClass::PersonaCore);
    }
    if MIRRORING_PRONE_PREFIXES
        .iter()
        .any(|p| predicate.starts_with(p))
    {
        return Some(DreamerIsolationClass::MirroringProne);
    }
    None
}

/// Grouping unit of a dotted predicate: every segment EXCEPT the last
/// ("drop the leaf" — DESIGN-PIN A0). The grammar guarantees ≥2 segments
/// (`validate_predicate`), so the root is always non-empty on valid
/// predicates. Total on arbitrary namespaces (the wild has `oneiron.*`,
/// `user.*`, …); never panics; no registry or layer-list lookup — an
/// explicit per-predicate family field supersedes this formula when the
/// ONE-252 registry lands.
#[must_use]
pub fn predicate_root(predicate: &str) -> &str {
    match predicate.rfind('.') {
        Some(index) if index > 0 => &predicate[..index],
        _ => predicate,
    }
}
