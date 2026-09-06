//! Predicate vocabulary and the D17 grammar gate: namespace constants, the
//! crate-owned well-known predicate registry, the reserved-namespace rule, and
//! the validators every predicate string passes through.

use super::*;
use crate::error::{Error, Result};

/// Predicate namespace for productizable memory-API records.
pub const PREDICATE_NAMESPACE_CORE: &str = "core";

/// Predicate namespace for relationship-aware companion extensions.
pub const PREDICATE_NAMESPACE_COMPANION: &str = "companion";

/// Predicate namespace for Eiri persona-specific extensions.
pub const PREDICATE_NAMESPACE_EIRI: &str = "eiri";

/// Predicate namespace for commitment claim records.
pub const PREDICATE_NAMESPACE_COMMITMENT: &str = "commitment";

/// Layer namespace prefixes allowed for crate-owned predicate ids.
pub const PREDICATE_LAYER_NAMESPACES: [&str; 4] = [
    PREDICATE_NAMESPACE_CORE,
    PREDICATE_NAMESPACE_COMPANION,
    PREDICATE_NAMESPACE_EIRI,
    PREDICATE_NAMESPACE_COMMITMENT,
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

/// Maximum predicate length in bytes (D17).
pub const MAX_PREDICATE_BYTES: usize = 128;

/// Reserved predicate namespace prefix (D17): `edge.*` predicates may only
/// be written through the `pub(crate)` provenance door.
pub const RESERVED_PREDICATE_NAMESPACE: &str = "edge";

/// Reserved skill predicate namespace: `skill.*` claims are authored only by
/// the crate-private skill-hub doors, never by the generic public Claim API.
pub(crate) const RESERVED_SKILL_PREDICATE_NAMESPACE: &str = "skill";

/// Reserved actor predicate namespace (ARCH-0053 §9, ONE-1739): `actor.*`
/// claims are STATES with meaning-by-projection (doc-13 r1/r3) — the
/// attribution projector, the Dreamer distill and the provider-confidence door
/// author them, and nobody else may. Reserving the namespace closes the hole
/// [`crate::provider_confidence`] documented on `actor.confidence_prior`: a
/// policy-authorized generic `put_claim` could plant a trust-bearing head that
/// the read path then honored. Engine doors keep writing through
/// `put_reserved_claim_in_txn`, the same exemption `skill.*` uses.
pub(crate) const RESERVED_ACTOR_PREDICATE_NAMESPACE: &str = "actor";

/// Claim predicate binding a Loro peer id (the device CRDT client id) to the
/// [`crate::write_envelope::WriteActor`] behind it (ED-00, ONE-1756).
///
/// Engine-reserved by construction: it sits in the `actor.*` namespace, so the
/// generic public Claim API rejects it and
/// [`crate::edit_distance::register_peer_actor`] — writing through
/// `put_reserved_claim_in_txn` — is the only author. That is what lets op
/// replay treat a binding as evidence of who a peer is rather than as a
/// caller's assertion. Deliberately NOT in [`CLAIM_PREDICATE_REGISTRY`]: the
/// registry admits only public `core.*`/`companion.*`/`eiri.*` predicates.
pub const PREDICATE_ACTOR_PEER_BINDING: &str = "actor.peer_binding";

/// Per-`(actor, scope)` amendment cost: how much a decider had to edit this
/// actor's proposals in one scope (ARCH-0003 §G.1, ARCH-0056 §5, ED-03).
///
/// Engine-reserved by its `actor.*` namespace, exactly like
/// [`PREDICATE_ACTOR_PEER_BINDING`], and written only through
/// [`crate::actor_claims::write_actor_claim`]'s chokepoint. Never in
/// [`CLAIM_PREDICATE_REGISTRY`]: the registry admits only public
/// `core.*`/`companion.*`/`eiri.*` predicates, and its landed test rejects a
/// reserved namespace outright.
pub const PREDICATE_ACTOR_EDIT_COST: &str = "actor.edit_cost";

/// Per-`(skill, scope)` amendment cost: how much a decider had to edit
/// proposals that rode this skill (ARCH-0003 §G.1, ARCH-0056 §5, ED-03).
///
/// The `skill.*` sibling of [`PREDICATE_ACTOR_EDIT_COST`], on the reserved
/// namespace `skill_hub` and `skill_reliability` already author through
/// `put_reserved_claim_in_txn`. Registry-exempt for the same reason.
pub const PREDICATE_SKILL_EDIT_COST: &str = "skill.edit_cost";

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
pub const PERSONA_CORE_PREFIXES: [&str; 3] = ["companion.", "eiri.persona.", "core.identity."];

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

/// Validates a predicate against the pinned D17 grammar: ≥2 segments, each
/// matching `[a-z][a-z0-9_]*`, joined by `.`, total ≤128 bytes.
///
/// When `allow_reserved` is `false` (every public write path), well-formed
/// predicates in the reserved `edge.*` namespace are rejected with
/// [`Error::ReservedPredicate`]. The provenance unit writes through the
/// `pub(crate)` door which sets `allow_reserved` to `true`, as does the
/// sync-replay door (`put_replicated`) so replicated provenance Claims
/// rematerialize; reads always allow reserved predicates so stored
/// provenance Claims stay decodable. `allow_reserved` skips ONLY this
/// reserved-namespace arm — the grammar checks above run unconditionally.
pub(crate) fn validate_predicate(predicate: &str, allow_reserved: bool) -> Result<()> {
    if predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "exceeds 128 bytes",
        });
    }

    let mut segments = 0_usize;
    for segment in predicate.split('.') {
        if !valid_predicate_segment(segment) {
            return Err(Error::InvalidPredicate {
                predicate: predicate.to_owned(),
                reason: "segments must match [a-z][a-z0-9_]*",
            });
        }
        segments += 1;
    }
    if segments < 2 {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "requires at least 2 dot-joined segments",
        });
    }

    if !allow_reserved && is_reserved_predicate(predicate) {
        return Err(Error::ReservedPredicate {
            predicate: predicate.to_owned(),
        });
    }

    Ok(())
}

/// Returns `true` when `predicate`'s first dot-separated segment is one of the
/// reserved `edge`, `skill` or `actor` namespaces (D17, ARCH-0053 §9). Their
/// writes and lifecycle transitions are owned by dedicated crate-private doors,
/// so the generic Claim API rejects them.
pub(crate) fn is_reserved_predicate(predicate: &str) -> bool {
    is_edge_reserved_predicate(predicate) || is_engine_owned_reserved_predicate(predicate)
}

pub(super) fn is_edge_reserved_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(RESERVED_PREDICATE_NAMESPACE)
}

/// The reserved namespaces whose lifecycle the ENGINE drives (`skill.*`,
/// `actor.*`), as opposed to `edge.*`, whose transitions must re-stamp
/// provenance-derived edge state and therefore stay exclusively edge-owned.
pub(super) fn is_engine_owned_reserved_predicate(predicate: &str) -> bool {
    let namespace = predicate.split('.').next();
    namespace == Some(RESERVED_SKILL_PREDICATE_NAMESPACE)
        || namespace == Some(RESERVED_ACTOR_PREDICATE_NAMESPACE)
}

fn valid_predicate_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

pub(crate) fn validate_session_tag(session_tag: &str) -> Result<()> {
    if session_tag.trim().is_empty() {
        return Err(Error::InvalidClaimBody(
            "sess must be a non-empty, non-whitespace string",
        ));
    }
    Ok(())
}
