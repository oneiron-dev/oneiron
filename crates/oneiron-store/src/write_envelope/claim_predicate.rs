//! Predicate grammar and the engine-owned predicate vocabulary used by stored claims.
use super::claim_body::PREDICATE_VAULT_DEFAULT_FACET;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{ClaimError, Error, Result};

/// Maximum predicate length in bytes (D17).
pub const MAX_PREDICATE_BYTES: usize = 128;

/// Reserved predicate namespace prefix (D17): `edge.*` predicates may only
/// be written through the `pub(crate)` provenance door.
pub const RESERVED_PREDICATE_NAMESPACE: &str = "edge";

/// Reserved skill predicate namespace: `skill.*` claims are authored only by
/// the crate-private skill-hub doors, never by the generic public Claim API.
const RESERVED_SKILL_PREDICATE_NAMESPACE: &str = "skill";

/// Reserved actor predicate namespace (ARCH-0053 §9, ONE-1739): `actor.*`
/// claims are STATES with meaning-by-projection (doc-13 r1/r3) — the
/// attribution projector, the Dreamer distill and the provider-confidence door
/// author them, and nobody else may. Reserving the namespace closes the hole
/// `provider_confidence` documented on `actor.confidence_prior`: a
/// policy-authorized generic `put_claim` could plant a trust-bearing head that
/// the read path then honored. Engine doors keep writing through
/// `put_reserved_claim_in_txn`, the same exemption `skill.*` uses.
const RESERVED_ACTOR_PREDICATE_NAMESPACE: &str = "actor";

/// Validates a predicate against the pinned D17 grammar: ≥2 segments, each
/// matching `[a-z][a-z0-9_]*`, joined by `.`, total ≤128 bytes.
///
/// When `allow_reserved` is `false` (every public write path), well-formed
/// predicates in the reserved `edge.*` namespace are rejected with
/// [`ClaimError::ReservedPredicate`](oneiron_contracts::error::ClaimError::ReservedPredicate). The provenance unit writes through the
/// `pub(crate)` door which sets `allow_reserved` to `true`, as does the
/// sync-replay door (`put_replicated`) so replicated provenance Claims
/// rematerialize; reads always allow reserved predicates so stored
/// provenance Claims stay decodable. `allow_reserved` skips ONLY this
/// reserved-namespace arm — the grammar checks above run unconditionally.
pub fn validate_predicate(predicate: &str, allow_reserved: bool) -> Result<()> {
    if predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::Claim(ClaimError::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "exceeds 128 bytes",
        }));
    }

    let mut segments = 0_usize;
    for segment in predicate.split('.') {
        if !valid_predicate_segment(segment) {
            return Err(Error::Claim(ClaimError::InvalidPredicate {
                predicate: predicate.to_owned(),
                reason: "segments must match [a-z][a-z0-9_]*",
            }));
        }
        segments += 1;
    }
    if segments < 2 {
        return Err(Error::Claim(ClaimError::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "requires at least 2 dot-joined segments",
        }));
    }

    if !allow_reserved && is_reserved_predicate(predicate) {
        return Err(Error::Claim(ClaimError::ReservedPredicate {
            predicate: predicate.to_owned(),
        }));
    }

    Ok(())
}

/// Returns `true` when `predicate`'s first dot-separated segment is one of the
/// reserved `edge`, `skill` or `actor` namespaces (D17, ARCH-0053 §9). Their
/// writes and lifecycle transitions are owned by dedicated crate-private doors,
/// so the generic Claim API rejects them.
pub fn is_reserved_predicate(predicate: &str) -> bool {
    is_edge_reserved_predicate(predicate) || is_engine_owned_reserved_predicate(predicate)
}

pub fn is_edge_reserved_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(RESERVED_PREDICATE_NAMESPACE)
}

/// The predicates whose lifecycle the ENGINE drives (`skill.*`, `actor.*`,
/// `repo.*`, the projector-only `learning.*`, and exactly `person.substrate`), unlike `edge.*`, whose
/// transitions re-stamp provenance-derived edge state and therefore stay
/// exclusively edge-owned. `repo.*` is the origin's own record of what it
/// published and admitted: a generic door that could write it could stand in
/// for a publication's intent or a push's evidence.
pub fn is_engine_owned_reserved_predicate(predicate: &str) -> bool {
    let namespace = predicate.split('.').next();
    namespace == Some("machine")
        || namespace == Some("world_access")
        || namespace == Some("activated")
        || namespace == Some("esign")
        || namespace == Some(RESERVED_SKILL_PREDICATE_NAMESPACE)
        || namespace == Some(RESERVED_ACTOR_PREDICATE_NAMESPACE)
        || predicate == PREDICATE_PERSON_SUBSTRATE
        || predicate == PREDICATE_VAULT_DEFAULT_FACET
        || namespace == Some("repo")
        || namespace == Some(LEARNING_NAMESPACE)
}

/// Whether `prefix` is a well-formed predicate prefix: one or more grammar
/// segments, each followed by a dot (`host.persona.`), within the predicate
/// byte bound. A host's protected namespace is declared in this shape.
pub fn is_predicate_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREDICATE_BYTES
        && prefix
            .strip_suffix('.')
            .is_some_and(|stem| stem.split('.').all(valid_predicate_segment))
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

pub fn validate_session_tag(session_tag: &str) -> Result<()> {
    if session_tag.trim().is_empty() {
        return Err(Error::InvalidClaimBody(
            "sess must be a non-empty, non-whitespace string",
        ));
    }
    Ok(())
}

/// Pinned companion-expression predicate for the relationship/persona layer.
pub const PREDICATE_COMPANION_EXPRESSION: &str = "companion.expression";
pub const PREDICATE_COMPANION_EXPRESSION_LANGUAGE: &str = "companion.expression.language";
pub const PREDICATE_COMPANION_EXPRESSION_REGISTER: &str = "companion.expression.register";
pub const PREDICATE_COMPANION_EXPRESSION_KEIGO: &str = "companion.expression.keigo";
pub const PREDICATE_COMPANION_EXPRESSION_STYLE: &str = "companion.expression.style";

/// Claim predicate for an unresolved conflict state.
pub const PREDICATE_CONFLICT_OPEN: &str = "core.conflict.open";

/// Claim predicate for a resolved conflict state.
pub const PREDICATE_CONFLICT_RESOLVED: &str = "core.conflict.resolved";

/// Status of a cross-vault coreference link (ONE-1414).
///
/// Subject is the `same_as` EdgeRef itself, never either PERSON: the status is
/// a fact about the LINK, so it cannot be mistaken for a property one endpoint
/// carries and cannot survive the link's absence.
pub const PREDICATE_COREFERENCE_STATUS: &str = "core.coreference.status";

/// Per-pact consent to export a cross-vault coreference link (ONE-1414).
///
/// Consent is scoped to ONE pact by construction — the pact id lives in the
/// value — so a link shared into pact P is not thereby shared into pact Q.
/// Absence of this claim means the link is local-only, which is the default.
pub const PREDICATE_COREFERENCE_SHARE_CONSENT: &str = "core.coreference.share_consent";

/// Namespace prefix shared by every coreference claim predicate.
///
/// The federation export filter excludes the WHOLE namespace by default, so a
/// later `core.coreference.*` predicate is withheld from the moment it exists
/// rather than from the moment someone remembers to list it.
pub const PREDICATE_COREFERENCE_PREFIX: &str = "core.coreference.";

/// `core.coreference.status` value for an asserted, unconfirmed link.
pub const COREFERENCE_STATUS_PROPOSED: &str = "proposed";

/// `core.coreference.status` value for an owner-confirmed link.
pub const COREFERENCE_STATUS_CONFIRMED: &str = "confirmed";

/// The ONE key a `core.coreference.share_consent` value map may carry.
pub const COREFERENCE_SHARE_CONSENT_PACT_KEY: &str = "pact_id";

/// A federation pact id is 32 bytes, carried as 64 LOWERCASE hex characters.
pub const COREFERENCE_PACT_ID_HEX_LEN: usize = 2 * COREFERENCE_PACT_ID_LEN;

/// Byte length of a federation pact id.
pub const COREFERENCE_PACT_ID_LEN: usize = 32;

pub const COMPANION_EXPRESSION_PROFESSIONAL: &str = "professional";
pub const COMPANION_EXPRESSION_WARM: &str = "warm";
pub const COMPANION_EXPRESSION_UNRESTRICTED: &str = "unrestricted";

pub const EXPRESSION_REGISTER_CASUAL: &str = "casual";
pub const EXPRESSION_REGISTER_NEUTRAL: &str = "neutral";
pub const EXPRESSION_REGISTER_FORMAL: &str = "formal";
pub const EXPRESSION_KEIGO_NONE: &str = "none";
pub const EXPRESSION_KEIGO_TEINEIGO: &str = "teineigo";
pub const EXPRESSION_KEIGO_SONKEIGO: &str = "sonkeigo";
pub const EXPRESSION_KEIGO_KENJOGO: &str = "kenjogo";
pub const EXPRESSION_KEIGO_ADAPTIVE: &str = "adaptive";
pub const MAX_EXPRESSION_LANGUAGE_TAG_BYTES: usize = 35;
pub const MAX_EXPRESSION_STYLE_TOKEN_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExpressionPreferenceKind {
    Language,
    Register,
    Keigo,
    Style,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionRegister {
    Casual,
    Neutral,
    Formal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionKeigo {
    None,
    Teineigo,
    Sonkeigo,
    Kenjogo,
    Adaptive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionPreferenceValue {
    Language(String),
    Register(ExpressionRegister),
    Keigo(ExpressionKeigo),
    Style(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionPreferenceOrigin {
    ExplicitUser,
    Inferred,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceChange {
    pub subject: EntityId,
    pub value: ExpressionPreferenceValue,
    pub origin: ExpressionPreferenceOrigin,
    pub valid_from: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressionPreferenceWriteResult {
    pub claim_id: EntityId,
    pub approval: ClaimApprovalStatus,
    pub superseded_claim_ids: Vec<EntityId>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpressionPreferenceSet {
    pub language: Option<String>,
    pub register: Option<ExpressionRegister>,
    pub keigo: Option<ExpressionKeigo>,
    pub style: Option<String>,
    pub winning_claim_ids: std::collections::BTreeMap<ExpressionPreferenceKind, EntityId>,
}

pub fn is_expression_preference_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE
            | PREDICATE_COMPANION_EXPRESSION_REGISTER
            | PREDICATE_COMPANION_EXPRESSION_KEIGO
            | PREDICATE_COMPANION_EXPRESSION_STYLE
    )
}

pub const PREDICATE_PERSON_SUBSTRATE: &str = "person.substrate";

pub const LEARNING_NAMESPACE: &str = "learning";
