//! Structural validators for the predicates this module owns itself, rather
//! than delegating to a domain module: expression preference, companion
//! expression, coreference, conflict, and the `edge.provenance` wrapper.
//!
//! Every function here is reached from the dispatcher in `core_types.rs`.

use rmpv::Value;

use super::*;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

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
const COREFERENCE_PACT_ID_HEX_LEN: usize = 2 * COREFERENCE_PACT_ID_LEN;

/// Byte length of a federation pact id.
pub(crate) const COREFERENCE_PACT_ID_LEN: usize = 32;

pub(crate) const COMPANION_EXPRESSION_PROFESSIONAL: &str = "professional";
pub(crate) const COMPANION_EXPRESSION_WARM: &str = "warm";
pub(crate) const COMPANION_EXPRESSION_UNRESTRICTED: &str = "unrestricted";

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

fn valid_expression_language(value: &str) -> bool {
    if !(2..=MAX_EXPRESSION_LANGUAGE_TAG_BYTES).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let parts: Vec<&str> = value.split('-').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p.len() > 8 || !p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return false;
    }
    if parts[0].len() < 2 || parts[0].len() > 8 || !parts[0].bytes().all(|b| b.is_ascii_lowercase())
    {
        return false;
    }
    for (i, part) in parts.iter().enumerate().skip(1) {
        let region = part.len() == 2 && part.bytes().all(|b| b.is_ascii_alphabetic());
        if region {
            if !part.bytes().all(|b| b.is_ascii_uppercase()) {
                return false;
            }
        } else if part.len() == 4
            && part.as_bytes()[0].is_ascii_uppercase()
            && part.as_bytes()[1..].iter().all(u8::is_ascii_lowercase)
        {
            // Canonical script subtags are title-cased, e.g. `zh-Hant`.
        } else if !part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
        let _ = i;
    }
    true
}
fn valid_expression_style(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXPRESSION_STYLE_TOKEN_BYTES
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
pub fn validate_expression_preference_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "expression preference subject must be an entity",
        ));
    }
    let value = body.value.as_str().ok_or(Error::InvalidClaimBody(
        "expression preference value must be a string",
    ))?;
    let valid = match body.predicate.as_str() {
        PREDICATE_COMPANION_EXPRESSION_LANGUAGE => valid_expression_language(value),
        PREDICATE_COMPANION_EXPRESSION_REGISTER => matches!(
            value,
            EXPRESSION_REGISTER_CASUAL | EXPRESSION_REGISTER_NEUTRAL | EXPRESSION_REGISTER_FORMAL
        ),
        PREDICATE_COMPANION_EXPRESSION_KEIGO => matches!(
            value,
            EXPRESSION_KEIGO_NONE
                | EXPRESSION_KEIGO_TEINEIGO
                | EXPRESSION_KEIGO_SONKEIGO
                | EXPRESSION_KEIGO_KENJOGO
                | EXPRESSION_KEIGO_ADAPTIVE
        ),
        PREDICATE_COMPANION_EXPRESSION_STYLE => valid_expression_style(value),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(
            "invalid expression preference value",
        ))
    }
}

pub(super) fn validate_companion_expression_claim_structure(body: &ClaimBody) -> Result<()> {
    let Some(expression) = body.value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "companion.expression value must be a string",
        ));
    };
    match expression {
        COMPANION_EXPRESSION_PROFESSIONAL
        | COMPANION_EXPRESSION_WARM
        | COMPANION_EXPRESSION_UNRESTRICTED => Ok(()),
        _ => Err(Error::InvalidClaimBody(
            "expression must be professional|warm|unrestricted",
        )),
    }
}

/// The subject shape both `core.coreference.*` validators require: an EdgeRef
/// naming a `same_as` edge, and nothing else.
///
/// The kind check is EXACT (byte 20 only), not "some structural kind". A
/// coreference status or consent claim hung off a `belongs_to` or `merged_into`
/// EdgeRef would be a statement about a relation these predicates do not
/// govern, and the export filter reads consent BY LINK — so admitting a
/// foreign-kind subject would let a claim vouch for a link it never described.
/// An entity subject fails for the same reason: status is a fact about the
/// LINK, so it must not be able to outlive it or attach to one endpoint.
fn require_coreference_link_subject(body: &ClaimBody) -> Result<()> {
    match body.subject {
        ClaimSubject::Edge {
            kind: EdgeKind::SameAs,
            ..
        } => Ok(()),
        _ => Err(Error::InvalidClaimBody(
            "coreference claim subject must be a same_as EdgeRef",
        )),
    }
}

/// ONE-1414 — `core.coreference.status`.
///
/// Value is the string `proposed` or `confirmed`, and the approval axis is
/// pinned to it: `confirmed` asserts identity as settled truth and therefore
/// requires an owner `Approved`, while `proposed` is an unsettled assertion and
/// admits only `Auto` or `Proposed`. The two rules are one gate — a `confirmed`
/// row carrying `Auto` would be an unreviewed identity merge wearing a
/// reviewed label.
pub(super) fn validate_coreference_status_claim_structure(body: &ClaimBody) -> Result<()> {
    require_coreference_link_subject(body)?;
    let Some(status) = body.value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.status value must be a string",
        ));
    };
    let approval_fits = match status {
        COREFERENCE_STATUS_CONFIRMED => body.approval == ClaimApprovalStatus::Approved,
        COREFERENCE_STATUS_PROPOSED => matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ),
        _ => {
            return Err(Error::InvalidClaimBody(
                "core.coreference.status value must be proposed|confirmed",
            ));
        }
    };
    if !approval_fits {
        return Err(Error::InvalidClaimBody(
            "confirmed coreference requires approved; proposed requires auto|proposed",
        ));
    }
    Ok(())
}

/// ONE-1414 — `core.coreference.share_consent`.
///
/// Sharing an identity link across a federation boundary is an owner decision,
/// so `Approved` is the only admissible approval; there is no `Auto` path that
/// could let an agent widen disclosure.
pub(super) fn validate_coreference_share_consent_claim_structure(body: &ClaimBody) -> Result<()> {
    require_coreference_link_subject(body)?;
    coreference_share_consent_pact_id(body)?;
    if body.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent requires approved",
        ));
    }
    Ok(())
}

/// The pact id a `core.coreference.share_consent` claim names.
///
/// The value vocabulary is EXACTLY one key. A second key — even an inert one —
/// is rejected rather than ignored: this claim is read by the export filter to
/// decide what crosses a grant, and a map with room for unread keys is a place
/// to hide a second, unhonored scope.
pub(crate) fn coreference_share_consent_pact_id(
    body: &ClaimBody,
) -> Result<[u8; COREFERENCE_PACT_ID_LEN]> {
    let Value::Map(entries) = &body.value else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent value must be a map",
        ));
    };
    let [(key, value)] = entries.as_slice() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent value must carry exactly one key",
        ));
    };
    if key.as_str() != Some(COREFERENCE_SHARE_CONSENT_PACT_KEY) {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent key must be pact_id",
        ));
    }
    let Some(hex) = value.as_str() else {
        return Err(Error::InvalidClaimBody(
            "core.coreference.share_consent pact_id must be a string",
        ));
    };
    decode_coreference_pact_id(hex)
}

/// Decodes a 64-character LOWERCASE hex pact id.
///
/// Lowercase-only is a canonicity rule, not fussiness: the selector compares
/// the claim's pact against the export pact, and admitting both cases would
/// give one pact two spellings — hence two consent claims that a
/// string-equality reader could disagree about. Odd length, uppercase, and
/// non-hex bytes all fail here.
fn decode_coreference_pact_id(hex: &str) -> Result<[u8; COREFERENCE_PACT_ID_LEN]> {
    let malformed =
        || Error::InvalidClaimBody("coreference pact_id must be 64 lowercase hex chars");
    if hex.len() != COREFERENCE_PACT_ID_HEX_LEN {
        return Err(malformed());
    }
    let (chunks, rem) = hex.as_bytes().as_chunks::<2>();
    debug_assert!(rem.is_empty());
    let mut bytes = [0_u8; COREFERENCE_PACT_ID_LEN];
    for (slot, &[hi, lo]) in bytes.iter_mut().zip(chunks) {
        let (Some(hi), Some(lo)) = (lowercase_hex_nibble(hi), lowercase_hex_nibble(lo)) else {
            return Err(malformed());
        };
        *slot = (hi << 4) | lo;
    }
    Ok(bytes)
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn validate_conflict_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "conflict claim subject must be an entity",
        ));
    }
    if matches!(body.value, Value::Nil) {
        return Err(Error::InvalidClaimBody(
            "conflict claim value must not be nil",
        ));
    }
    if conflict_value_uses_repo_schema(&body.value) {
        crate::repo_mutation::validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    }
    Ok(())
}

fn conflict_value_uses_repo_schema(value: &Value) -> bool {
    let Value::Map(entries) = value else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        matches!(
            key.as_str(),
            Some(
                "schema_version"
                    | "kind"
                    | "repo_ref"
                    | "branch"
                    | "base_tree"
                    | "ours_tree"
                    | "theirs_tree"
                    | "conflicted_paths"
                    | "open_conflict_claim_id"
                    | "resolved_tree"
                    | "resolved_paths"
            )
        ) || value.as_str() == Some("repo_branch")
    })
}

/// ONE-1159 — full structural validation of an `edge.provenance` Claim at
/// the WRITE door.
///
/// D18 treats `val` as opaque MessagePack and `evid` as an opaque payload,
/// so the replicated door admitted D18-valid but STRUCTURALLY invalid
/// provenance Claims (junk `val`, non-record `val` maps, missing
/// actor-class evidence); later provenance ops then failed closed only at
/// read/supersede time. Sync replay is a WRITE PATH — the same fail-closed
/// checks run behind the trusted door:
///
/// * `val` must decode as the pinned `edge.provenance` value record via the
///   SHARED validator [`crate::provenance::validate_edge_provenance_value`]
///   — the pinned key vocabulary lives in exactly one place, so vocabulary
///   growth flows through here with zero edits;
/// * the write-time validated `actor_class` must be persisted in EXACTLY
///   one place: as an `actor_class` key in the value record (accepted only
///   once the shared vocabulary carries that key) or as the engine-owned
///   `{"actor_class": u8}` map on the wrapper's `evid`
///   ([`crate::provenance::decode_actor_class_evidence`]). Present in both
///   → ambiguous, rejected; present in neither → rejected. A provenance
///   Claim without a persisted class can never participate in flag refresh,
///   and the class is never defaulted (D13).
///
/// ONE-1159 fix-wave adds two WRAPPER-axis checks the door previously
/// skipped (D18 treats the wrapper's lifecycle fields as opaque):
///
/// * surfaceability — `appr ∈ {auto, approved}` (the exact set from
///   [`claim_surfaceable`]) and `stale = false`, so a non-surfaceable Claim
///   cannot enter at the write door and silently steer edge flags. Lifecycle
///   is NOT gated (`superseded` / `retracted` are legitimate provenance
///   states the live_/retracted_ scans read);
/// * wrapper↔value-record mirror — `conf == confidence`, `from == valid_from`,
///   `to == valid_to`, so the precedence/display wrapper can never lie about
///   the value record the writer mirrored it from.
///
/// Typed rejections only (the [`Error::InvalidProvenanceBody`] family) — at
/// the sync replay door the caller quarantines them (`x:` row, hash-only
/// per ONE-1124), never drops.
pub(super) fn validate_edge_provenance_claim_structure(body: &ClaimBody) -> Result<()> {
    // ONE-1159 fix-wave (BLOCKER #2) — decode the value record ONCE via the
    // SHARED decoder so the typed record is held for the wrapper↔value-record
    // mirror checks below. This is exactly what
    // [`crate::provenance::validate_edge_provenance_value`] runs (it is the
    // same call with the record discarded), so the value-record structural
    // rules are unchanged and vocabulary growth (ONE-1138's 10-key shape)
    // flows through this one call with zero edits.
    let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
    // Presence-only probe for the value-record `actor_class` key: VALIDITY
    // of the key's value is the shared decoder's responsibility above (and a body
    // key outside the pinned vocabulary was already rejected there), so
    // this never duplicates shape logic.
    let value_has_actor_class = matches!(
        &body.value,
        Value::Map(entries) if entries.iter().any(|(key, _)| {
            key.as_str() == Some(crate::provenance::EVIDENCE_KEY_ACTOR_CLASS)
        })
    );
    match (value_has_actor_class, body.evidence.as_ref()) {
        (true, Some(_)) => {
            return Err(Error::InvalidProvenanceBody(
                "actor_class present in both the value record and the wrapper evid (ambiguous)",
            ));
        }
        (true, None) => {}
        (false, evidence) => {
            crate::provenance::decode_actor_class_evidence(evidence)?;
        }
    }

    // ONE-1159 fix-wave (BLOCKER #1) — surfaceability-axis guard on the
    // WRAPPER. A provenance Claim only drives edge-flag refresh while it is
    // surfaceable on the read gate; admitting a non-surfaceable wrapper at the
    // replay door would let an `appr=rejected` / `stale=true` Claim silently
    // steer flags. Reuse the EXACT approval set from [`claim_surfaceable`] so
    // the door and the read gate cite one approval rule. Lifecycle is
    // DELIBERATELY not gated here — `superseded` / `retracted` are legitimate
    // provenance lifecycle states the live_/retracted_ scans must read.
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper appr must be auto|approved",
        ));
    }
    if body.stale {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper must not be stale",
        ));
    }

    // ONE-1159 fix-wave (BLOCKER #2) — the wrapper's `conf`/`from`/`to` MUST
    // mirror the value record's `confidence`/`valid_from`/`valid_to`. The
    // local writer guarantees this by construction, and precedence/display
    // read the wrapper, so a mismatched wrapper is a structural lie. `conf`
    // and `confidence` are both required and parsed through the same
    // `unit_interval_f32`/`Value::F32` path, so `==` is the exact VALUE
    // equality the contract pins; `from`/`to` are optional on both sides and
    // compared as `Option` equality (both-present-equal or both-absent).
    if record.confidence != body.confidence {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper conf does not mirror value-record confidence",
        ));
    }
    if record.valid_from != body.valid_from {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper from does not mirror value-record valid_from",
        ));
    }
    if record.valid_to != body.valid_to {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper to does not mirror value-record valid_to",
        ));
    }

    Ok(())
}
