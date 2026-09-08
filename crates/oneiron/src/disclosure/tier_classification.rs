//! Mode/tier classification and disclosure-claim structural validation.

use heed::RoTxn;
use serde::Serialize;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimBody, ClaimSubject, claim_sensitivity_band, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::interlocutor::InterlocutorSet;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT,
};
use crate::store::Store;

use super::disclosure_tier_a_marked_in;
use super::scope_codec::{MAX_DISCLOSURE_SCOPE_TOPIC_BYTES, decode_disclosure_scope_value};

/// Pinned `disclosure.*` claim predicates.
pub const DISCLOSURE_CLAIM_PREDICATES: [&str; 3] =
    ["disclosure.scope", "disclosure.tier", "disclosure.topic"];

pub const PREDICATE_DISCLOSURE_SCOPE: &str = "disclosure.scope";

pub const PREDICATE_DISCLOSURE_TIER: &str = "disclosure.tier";

pub const PREDICATE_DISCLOSURE_TOPIC: &str = "disclosure.topic";

pub(super) const DISCLOSURE_TIER_VALUE_TIER_A: &str = "tier_a";

/// Entity types that are NEVER disclosure material for third parties:
/// governance / consent / biometric / intimate-profile records — exactly the
/// records that describe OTHER people's consent state (design §7 rule 2).
/// The ILD-3 voice-print type byte joins this list when it lands (ONE-1518).
pub const DISCLOSURE_TIER_A_ENTITY_TYPES: [u8; 10] = [
    ENTITY_TYPE_REDACTION_AUDIT,
    ENTITY_TYPE_AUTHORITY_LOG,
    ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_ACCESS_GRANT,
    ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
];

/// Claim predicate prefixes that classify Tier A regardless of band: affect
/// annotations and the meta-privacy families (scope/tier marks themselves
/// never leak — design §7 rule 4).
pub const DISCLOSURE_TIER_A_PREDICATE_PREFIXES: [&str; 5] = [
    "affect.",
    "disclosure.",
    "counterparty_contact.",
    "channel_identity.",
    "voice_print.",
];

/// The two-mode law's mode axis (design §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisclosureMode {
    OwnerAlone,
    Supervised,
    AbsenceClamp,
}

impl DisclosureMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerAlone => "owner_alone",
            Self::Supervised => "supervised",
            Self::AbsenceClamp => "absence_clamp",
        }
    }

    /// Total mode derivation from the resolved interlocutor set: owner alone
    /// -> `OwnerAlone`; owner plus non-owners -> `Supervised`; no owner entry
    /// -> `AbsenceClamp`. Supervision keys to the session-constructed Owner
    /// entry only (I3).
    #[must_use]
    pub fn from_set(set: &InterlocutorSet) -> Self {
        match (set.supervised(), set.has_non_owner()) {
            (true, false) => Self::OwnerAlone,
            (true, true) => Self::Supervised,
            (false, _) => Self::AbsenceClamp,
        }
    }
}

/// Content tier under the two-tier hiding law (OF-355).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureTier {
    TierA,
    TierB,
}

/// Classifies one entity against the five Tier-A rules IN ORDER (design §7):
/// live off-record overlay membership, governance type byte, sensitivity band (band 2+ or an
/// ambiguous band fails closed), Tier-A predicate prefix, owner mark row. A
/// type-0 record whose body is missing or undecodable is ambiguous and fails
/// closed to Tier A.
pub(crate) fn disclosure_tier(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<DisclosureTier> {
    // Rule 1 — live session-overlay membership. ONE-1731 removed the durable
    // fence half; membership in a live room is the whole rule now.
    if store.off_record_sessions.contains_entity(id)? {
        return Ok(DisclosureTier::TierA);
    }
    // Rule 2 — governance/consent/biometric/intimate-profile type bytes.
    if DISCLOSURE_TIER_A_ENTITY_TYPES.contains(&entity_type) {
        return Ok(DisclosureTier::TierA);
    }
    if entity_type == ENTITY_TYPE_CLAIM {
        let decoded;
        let body = match claim_body {
            Some(body) => Some(body),
            None => {
                decoded = read_stored_claim_body(store, rtxn, id)?;
                decoded.as_ref()
            }
        };
        let Some(body) = body else {
            return Ok(DisclosureTier::TierA);
        };
        // Rule 3 — sensitivity band: ambiguous (duplicate key) or >= 2
        // ("sensitive"/"restricted") fails closed to Tier A. A missing stamp
        // reads band 2 (the ONE-1645 unstamped floor), so a claim with no
        // recorded provenance is never disclosed to a non-owner party; only a
        // positive `"sensitivity": public|0` stamp reaches Tier B here.
        match claim_sensitivity_band(body) {
            None => return Ok(DisclosureTier::TierA),
            Some(band) if band >= 2 => return Ok(DisclosureTier::TierA),
            Some(_) => {}
        }
        // Rule 4 — Tier-A predicate prefixes.
        if DISCLOSURE_TIER_A_PREDICATE_PREFIXES
            .iter()
            .any(|prefix| body.predicate.starts_with(prefix))
        {
            return Ok(DisclosureTier::TierA);
        }
    }
    // Rule 5 — owner-marked-private row.
    if disclosure_tier_a_marked_in(store, rtxn, id)? {
        return Ok(DisclosureTier::TierA);
    }
    Ok(DisclosureTier::TierB)
}

pub(super) fn read_stored_claim_body(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    Ok(raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|payload| decode_claim_body(payload, true).ok()))
}

/// Returns whether `predicate` belongs to the disclosure claim family.
#[must_use]
pub fn is_disclosure_claim_predicate(predicate: &str) -> bool {
    DISCLOSURE_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `disclosure.*` claim body.
pub(crate) fn validate_disclosure_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "disclosure claim subject must be an entity",
        ));
    }
    match body.predicate.as_str() {
        PREDICATE_DISCLOSURE_SCOPE => decode_disclosure_scope_value(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("disclosure.scope value invalid")),
        PREDICATE_DISCLOSURE_TIER => {
            if body.value.as_str() == Some(DISCLOSURE_TIER_VALUE_TIER_A) {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "disclosure.tier value must be tier_a",
                ))
            }
        }
        PREDICATE_DISCLOSURE_TOPIC => {
            let Some(topic) = body.value.as_str() else {
                return Err(Error::InvalidClaimBody(
                    "disclosure.topic value must be a string",
                ));
            };
            if topic.trim().is_empty()
                || topic.trim() != topic
                || topic.len() > MAX_DISCLOSURE_SCOPE_TOPIC_BYTES
            {
                return Err(Error::InvalidClaimBody(
                    "disclosure.topic value must be trimmed, non-empty, and at most 128 bytes",
                ));
            }
            Ok(())
        }
        _ => Err(Error::InvalidClaimBody(
            "unknown disclosure claim predicate",
        )),
    }
}
