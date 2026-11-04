//! CLAIM scope-map values used by write envelopes and stored-body codecs.
use super::*;
use oneiron_contracts::error::{Error, Result};
use rmpv::Value;

pub(crate) const CLAIM_SCOPE_SENSITIVITY_KEY: &str = "sensitivity";
pub const CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY: &str = "federated_original_source";
/// Scope key carrying the GATE-05 evidence-taint class stamped by the
/// promotion writer when a consolidation meet lands at/below `tool_output`
/// (engine-owned scope-map pattern, like `federated_original_source`).
pub const CLAIM_SCOPE_EVIDENCE_TAINT_KEY: &str = "evidence_taint";
pub const CLAIM_SCOPE_DEMOTION_RUNG_KEY: &str = "demotion_rung";
/// Scope key carrying a claim's initial ClaimOf weight. It sits in the
/// candidate's canonical body scope, so a MACHINE birth signs it with the
/// rest of the body (OF-023 B2: a curator revert stands its copy at the
/// target's prior weight).
pub const CLAIM_SCOPE_INITIAL_CLAIM_OF_WEIGHT_KEY: &str = "initial_claim_of_weight";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimDemotionRung {
    Decayed,  // wire = "decayed"
    Weakened, // wire = "weakened"
    Stale,    // wire = "stale"
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClaimDemotionAction {
    Decay { new_claim_of_weight: f32 },
    Weaken { new_confidence: f32 },
    MarkStale,
}

/// The one change a claim successor may make to its predecessor's body.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClaimSuccession {
    /// A lower confidence, stamped with the `weakened` rung.
    Weakening { confidence: f32 },
    /// The same claim under another facet; `stamp` adds its `facet_of` edge.
    Fork {
        facet: oneiron_contracts::entity_id::EntityId,
        stamp: bool,
    },
}

/// One demotion step's result: the rung now carried and the claim that
/// carries it. A weakening supersedes, so `claim` is its successor; decay and
/// the stale mark write in place and return the demoted claim itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimDemotion {
    pub rung: ClaimDemotionRung,
    pub claim: oneiron_contracts::entity_id::EntityId,
}

/// Provenance inheritance floor (ONE-1645, P3/V2): the band an UNSTAMPED
/// claim reads. A claim with no scope map, or a scope map carrying no
/// `sensitivity` key, has no recorded provenance — so it reads "sensitive"
/// (band 2) and every disclosure surface fails closed against it.
///
/// Positive-evidence rule: public is an explicit act. Only a stored
/// `"sensitivity": "public" | 0` stamp reads band 0; absence never reads
/// public. Band 2 (not 3) is deliberate — it holds unstamped claims out of
/// non-owner disclosure (`disclosure_tier` Rule 3 fails closed at >= 2) while
/// leaving them visible to the OWNER in persona compiles
/// (`TIER_A_MIN_SENSITIVITY_BAND` = 3). Private means not-disclosed-to-others,
/// not invisible-to-self.
pub const UNSTAMPED_CLAIM_SENSITIVITY_BAND: u8 = 2;

/// Lookup outcome for ONE recognized key in an engine-owned scope map.
/// `Duplicate` is kept distinct from `Present`: an ambiguous stamp is never
/// silently resolved to one of its values — each reader decides its own
/// fail-closed answer.
pub enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

/// The single duplicate-aware scope-map lookup. Shared with
/// the recognized provenance/taint/sensitivity entries of the opaque map.
pub fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

/// Reads the demotion rung recorded in a claim's scope map. `None` means the
/// claim carries no rung (no scope map, or no rung key); a duplicate or
/// malformed rung is a fail-closed [`Error::InvalidClaimBody`].
pub fn claim_demotion_rung(body: &ClaimBody) -> Result<Option<ClaimDemotionRung>> {
    let Some(scope) = &body.scope else {
        return Ok(None);
    };
    let Value::Map(entries) = scope else {
        return Err(Error::InvalidClaimBody("scope must be a map"));
    };
    let value = match single_map_value(entries, CLAIM_SCOPE_DEMOTION_RUNG_KEY) {
        MapValue::Missing => return Ok(None),
        MapValue::Duplicate => return Err(Error::InvalidClaimBody("duplicate demotion rung")),
        MapValue::Present(value) => value,
    };
    match value.as_str() {
        Some("decayed") => Ok(Some(ClaimDemotionRung::Decayed)),
        Some("weakened") => Ok(Some(ClaimDemotionRung::Weakened)),
        Some("stale") => Ok(Some(ClaimDemotionRung::Stale)),
        _ => Err(Error::InvalidClaimBody("malformed demotion rung")),
    }
}

/// `scope` without its initial ClaimOf weight entry, for a writer that copies
/// an existing claim's scope onto another claim. The weight is the copied
/// claim's own birth fact, so the new claim is born at the default. A map the
/// strip leaves empty is no scope, as if the entry had never been written.
pub fn without_initial_weight(scope: Option<Value>) -> Option<Value> {
    match scope {
        Some(Value::Map(mut entries)) => {
            let before = entries.len();
            entries
                .retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_INITIAL_CLAIM_OF_WEIGHT_KEY));
            (entries.len() == before || !entries.is_empty()).then_some(Value::Map(entries))
        }
        scope => scope,
    }
}

/// Reads a claim's sensitivity band. Two distinct fail-closed shapes:
///
/// * **missing** (no scope map, or no `sensitivity` key) ⇒
///   `Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND)` — the ONE-1645 inheritance
///   floor. Unrecorded provenance reads private at every disclosure surface.
/// * **ambiguous** (duplicate `sensitivity` key) ⇒ `None` — unreadable, not
///   merely unstamped; consumers clamp harder on `None` than on the floor.
pub fn claim_sensitivity_band(body: &ClaimBody) -> Option<u8> {
    let Some(Value::Map(entries)) = &body.scope else {
        return Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND);
    };

    match single_map_value(entries, CLAIM_SCOPE_SENSITIVITY_KEY) {
        MapValue::Missing => Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        MapValue::Present(value) => sensitivity_band_from_value(value),
        MapValue::Duplicate => None,
    }
}

/// Parses a MessagePack number as a finite `f32` in `[0, 1]`. Shared with
/// the provenance module so `conf` and `confidence` validate identically.
pub fn unit_interval_f32(value: &Value) -> Option<f32> {
    let parsed = match value {
        Value::F32(v) => f64::from(*v),
        Value::F64(v) => *v,
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                i as f64
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
        return None;
    }
    Some(parsed as f32)
}

pub fn sensitivity_band_from_value(value: &Value) -> Option<u8> {
    if let Some(raw) = value.as_u64() {
        return u8::try_from(raw).ok();
    }

    match value.as_str()? {
        "public" => Some(0),
        "private" | "internal" => Some(1),
        "sensitive" => Some(2),
        "restricted" => Some(3),
        _ => None,
    }
}
