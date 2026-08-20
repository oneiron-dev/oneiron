//! Source-of-truth, taint, sensitivity and demotion state carried in a claim's
//! engine-owned `scope` map, plus the read-admission predicates
//! (`claim_surfaceable` / `claim_consolidatable` / `claim_evidence_admissible`)
//! that consume them.

use rmpv::Value;

use super::*;
use crate::error::{Error, Result};

const CLAIM_SCOPE_SENSITIVITY_KEY: &str = "sensitivity";
pub(super) const CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY: &str = "federated_original_source";
/// Scope key carrying the GATE-05 evidence-taint class stamped by the
/// promotion writer when a consolidation meet lands at/below `tool_output`
/// (engine-owned scope-map pattern, like `federated_original_source`).
pub(crate) const CLAIM_SCOPE_EVIDENCE_TAINT_KEY: &str = "evidence_taint";
pub(crate) const CLAIM_SCOPE_DEMOTION_RUNG_KEY: &str = "demotion_rung";

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

#[cfg(feature = "sync")]
const CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY: &str = "pre_restamp_scope";
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
pub(crate) const UNSTAMPED_CLAIM_SENSITIVITY_BAND: u8 = 2;

enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
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
pub(crate) fn claim_demotion_rung(body: &ClaimBody) -> Result<Option<ClaimDemotionRung>> {
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

/// Reads a claim's sensitivity band. Two distinct fail-closed shapes:
///
/// * **missing** (no scope map, or no `sensitivity` key) ⇒
///   `Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND)` — the ONE-1645 inheritance
///   floor. Unrecorded provenance reads private at every disclosure surface.
/// * **ambiguous** (duplicate `sensitivity` key) ⇒ `None` — unreadable, not
///   merely unstamped; consumers clamp harder on `None` than on the floor.
pub(crate) fn claim_sensitivity_band(body: &ClaimBody) -> Option<u8> {
    let Some(Value::Map(entries)) = &body.scope else {
        return Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND);
    };

    match single_map_value(entries, CLAIM_SCOPE_SENSITIVITY_KEY) {
        MapValue::Missing => Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        MapValue::Present(value) => sensitivity_band_from_value(value),
        MapValue::Duplicate => None,
    }
}

fn claim_federated_original_source(body: &ClaimBody) -> Option<ClaimSource> {
    let Some(Value::Map(entries)) = &body.scope else {
        return None;
    };

    match single_map_value(entries, CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY) {
        MapValue::Missing => None,
        MapValue::Present(value) => value.as_str().and_then(ClaimSource::parse),
        // A duplicated internal origin marker is ambiguous; read admission
        // treats it as generated-origin so authority consumers fail closed.
        MapValue::Duplicate => Some(ClaimSource::Generated),
    }
}

/// GATE-05 evidence-taint reader (ONE-1385): the trust-lattice meet class
/// recorded on a derived claim whose evidence passed through external
/// sources. A duplicated or unparseable taint marker is ambiguous; read
/// admission treats it as maximally tainted (`Imported`, the lattice
/// bottom) so authority consumers fail closed.
pub(crate) fn claim_evidence_taint(body: &ClaimBody) -> Option<ClaimSource> {
    let Some(Value::Map(entries)) = &body.scope else {
        return None;
    };

    match single_map_value(entries, CLAIM_SCOPE_EVIDENCE_TAINT_KEY) {
        MapValue::Missing => None,
        MapValue::Present(value) => Some(
            value
                .as_str()
                .and_then(ClaimSource::parse)
                .unwrap_or(ClaimSource::Imported),
        ),
        MapValue::Duplicate => Some(ClaimSource::Imported),
    }
}

/// A taint meet at/below `tool_output` in the D10 lattice blocks
/// consolidation until a human re-stamp (`Approved`) clears admission.
const fn evidence_taint_blocks_consolidation(taint: ClaimSource) -> bool {
    matches!(taint, ClaimSource::ToolOutput | ClaimSource::Imported)
}

/// D10 trust-lattice rank, high → low:
/// `UserStated > Observed > Inferred = Generated > ToolOutput > Imported`.
/// The single numeric statement of the order
/// [`crate::dreamer_consolidation::source_meet`] folds over — the lineage
/// guard compares ranks so `Inferred` and `Generated` remain one class.
#[must_use]
const fn claim_source_rank(source: ClaimSource) -> u8 {
    match source {
        ClaimSource::Imported => 0,
        ClaimSource::ToolOutput => 1,
        ClaimSource::Inferred | ClaimSource::Generated => 2,
        ClaimSource::Observed => 3,
        ClaimSource::UserStated => 4,
    }
}

/// True when `source` claims MORE trust than the evidence it was derived
/// from (ARCH-0067 §7: "re-stamping tool-output lineage as first-person
/// generated must be impossible"). Every upward move is a widening, not just
/// the `ToolOutput → Generated` one, so no alternate laundering label
/// (`Inferred`, `Observed`, `UserStated`) is left standing.
#[must_use]
pub(crate) const fn claim_source_widens_beyond(
    source: ClaimSource,
    evidence_meet: ClaimSource,
) -> bool {
    claim_source_rank(source) > claim_source_rank(evidence_meet)
}

/// Lineage-forgery guard (ONE-1710, ARCH-0067 §7), run from the write-only
/// chokepoint [`validate_claim_body_and_decode`] so every exposed write door
/// — `Vault::put_claim`, both batch builders, the reserved door, sync replay
/// and the provenance lifecycle rewrites — is covered by construction.
///
/// The invariant is lattice-wide: a stored `src` may never be more trusted
/// than the engine-owned `scope.evidence_taint` meet stamped beside it.
///
/// Two deliberate exits keep it a forgery guard rather than a new schema
/// rule:
///
/// * **Engine-reserved predicates** (`edge.*`, `skill.*`, `actor.*`) are
///   exempt. Those namespaces are unreachable from the generic public Claim
///   API — only crate-private engine doors author them — and they use the
///   two axes independently by design: `actor_claims` records WHO observed a
///   fact (`src = observed`) beside the trust class of the evidence chain it
///   observed (`evidence_taint = tool_output`, ONE-1314), which the
///   consolidation gate reads. Rejecting that shape would break both the
///   attribution projector and sync convergence for already-replicated rows,
///   without closing any agent-reachable path. The exemption is keyed on the
///   PREDICATE, never on `allow_reserved_predicate`: a caller that reaches a
///   reserved-door flag still gets the same predicate-derived answer.
/// * **Sourceless bodies** (legacy rows, sync replay of pre-`src` claims)
///   cannot widen anything, so they pass untouched — preserving convergence.
///
/// [`claim_evidence_taint`] already fails closed (malformed/duplicate taint
/// decodes as `Imported`, the lattice bottom), so a forger cannot escape by
/// corrupting the stamp: it lands at the most restrictive class instead.
pub(crate) fn validate_claim_source_lineage(body: &ClaimBody) -> Result<()> {
    if is_reserved_predicate(&body.predicate) {
        return Ok(());
    }
    let (Some(source), Some(evidence_meet)) = (body.source, claim_evidence_taint(body)) else {
        return Ok(());
    };
    if claim_source_widens_beyond(source, evidence_meet) {
        return Err(Error::InvalidClaimBody(
            "claim source widens beyond evidence lineage",
        ));
    }
    Ok(())
}

pub(crate) fn claim_generated_origin(body: &ClaimBody) -> bool {
    body.source == Some(ClaimSource::Generated)
        || claim_federated_original_source(body) == Some(ClaimSource::Generated)
}

pub(crate) fn sensitivity_band_from_value(value: &Value) -> Option<u8> {
    if let Some(raw) = value.as_u64() {
        return u8::try_from(raw).ok();
    }

    match value.as_str()? {
        "public" => Some(0),
        "internal" => Some(1),
        "sensitive" => Some(2),
        "restricted" => Some(3),
        _ => None,
    }
}

/// D19 read-path status gate predicate (ARCH-0003 retrieval rule; ARCH-0004
/// §H "Claim filtering — enumerated requirements" items 1, 2, 4): a Claim
/// may surface on the retrieval read paths (pipeline results across all five
/// channels, context-pack results, and context-pack neighbors) only when
///
/// * `appr ∈ {auto, approved}` — respect consent;
/// * `life = active` — only current beliefs;
/// * `stale = false` — only regenerated content (absent on disk means
///   `false`, [`decode_claim_body`]; absence alone never excludes).
///
/// The gate is an EXCLUSION, not an error: failing claims are silently
/// dropped and counted (`PackStats::claims_suppressed`). Targeted reads stay
/// deliberately UNGATED: [`crate::Vault::get_claim`] is the history /
/// consent-review door and the edge-provenance lifecycle readers must see
/// closed (`superseded` / `retracted`) Claims to compute winner stamps.
/// World/facet filtering (§H item 3) is a separate unit, and
/// deleted-revision contamination (§H item 5) is the M4/M5 sweep scope.
pub(crate) fn claim_surfaceable(body: &ClaimBody) -> bool {
    matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale
}

/// Read-admission predicate for authority-consuming consolidation paths.
///
/// This is intentionally stricter than [`claim_surfaceable`]: first-party or
/// replicated `Auto` claims stamped `src = generated` may surface immediately
/// on retrieval/review read paths, but authority-consuming paths must call this
/// predicate at their consolidation/corroboration/effector admission boundary
/// and decline them until they are vetted into `appr = approved`. Federated
/// claims restamped to `src = imported` preserve a generated pre-restamp source
/// in `scope.federated_original_source` for this read-admission check. Existing
/// retrieval and context-pack surfacing paths intentionally remain on
/// [`claim_surfaceable`]. This is a read gate only; replication and replay
/// paths must not re-run policy source-trust checks.
pub(crate) fn claim_consolidatable(body: &ClaimBody) -> bool {
    claim_surfaceable(body)
        && !(body.approval == ClaimApprovalStatus::Auto && claim_generated_origin(body))
        && !(claim_evidence_taint(body).is_some_and(evidence_taint_blocks_consolidation)
            && body.approval != ClaimApprovalStatus::Approved)
}

/// GATE-11: a generated-origin claim may never serve as extraction evidence
/// or corroboration for another first-party write — generated output must
/// never corroborate itself into higher trust. Reads declared source AND
/// the federated pre-restamp origin, like [`claim_consolidatable`].
///
/// Unlike consolidatability, approval status does NOT clear evidence
/// admissibility: an `Approved` Generated claim is merge-eligible but still
/// contributes ZERO corroboration. Consumption contract: the promotion
/// writer (ONE-1290) drops any `evidence_turn_refs` entry resolving to a
/// CLAIM entity that fails this predicate, and the consolidation working
/// set (ONE-1289) is TURN-only — claims never enter it.
#[cfg_attr(not(test), allow(dead_code))] // consumed by ONE-1289/ONE-1290
pub(crate) fn claim_evidence_admissible(body: &ClaimBody) -> bool {
    !claim_generated_origin(body)
}

pub(crate) fn psych_mirror_claim_affect_salience(body: &ClaimBody) -> Result<f32> {
    let salience = body.salience.unwrap_or(0.0);
    let affect = crate::affect::decode_affect_trigger_claim(body)?.map_or(0.0, |trigger| {
        let delta = trigger.vad_delta();
        let valence = (delta.valence().abs() / 2.0).clamp(0.0, 1.0);
        let arousal = delta.arousal().abs().clamp(0.0, 1.0);
        let dominance = delta.dominance().abs().clamp(0.0, 1.0);
        ((valence + arousal + dominance) / 3.0) * trigger.confidence()
    });
    Ok(salience.max(affect).clamp(0.0, 1.0))
}

#[cfg(feature = "sync")]
pub(crate) fn restamp_federated_claim_source(mut body: ClaimBody) -> ClaimBody {
    if body.source == Some(ClaimSource::Generated) {
        body.scope = Some(match body.scope.take() {
            Some(Value::Map(mut entries)) => {
                entries.retain(|(key, _)| {
                    key.as_str() != Some(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY)
                });
                entries.push((
                    Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                    Value::from(ClaimSource::Generated.as_str()),
                ));
                Value::Map(entries)
            }
            Some(scope) => Value::Map(vec![
                (
                    Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                    Value::from(ClaimSource::Generated.as_str()),
                ),
                (Value::from(CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY), scope),
            ]),
            None => Value::Map(vec![(
                Value::from(CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
                Value::from(ClaimSource::Generated.as_str()),
            )]),
        });
    }
    body.source = Some(ClaimSource::Imported);
    body
}

/// Parses a MessagePack number as a finite `f32` in `[0, 1]`. Shared with
/// the provenance module so `conf` and `confidence` validate identically.
pub(crate) fn unit_interval_f32(value: &Value) -> Option<f32> {
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
