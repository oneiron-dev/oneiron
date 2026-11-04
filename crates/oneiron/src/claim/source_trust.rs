//! Source-of-truth, taint, sensitivity and demotion state carried in a claim's
//! engine-owned `scope` map, plus the read-admission predicates
//! (`claim_surfaceable` / `claim_consolidatable` / `claim_evidence_admissible`)
//! that consume them.

use rmpv::Value;

use super::*;
use crate::error::{Error, Result};

pub(crate) use crate::write_envelope::claim_body::*;
pub use crate::write_envelope::claim_body::{
    ClaimDemotion, ClaimDemotionAction, ClaimDemotionRung,
};

#[cfg(feature = "sync")]
const CLAIM_SCOPE_PRE_RESTAMP_SCOPE_KEY: &str = "pre_restamp_scope";
pub(crate) use crate::store::claim_lineage::{
    claim_initial_claim_of_weight, claim_evidence_taint, claim_source_widens_beyond, validate_claim_source_lineage, claim_generated_origin, claim_value_index_text,
};
use crate::store::claim_lineage::evidence_taint_blocks_consolidation;

/// Exact-store claims have their own actor/class-bound reader. Even the owner
/// must use that reader, not generic retrieval, hydration, or history projection.
/// This is not a raw storage ACL: `Vault::get_claim` and batch APIs are unchanged.
pub(crate) const KEY_VALUE_PREDICATE: &str = "core.memory.key_value";

pub(crate) fn claim_generic_readable(body: &ClaimBody) -> bool {
    body.predicate != KEY_VALUE_PREDICATE
        && super::history_store::machine_history_kind(&body.predicate).is_none()
}

/// D19 read-path status gate predicate (ARCH-0003 retrieval rule; ARCH-0004
/// §H "Claim filtering — enumerated requirements" items 1, 2, 4): a Claim
/// may surface on the retrieval read paths (pipeline results across all five
/// channels, context-pack results, and context-pack neighbors) only when
///
/// * not actor-owned exact-store data — read only through the keyed API;
/// * `appr ∈ {auto, approved}` — respect consent;
/// * `life = active` — only current beliefs;
/// * `stale = false` — only regenerated content (absent on disk means
///   `false`, [`crate::claim::decode_claim_body`]; absence alone never excludes).
///
/// The gate is an EXCLUSION, not an error: failing claims are silently
/// dropped and counted (`PackStats::claims_suppressed`). Targeted reads stay
/// deliberately UNGATED: [`crate::Vault::get_claim`] is the history /
/// consent-review door and the edge-provenance lifecycle readers must see
/// closed (`superseded` / `retracted`) Claims to compute winner stamps.
/// World/facet filtering (§H item 3) is a separate unit, and
/// deleted-revision contamination (§H item 5) is the M4/M5 sweep scope.
pub(crate) fn claim_surfaceable(body: &ClaimBody) -> bool {
    claim_generic_readable(body)
        && matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
        && body.lifecycle == ClaimLifecycleStatus::Active
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

/// Provisional standing (Engine ruling 2026-10-12): a first-party generated
/// `Auto` claim a later correction may close. [`claim_consolidatable`]
/// declines it for its generated origin alone; every other reason that
/// predicate declines a claim declines it here too:
///
/// * not surfaceable (exact-store data, neither `Auto` nor `Approved`, closed,
///   or stale);
/// * a blocking evidence taint (`tool_output`, `imported`, or a malformed
///   stamp, which reads as `imported`): an `Auto` claim never takes the
///   `Approved` exit;
/// * a generated origin that arrived by federation: any
///   `federated_original_source` marker, readable or not, keeps the head on
///   the existing path (a restamped row is `src = imported` besides).
///
/// GATE-11 holds because closing the head is all this permits. A correction
/// replaces it through the deferred grant door, which judges the replacement
/// on its own evidence, and a closed head only loses standing. Nothing
/// attaches to it, it never corroborates, and it is never extraction evidence
/// ([`claim_evidence_admissible`] still refuses it), so no claim gains trust
/// from it. Approved generated heads and consolidatable heads keep their path:
/// the two predicates never both hold.
pub(crate) fn claim_correctable_generated(body: &ClaimBody) -> bool {
    body.approval == ClaimApprovalStatus::Auto
        && body.source == Some(ClaimSource::Generated)
        && !claim_has_federated_origin_marker(body)
        && claim_surfaceable(body)
        && !claim_evidence_taint(body).is_some_and(evidence_taint_blocks_consolidation)
}

/// Whether the scope map carries a federated origin marker at all, however
/// it reads.
fn claim_has_federated_origin_marker(body: &ClaimBody) -> bool {
    let Some(Value::Map(entries)) = &body.scope else {
        return false;
    };
    !matches!(
        single_map_value(entries, CLAIM_SCOPE_FEDERATED_ORIGINAL_SOURCE_KEY),
        MapValue::Missing
    )
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
    let affect = crate::write_envelope::affect_trigger::decode_affect_trigger_claim(body)?.map_or(
        0.0,
        |trigger| {
            let delta = trigger.vad_delta();
            let valence = (delta.valence().abs() / 2.0).clamp(0.0, 1.0);
            let arousal = delta.arousal().abs().clamp(0.0, 1.0);
            let dominance = delta.dominance().abs().clamp(0.0, 1.0);
            ((valence + arousal + dominance) / 3.0) * trigger.confidence()
        },
    );
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
