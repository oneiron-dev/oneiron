//! Claim source lineage, evidence taint, and stored value projections.

use crate::error::{Error, Result};
use crate::write_envelope::claim_body::*;
use crate::write_envelope::claim_predicate::is_reserved_predicate;
use oneiron_contracts::claim::{ClaimLifecycleStatus, ClaimSource};
use rmpv::Value;

/// The ClaimOf weight a claim is born with: the initial-weight entry in its
/// scope map, else the ClaimOf default. `None` for an edge subject, which has
/// no ClaimOf edge. The candidate materializer and both machine-history fold
/// entry points read this one value, so the stored edge and signed replay
/// agree. An absent entry, or a scope that is not a map, is the default; a
/// duplicate entry, a value that is not a finite weight in 0..1, or an entry
/// on an edge subject is a fail-closed [`Error::InvalidClaimBody`].
pub(crate) fn claim_initial_claim_of_weight(body: &ClaimBody) -> Result<Option<f32>> {
    let entry = match &body.scope {
        Some(Value::Map(entries)) => {
            match single_map_value(entries, CLAIM_SCOPE_INITIAL_CLAIM_OF_WEIGHT_KEY) {
                MapValue::Missing => None,
                MapValue::Duplicate => {
                    return Err(Error::InvalidClaimBody("duplicate initial ClaimOf weight"));
                }
                MapValue::Present(value) => Some(
                    unit_interval_f32(value)
                        .ok_or(Error::InvalidClaimBody("malformed initial ClaimOf weight"))?,
                ),
            }
        }
        _ => None,
    };
    match (body.subject, entry) {
        (ClaimSubject::Entity(_), weight) => Ok(Some(
            weight.unwrap_or(crate::vault::CLAIM_OF_DEFAULT_WEIGHT),
        )),
        (ClaimSubject::Edge { .. }, None) => Ok(None),
        (ClaimSubject::Edge { .. }, Some(_)) => Err(Error::InvalidClaimBody(
            "initial ClaimOf weight requires an entity subject",
        )),
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
pub(crate) const fn evidence_taint_blocks_consolidation(taint: ClaimSource) -> bool {
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

/// The text a surfaced claim indexes under `val`: its value's string, or the
/// value's MessagePack display for any other kind. The claim commit and the
/// indexed-revision idle pass both index this, so a republish keeps the
/// claim's postings (FIX 12368).
pub(crate) fn claim_value_index_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}
