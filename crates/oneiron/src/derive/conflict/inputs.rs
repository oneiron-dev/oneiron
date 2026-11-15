//! What the conflict stager feeds the marker builder: each member's
//! confidence and normalised hints stamped on its checked candidate, and
//! derive provenance for the marker.

use rmpv::Value;

use super::super::commit::ItemContext;
use crate::ClaimCandidate;

/// The checked `candidate` stamped with the item member's `confidence` and
/// normalised `hints`. `CandidateAssemblyInput.confidence` lands as the
/// fourth argument of `ClaimCandidate::new` and `lexical_hints` via
/// `with_lexical_hints`, so the stamp rebuilds the candidate through those
/// same two inputs and copies every other field (subject, predicate, value,
/// relationship, world, scope) back from the probe body the claim id reads.
/// The rebuilt candidate differs only in confidence and hints, so its facts,
/// and its claim id, are unchanged.
///
/// # Errors
///
/// A candidate whose probe body does not read, and hints the normaliser
/// refuses. The batch shape check already refused the latter, and the set
/// rebuild already probed the former, so neither fires on a checked batch.
pub(super) fn member_candidate(
    candidate: &ClaimCandidate,
    confidence: f32,
    hints: &[String],
) -> crate::error::Result<ClaimCandidate> {
    let probe = crate::dreamer_consolidation::candidate_probe_body(candidate)?;
    let queries: Vec<&str> = hints.iter().map(String::as_str).collect();
    let mut stamped = ClaimCandidate::new(probe.predicate, probe.subject, probe.value, confidence)
        .with_relationships(probe.rel)
        .with_lexical_hints(crate::claim::normalize_lexical_query_hints(&queries)?);
    if let Some(world) = probe.world {
        stamped = stamped.with_world(world);
    }
    if let Some(scope) = probe.scope {
        stamped = stamped.with_scope(scope);
    }
    Ok(stamped)
}

/// The provenance the marker carries: derive's, as every other derive item
/// stamps it (the Claim stager's envelope): the derivation surface, the
/// batch, the item, and the run. No decision memo.
pub(super) fn derive_provenance(context: &ItemContext<'_>, local: &str) -> Vec<(Value, Value)> {
    let mut provenance = vec![
        (
            Value::from("surface"),
            Value::from(super::super::DERIVE_SURFACE),
        ),
        (
            Value::from(super::super::DERIVE_BATCH_KEY),
            Value::from(context.batch.to_hex()),
        ),
        (Value::from("item"), Value::from(local)),
    ];
    if let Some(run) = &context.stamp.run {
        provenance.push((Value::from("run"), Value::from(run.as_str())));
    }
    provenance
}
