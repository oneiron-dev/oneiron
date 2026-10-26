//! The response limits a context-pack response is cut to after its scoped
//! filter, and the stats a cut pack shows.

#[derive(Clone, Copy)]
pub(crate) struct ContextPackResponseLimits {
    pub(crate) results: usize,
    pub(crate) neighbors: usize,
    pub(crate) retrieval: oneiron::ContextPackRetrievalBudget,
}

/// Cuts `pack` to `limits` by the pipeline's share-aware selection, critical
/// rows first in every cut and an `All`-world pack's share held over its
/// results and neighbors (FIX 9759, FIX 9760). The pre-cut critical count
/// stands; a critical row a cut leaves out raises the overflow warning.
pub(crate) fn apply_context_pack_response_limits(
    pack: &mut oneiron::context_pack::UnfinalizedContextPack<'_>,
    limits: ContextPackResponseLimits,
) {
    let cut_critical =
        pack.select_response_rows(limits.retrieval, limits.results, limits.neighbors);
    pack.value.stats.critical_over_budget |= cut_critical;
    scrub_context_pack_visible_stats(&mut pack.value);
}

/// Every empty pack reads alike, whoever reads it: no key reads every row
/// (another principal's claims stay private even to the owner's key), so a
/// reason would tell a match its reader cannot read from no match (F19).
pub(crate) fn scrub_context_pack_visible_stats(pack: &mut oneiron::ContextPack) {
    // How many claims the scope withheld is a count of rows the caller may
    // not read: it never leaves as a stat (F19).
    pack.stats.claims_suppressed = 0;
    // How many candidates the cosine-ghost rule damped counts rows before
    // any read admitted them, so it never leaves either (FIX 646).
    pack.stats.cosine_ghosts_dampened = 0;
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() && pack.l2_base.is_none() {
        // A reader profile's skip is decided before any row is read, so
        // naming it tells nothing about rows.
        if pack
            .empty
            .as_ref()
            .is_some_and(|empty| empty.reason == oneiron::EmptyReason::SkippedByProfile)
        {
            return;
        }
        pack.empty = Some(oneiron::EmptyContext {
            retrieval_quality: pack.retrieval_quality.clone(),
            reason: oneiron::EmptyReason::FilterMatchedNone,
            total_in_scope: 0,
            hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
        });
    } else {
        pack.empty = None;
    }
}
