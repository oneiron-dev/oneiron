//! The response limits a context-pack response is cut to after its scoped
//! filter, and the stats a cut pack shows.

#[derive(Clone, Copy)]
pub(crate) struct ContextPackResponseLimits {
    pub(crate) results: usize,
    pub(crate) neighbors: usize,
    pub(crate) retrieval: oneiron::ContextPackRetrievalBudget,
}

/// Cuts `pack` to `limits`, critical rows first in every cut (FIX 9760). The
/// pre-cut critical count stands; a critical row a cut leaves out raises the
/// overflow warning.
pub(crate) fn apply_context_pack_response_limits(
    pack: &mut oneiron::ContextPack,
    limits: ContextPackResponseLimits,
) {
    apply_context_pack_response_retrieval_budget(pack, limits.retrieval);
    let results_cut = truncate_critical_first(&mut pack.results, limits.results);
    let neighbors_cut = truncate_critical_first(&mut pack.neighbors, limits.neighbors);
    pack.stats.critical_over_budget |= results_cut || neighbors_cut;
    scrub_context_pack_visible_stats(pack);
}

/// Cuts `rows` to `limit`, critical rows first; the kept rows keep their
/// order. Returns whether a critical row was cut.
fn truncate_critical_first(
    rows: &mut Vec<oneiron::context_pack::ContextEntity>,
    limit: usize,
) -> bool {
    let mut taken = 0_usize;
    let cut = oneiron::context_pack::select_critical_pack_rows(
        rows,
        |row| row.critical,
        |_| {
            let fits = taken < limit;
            taken += usize::from(fits);
            fits
        },
    );
    !cut.is_empty()
}

pub(crate) fn apply_context_pack_response_retrieval_budget(
    pack: &mut oneiron::ContextPack,
    budget: oneiron::ContextPackRetrievalBudget,
) {
    let mut claims = 0_usize;
    let mut turns = 0_usize;
    let mut summaries = 0_usize;
    let mut facets = 0_usize;
    let mut other = 0_usize;
    let cut = oneiron::context_pack::select_critical_pack_rows(
        &mut pack.results,
        |entity| entity.critical,
        |entity| {
            let (count, limit) = match entity.entity_type {
                oneiron::registry::ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
                oneiron::registry::ENTITY_TYPE_TURN => (&mut turns, budget.turns),
                oneiron::registry::ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
                oneiron::registry::ENTITY_TYPE_FACET => (&mut facets, budget.facets),
                _ => (&mut other, budget.other),
            };
            if *count >= limit {
                return false;
            }
            *count += 1;
            true
        },
    );
    pack.stats.critical_over_budget |= !cut.is_empty();
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
