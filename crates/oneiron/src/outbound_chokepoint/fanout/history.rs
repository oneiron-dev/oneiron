//! Admission against the live consult graph, without charging its old edges again.

use super::*;

pub(crate) struct FanoutHistory<'a> {
    pub(crate) edges: &'a [FanoutPlanEdge],
    pub(crate) peer_rates: &'a [PeerRateSnapshot],
}

pub(crate) fn admit_fanout_with_history(
    plan: &FanoutPlan,
    threshold: Option<u32>,
    history: FanoutHistory<'_>,
    auto: &dyn FanoutAutoDecider,
    surface: &mut dyn FanoutSurfaceSink,
    now_ms: u64,
) -> Result<FanoutAdmission> {
    if let Some(pathology) = fanout_history_pathology(plan, &history)? {
        let canonical = canonicalize(plan)?;
        let estimate = estimate_of(&canonical);
        return pause(&canonical, estimate, Some(pathology), surface, now_ms);
    }
    admit_fanout_plan(plan, threshold, history.peer_rates, auto, surface, now_ms)
}

pub(crate) fn fanout_history_pathology(
    plan: &FanoutPlan,
    history: &FanoutHistory<'_>,
) -> Result<Option<FanoutPathology>> {
    let mut graph = FanoutPlan {
        edges: history.edges.to_vec(),
        ..plan.clone()
    };
    graph.edges.extend(plan.edges.iter().cloned());
    let graph = canonicalize(&graph)?;
    // A cycle wholly in old history is not evidence against an unrelated run.
    // Test each proposed edge for an existing path back to its source.
    for edge in &plan.edges {
        let mut pending = vec![(edge.to_peer_ref.clone(), vec![edge.from_peer_ref.clone()])];
        let mut seen = BTreeSet::new();
        while let Some((peer, mut path)) = pending.pop() {
            path.push(peer.clone());
            if peer == edge.from_peer_ref {
                return Ok(Some(FanoutPathology::ConsultCycle { peer_path: path }));
            }
            if seen.insert(peer.clone()) {
                for (from, to, _) in graph.edges.iter().rev() {
                    if from == &peer {
                        pending.push((to.clone(), path.clone()));
                    }
                }
            }
        }
    }
    detect_pathology(&canonicalize(plan)?, history.peer_rates)
}
