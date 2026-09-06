//! Focused pure-leaf tests. Integration must export the module to discover them.

use super::*;
use crate::edge::{EdgeActorClass, EdgeProvenanceFlags, EdgeValueLayout};

fn id(n: u32) -> EntityId {
    let mut bytes = [0; 16]; bytes[0] = 1; bytes[12..].copy_from_slice(&n.to_be_bytes());
    EntityId::from_bytes(bytes).expect("fixture ID")
}

fn edge(a: u32, b: u32, kind: EdgeKind) -> CommunityEdge {
    CommunityEdge { source: id(a), target: id(b), kind, deleted: false,
        value: DecodedEdgeValue { layout: EdgeValueLayout::SemanticBare, weight: 0.25,
            created_at: 1, vad: None, provenance: None } }
}

fn clique(start: u32, end: u32) -> Vec<CommunityEdge> {
    let mut edges = Vec::new();
    for a in start..end {
        for b in a + 1..end {
            for kind in [EdgeKind::BelongsTo, EdgeKind::Mentions, EdgeKind::About] {
                edges.push(edge(a, b, kind));
            }
        }
    }
    edges
}

fn meta(version: u64) -> CommunityCacheMeta {
    CommunityCacheMeta { schema: 0, graph_version: version, gamma: 1.0, generated_at: 42 }
}

fn fixture() -> CommunitySnapshot {
    let mut fine = vec![(1..=8).map(id).collect(), (9..=16).map(id).collect()];
    fine.extend((17..=100).map(|n| vec![id(n)]));
    let mut coarse = vec![(1..=16).map(id).collect()];
    coarse.extend((17..=100).map(|n| vec![id(n)]));
    CommunitySnapshot::from_partitions(meta(7), &fine, &coarse).expect("snapshot")
}

fn experiment() -> PprCommunityConfig {
    PprCommunityConfig { beta: PPR_COMMUNITY_BETA_EXPERIMENT, ..Default::default() }
}

fn scored(n: u32, score: f32) -> ScoredEntity { ScoredEntity { id: id(n), score } }

fn refresh(
    entities: &[EntityId], edges: &[CommunityEdge], old: Option<&CommunitySnapshot>,
    changed: &[EntityId], version: u64,
) -> (CommunitySnapshot, CommunityRefreshReport) {
    compute_communities(&CommunityGraphInput { entities, edges, changed, graph_version: version },
        old, 42, &PprCommunityConfig::default()).expect("refresh")
}

#[test]
fn constants_and_configuration_are_pinned() {
    let c = PprCommunityConfig::default();
    assert_eq!(c.beta.to_bits(), 0.0_f32.to_bits());
    assert_eq!(c.gamma, 1.0);
    assert_eq!(PPR_COMMUNITY_DETERMINISTIC_SEED, 0x4f4e455f313837);
    assert_eq!(PPR_COMMUNITY_REFRESH_CHURN_FRACTION, 0.05);
    assert_eq!(PPR_COMMUNITY_USAGE_DECAY, 0.10);
    assert!(c.validate().is_ok());
    for bad in [f32::NAN, f32::INFINITY, -0.1] {
        assert!(PprCommunityConfig { beta: bad, ..c.clone() }.validate().is_err());
    }
    for bad in [0.5, f32::NAN, 2.0] {
        assert!(PprCommunityConfig { gamma: bad, ..c.clone() }.validate().is_err());
    }
    assert!(PprCommunityConfig { multiplier_cap: 1.6, ..c.clone() }.validate().is_err());
    assert!(PprCommunityConfig { max_graph_fraction: 0.11, ..c.clone() }.validate().is_err());
    assert!(PprCommunityConfig { max_top_k_fraction: 0.71, ..c }.validate().is_err());
}

#[test]
fn every_current_edge_kind_has_the_curated_weight_not_its_stored_prior() {
    for raw in 0..=26 {
        let kind = EdgeKind::try_from_u8(raw).expect("registered edge kind");
        let expected = match kind {
            EdgeKind::BelongsTo | EdgeKind::ParticipatesIn | EdgeKind::Mentions | EdgeKind::About => Some(1.0),
            EdgeKind::Supports | EdgeKind::DerivedFrom | EdgeKind::HasFacet | EdgeKind::FacetOf => Some(0.8),
            EdgeKind::ClaimOf | EdgeKind::ScopedTo => Some(0.5),
            EdgeKind::Opposes | EdgeKind::ChildOf | EdgeKind::AssignedTo | EdgeKind::SameAs
            | EdgeKind::BlockedBy | EdgeKind::Blocks | EdgeKind::Fulfills | EdgeKind::DischargedBy => None,
            _ => Some(0.1),
        };
        assert_eq!(projection_weight(kind), expected, "{kind:?}");
        if crate::ppr::lambda_for_kind(kind).is_none() { assert_eq!(expected, None); }
        let projected = project_graph(&[id(1), id(2)], &[edge(1, 2, kind)]).expect("projection");
        assert_eq!(projected.edges.get(&(id(1), id(2))).copied(), expected.map(|w| (w * 10.0) as u64));
    }
}

#[test]
fn projection_excludes_deleted_retracted_zero_self_and_absent_endpoints() {
    let mut deleted = edge(1, 2, EdgeKind::About); deleted.deleted = true;
    let mut retracted = edge(1, 2, EdgeKind::Mentions);
    retracted.value.provenance = Some(EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Retracted, actor_class: EdgeActorClass::Human,
    });
    let mut zero = edge(1, 2, EdgeKind::BelongsTo); zero.value.weight = 0.0;
    let p = project_graph(&[id(1), id(2)], &[deleted, retracted, zero,
        edge(1, 1, EdgeKind::Supports), edge(1, 3, EdgeKind::Supports)]).expect("projection");
    assert!(p.edges.is_empty()); assert_eq!(p.entities, vec![id(1), id(2)]);
}

#[test]
fn projection_sums_distinct_directed_relations_and_deduplicates_records() {
    let a = edge(2, 1, EdgeKind::Mentions);
    let p = project_graph(&[id(2), id(1), id(1)], &[a, a, edge(1, 2, EdgeKind::Mentions),
        edge(1, 2, EdgeKind::Supports)]).expect("projection");
    assert_eq!(p.edges[&(id(1), id(2))], 28);
    let mut conflict = a; conflict.deleted = true;
    assert_eq!(project_graph(&[id(1), id(2)], &[a, conflict]), Err(CommunityError::Graph));
    for bad in [f32::NAN, f32::INFINITY, -1.0, 1.1] {
        let mut bad_edge = a; bad_edge.value.weight = bad;
        assert!(project_graph(&[id(1), id(2)], &[bad_edge]).is_err());
    }
}

#[test]
fn stable_content_ids_ignore_order_and_duplicate_input() {
    let a = CommunityId::from_members(&[id(3), id(1), id(2)]).expect("ID");
    let b = CommunityId::from_members(&[id(2), id(1), id(3), id(1)]).expect("ID");
    assert_eq!(a, b); assert_eq!(a.to_hex().len(), 32);
    assert_ne!(a, CommunityId::from_members(&[id(1), id(2)]).expect("ID"));
    assert!(CommunityId::from_members(&[]).is_err());
}

fn assert_connected(snapshot: &CommunitySnapshot, projection: &CommunityProjection) {
    for members in snapshot.members.values() {
        let allowed: BTreeSet<_> = members.iter().copied().collect();
        let mut seen = BTreeSet::from([members[0]]); let mut queue = vec![members[0]];
        while let Some(v) = queue.pop() {
            for &(a, b) in projection.edges.keys() {
                let next = if a == v { b } else if b == v { a } else { continue; };
                if allowed.contains(&next) && seen.insert(next) { queue.push(next); }
            }
        }
        assert_eq!(seen, allowed);
    }
}

#[test]
fn leiden_finds_dense_blocks_and_is_permutation_deterministic_at_both_levels() {
    let mut entities: Vec<_> = (1..=9).map(id).collect();
    let mut edges = clique(1, 4); edges.extend(clique(4, 7));
    edges.push(edge(3, 4, EdgeKind::PartOf));
    let (expected, _) = refresh(&entities, &edges, None, &[], 7);
    assert_eq!(expected.nodes[&id(1)].fine, expected.nodes[&id(3)].fine);
    assert_ne!(expected.nodes[&id(1)].fine, expected.nodes[&id(4)].fine);
    assert_eq!(expected.nodes[&id(7)].fine, CommunityId::from_members(&[id(7)]).expect("singleton"));
    assert_connected(&expected, &project_graph(&entities, &edges).expect("projection"));
    for shift in 0..12 {
        entities.rotate_left(1); edges.rotate_left(shift); edges.reverse();
        let (actual, _) = refresh(&entities, &edges, None, &[], 7);
        assert_eq!(actual, expected);
        assert_eq!(actual.encode_rows().expect("rows"), expected.encode_rows().expect("rows"));
    }
}

#[test]
fn gamma_one_allows_neutral_merges_but_does_not_cluster_weak_edges() {
    let nodes = [id(1), id(2)];
    let (strong, _) = refresh(&nodes, &[edge(1, 2, EdgeKind::About)], None, &[], 1);
    assert_eq!(strong.nodes[&id(1)].fine, strong.nodes[&id(2)].fine);
    let (weak, _) = refresh(&nodes, &[edge(1, 2, EdgeKind::Supports)], None, &[], 1);
    assert_ne!(weak.nodes[&id(1)].fine, weak.nodes[&id(2)].fine);
    let (empty, _) = refresh(&[], &[], None, &[], 1);
    assert!(empty.nodes.is_empty());
}

#[test]
fn leiden_refinement_restarts_singletons_and_requires_gamma_connected_subsets() {
    let p = project_graph(&[id(1), id(2), id(3)], &[edge(1, 2, EdgeKind::About),
        edge(2, 3, EdgeKind::About)]).expect("projection");
    let graph = Graph::from_projection(&p, &p.entities.iter().copied().collect());
    // A Louvain-only implementation would keep the supplied parent untouched.
    assert_eq!(refine_partition(&graph, &[0, 0, 0]), vec![vec![0], vec![1], vec![2]]);
    assert_eq!(connected_groups(&graph, &[0, 1, 0]), vec![vec![0], vec![1], vec![2]]);
}

fn quality(graph: &Graph, labels: &[usize]) -> i128 {
    let internal: u64 = graph.adj.iter().enumerate().map(|(v, edges)| {
        edges.iter().filter(|&(&u, _)| u > v && labels[u] == labels[v]).map(|(_, &w)| w).sum::<u64>()
    }).sum();
    i128::from(internal) - groups(labels).iter().map(|g| {
        let mass: usize = g.iter().map(|&v| graph.mass[v]).sum();
        5 * mass as i128 * (mass as i128 - 1)
    }).sum::<i128>()
}

#[test]
fn quotient_keeps_vertex_mass_and_cpm_deltas() {
    let mut edges = clique(1, 5); edges.push(edge(4, 5, EdgeKind::About));
    let p = project_graph(&(1..=5).map(id).collect::<Vec<_>>(), &edges).expect("projection");
    let graph = Graph::from_projection(&p, &p.entities.iter().copied().collect());
    let quotient = graph.aggregate(&[vec![0, 1], vec![2, 3], vec![4]]);
    assert_eq!(quotient.mass, vec![2, 2, 1]);
    assert_eq!(quality(&quotient, &[0, 0, 1]) - quality(&quotient, &[0, 1, 2]),
        quality(&graph, &[0, 0, 0, 0, 1]) - quality(&graph, &[0, 0, 1, 1, 2]));
    let mut labels = vec![0, 1, 2, 3, 4]; let before = quality(&graph, &labels);
    local_move(&graph, &mut labels); assert!(quality(&graph, &labels) >= before);
    let stable = labels.clone(); local_move(&graph, &mut labels); assert_eq!(labels, stable);
}

#[test]
fn cache_roundtrip_uses_only_pinned_logical_keys_and_fixed_metadata() {
    let snapshot = fixture(); let rows = snapshot.encode_rows().expect("rows");
    assert!(rows.keys().all(|k| k.starts_with(PPR_COMMUNITY_CACHE_PREFIX.as_bytes())));
    let value = &rows[META_KEY.as_bytes()];
    assert_eq!(value.len(), 21); assert_eq!(&value[1..9], &7_u64.to_le_bytes());
    assert_eq!(&value[9..13], &1.0_f32.to_le_bytes());
    let key = format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", id(1).to_hex()).into_bytes();
    let m = snapshot.nodes[&id(1)];
    assert_eq!(&rows[&key][..16], m.fine.as_bytes()); assert_eq!(&rows[&key][16..], m.coarse.as_bytes());
    let mut rows: Vec<_> = rows.into_iter().collect(); rows.reverse();
    assert_eq!(CommunitySnapshot::decode_rows(&rows, 7, 100).expect("decode"), snapshot);
    assert_eq!(CommunitySnapshot::decode_rows(&rows, 8, 100), Err(CommunityError::Version));
    assert!(CommunitySnapshot::decode_rows(&rows, 7, 99).is_err());
    assert!(PprCommunityCache::new(&snapshot, 8).is_err());
}

#[test]
fn cache_rejects_truncation_unknown_schema_duplicates_and_torn_rows() {
    let snapshot = fixture(); let rows: Vec<_> = snapshot.encode_rows().expect("rows").into_iter().collect();
    for i in 0..rows.len() {
        let mut bad = rows.clone(); bad[i].1.pop();
        assert!(CommunitySnapshot::decode_rows(&bad, 7, 100).is_err(), "truncated row {i}");
        let mut missing = rows.clone(); missing.remove(i);
        assert!(CommunitySnapshot::decode_rows(&missing, 7, 100).is_err(), "missing row {i}");
    }
    let mut duplicate = rows.clone(); duplicate.push(rows[0].clone());
    assert!(CommunitySnapshot::decode_rows(&duplicate, 7, 100).is_err());
    let mut bad = rows.clone();
    bad.iter_mut().find(|(k, _)| k.as_slice() == META_KEY.as_bytes()).expect("meta").1[0] = 1;
    assert!(CommunitySnapshot::decode_rows(&bad, 7, 100).is_err());
    let mut bad = rows;
    bad.push((b"ppr_community_cache:v0:unknown".to_vec(), vec![]));
    assert!(CommunitySnapshot::decode_rows(&bad, 7, 100).is_err());
}

#[test]
fn cache_rejects_noncanonical_members_reserved_ids_and_cross_level_aliasing() {
    let snapshot = fixture(); let rows = snapshot.encode_rows().expect("rows");
    let mut reversed: Vec<_> = rows.clone().into_iter().collect();
    let (_, members) = reversed.iter_mut().find(|(k, v)| k.starts_with(b"ppr_community_cache:v0:members:") && v.len() > 16).expect("members");
    members.reverse(); assert!(CommunitySnapshot::decode_rows(&reversed, 7, 100).is_err());
    let mut reserved: Vec<_> = rows.into_iter().collect();
    let (key, _) = reserved.iter_mut().find(|(k, _)| k.starts_with(b"ppr_community_cache:v0:node:")).expect("node");
    *key = format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", "0".repeat(32)).into_bytes();
    assert!(CommunitySnapshot::decode_rows(&reserved, 7, 100).is_err());
    let mut alias = snapshot;
    let coarse = alias.nodes[&id(1)].coarse;
    for n in 1..=8 { alias.nodes.get_mut(&id(n)).expect("node").fine = coarse; }
    assert!(alias.validate(7).is_err());
    assert!(CommunitySnapshot::from_partitions(meta(1), &[vec![id(1), id(2)]],
        &[vec![id(1)], vec![id(2)]]).is_err());
}

#[test]
fn incremental_refresh_matches_full_and_preserves_unaffected_membership() {
    let entities: Vec<_> = (1..=100).map(id).collect();
    let mut edges = clique(1, 4); edges.extend(clique(10, 13));
    let (old, _) = refresh(&entities, &edges, None, &[], 1);
    edges.retain(|e| e.source != id(1) && e.target != id(1));
    let (incremental, report) = refresh(&entities, &edges, Some(&old), &[id(1), id(2), id(3), id(1)], 2);
    let (full, _) = refresh(&entities, &edges, None, &[], 2);
    assert!(!report.full_recompute); assert_eq!(report.changed_entities, 3);
    assert_eq!(report.recomputed_entities, 3); assert_eq!(incremental, full);
    assert_eq!(incremental.nodes[&id(10)], old.nodes[&id(10)]);
    let remaining: Vec<_> = entities.into_iter().filter(|&e| e != id(1)).collect();
    let (deleted, _) = refresh(&remaining, &edges, Some(&old), &[id(2), id(3)], 3);
    assert!(!deleted.nodes.contains_key(&id(1)));
    assert_eq!(deleted, refresh(&remaining, &edges, None, &[], 3).0);
}

#[test]
fn frontier_closes_new_connections_and_full_fallback_is_strictly_above_five_percent() {
    let entities: Vec<_> = (1..=100).map(id).collect();
    let mut edges = clique(1, 4); edges.extend(clique(10, 13));
    let (old, _) = refresh(&entities, &edges, None, &[], 1);
    edges.push(edge(3, 10, EdgeKind::About));
    let (new, report) = refresh(&entities, &edges, Some(&old), &[id(3), id(10)], 2);
    assert_eq!(report.recomputed_entities, 6); assert_eq!(new, refresh(&entities, &edges, None, &[], 2).0);
    assert!(!refresh(&entities, &edges, Some(&old), &(1..=5).map(id).collect::<Vec<_>>(), 2).1.full_recompute);
    assert!(refresh(&entities, &edges, Some(&old), &(1..=6).map(id).collect::<Vec<_>>(), 2).1.full_recompute);
    assert!(refresh(&entities, &edges, Some(&old), &[], 2).1.full_recompute);
    let unchanged = refresh(&entities, &edges, Some(&new), &[], 2);
    assert_eq!(unchanged.1.recomputed_entities, 0);
    assert_eq!(unchanged.0, new);
    assert!(compute_communities(&CommunityGraphInput { entities: &entities, edges: &edges,
        changed: &[id(1)], graph_version: 1 }, Some(&old), 42, &experiment()).is_err());
}

#[test]
fn activation_covers_single_dominant_repeated_top_five_and_boundaries() {
    let snapshot = fixture(); let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    let fine = snapshot.nodes[&id(1)].fine;
    assert!(activated_communities(&cache, &[]).expect("active").is_empty());
    assert_eq!(activated_communities(&cache, &[scored(1, 1.0)]).expect("single"), BTreeSet::from([fine]));
    assert!(activated_communities(&cache, &[scored(1, 1.49), scored(9, 1.0)]).expect("not dominant").is_empty());
    assert_eq!(activated_communities(&cache, &[scored(1, 1.5), scored(9, 1.0)]).expect("dominant"), BTreeSet::from([fine]));
    assert_eq!(activated_communities(&cache, &[scored(1, 1.0), scored(9, 0.9), scored(2, 0.8)]).expect("shared"), BTreeSet::from([fine]));
    assert!(activated_communities(&cache, &[scored(1, 1.0), scored(9, 0.9), scored(17, 0.8),
        scored(18, 0.7), scored(19, 0.6), scored(2, 0.5)]).expect("outside five").is_empty());
    assert!(activated_communities(&cache, &[scored(1, 1.0), scored(1, 0.9)]).is_err());
    assert!(activated_communities(&cache, &[scored(1, 0.9), scored(9, 1.0)]).is_err());
    assert!(activated_communities(&cache, &[scored(1, f32::NAN)]).is_err());
    assert!(activated_communities(&cache, &[scored(999, 1.0)]).expect("missing").is_empty());
}

#[test]
fn multiplier_obeys_size_formula_decay_cap_and_large_community_disable() {
    let c = experiment();
    let m = community_multiplier(8, 100, 0, &c).expect("multiplier");
    let expected = 1.0 + f64::from(c.beta) / 9.0_f64.ln();
    assert!((f64::from(m) - expected).abs() < 1e-7);
    let decayed = community_multiplier(8, 100, 10, &c).expect("decay");
    assert!(decayed < m && decayed > 1.0);
    assert!((f64::from(decayed) - (1.0 + (expected - 1.0) * (-f64::from(PPR_COMMUNITY_USAGE_DECAY) * 10.0).exp())).abs() < 1e-7);
    assert!(community_multiplier(10, 100, 0, &c).expect("boundary") > 1.0);
    assert_eq!(community_multiplier(11, 100, 0, &c).expect("large"), 1.0);
    assert_eq!(community_multiplier(0, 100, 0, &c).expect("empty"), 1.0);
    assert_eq!(community_multiplier(1, 0, 0, &c).expect("empty graph"), 1.0);
    assert_eq!(community_multiplier(1, 100, u32::MAX, &c).expect("usage"), 1.0);
    assert_eq!(community_multiplier(1, 100, 0, &PprCommunityConfig { beta: f32::MAX, ..c }).expect("cap"), 1.5);
}

#[test]
fn beta_zero_is_bit_exact_even_with_bad_evidence_zero_limit_and_invalid_other_config() {
    let snapshot = fixture(); let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    let usage = HashMap::new();
    let mut scores = vec![scored(2, -0.0), scored(1, f32::from_bits(0x7fc00187)), scored(2, f32::INFINITY)];
    let before: Vec<_> = scores.iter().map(|s| (s.id, s.score.to_bits())).collect();
    for beta in [0.0, -0.0] {
        let context = CommunityBoostContext { ordered_seeds: &[scored(1, f32::NAN)], result_limit: 0, session_usage: &usage };
        let config = PprCommunityConfig { beta, gamma: f32::NAN, ..Default::default() };
        assert_eq!(apply_community_prior(&mut scores, &cache, &context, &config).expect("bypass"), CommunityBoostReport::default());
        assert_eq!(scores.iter().map(|s| (s.id, s.score.to_bits())).collect::<Vec<_>>(), before);
        assert_eq!(community_cache_identity(beta, 99).expect("identity"), None);
    }
    assert_ne!(community_cache_identity(0.2, 7).expect("key"), community_cache_identity(0.2, 8).expect("key"));
    assert_ne!(community_cache_identity(0.2, 7).expect("key"), community_cache_identity(0.3, 7).expect("key"));
}

#[test]
fn prior_boosts_matching_fine_not_merely_coarse_and_errors_are_atomic() {
    let snapshot = fixture(); let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    let usage = HashMap::new();
    let context = CommunityBoostContext { ordered_seeds: &[scored(1, 1.0)], result_limit: 10, session_usage: &usage };
    let mut scores = vec![scored(2, 1.0), scored(9, 0.9), scored(17, 0.8)];
    let report = apply_community_prior(&mut scores, &cache, &context, &experiment()).expect("prior");
    assert_eq!(report.boosted_candidates, 1); assert_eq!(report.activated_communities, 1);
    assert!(scores.iter().find(|s| s.id == id(2)).expect("matching").score > 1.0);
    assert_eq!(scores.iter().find(|s| s.id == id(9)).expect("coarse only").score.to_bits(), 0.9_f32.to_bits());
    assert!(report.fine_entropy_bits > report.coarse_entropy_bits);
    let mut overflow = vec![scored(2, f32::MAX), scored(9, 1.0)]; let before = overflow.clone();
    assert!(apply_community_prior(&mut overflow, &cache, &context, &experiment()).is_err());
    assert_eq!(overflow, before);
}

fn ranked(n: u32, group: u32, coarse: u32, score: f32, boosted: bool) -> Ranked {
    Ranked { entity: scored(n, score), boosted, membership: Some(CommunityMembership {
        fine: CommunityId::from_members(&[id(group)]).expect("fine"),
        coarse: CommunityId::from_members(&[id(coarse)]).expect("coarse"),
    }) }
}

#[test]
fn diversity_keeps_exactly_seven_of_ten_when_alternatives_exist_and_one_unboosted() {
    let mut pool: Vec<_> = (1..=12).map(|n| ranked(n, 1, 1, 2.0, true)).collect();
    pool.extend((20..=25).map(|n| ranked(n, n, n, 1.0, false)));
    let rows = diversify(pool, 10, PPR_COMMUNITY_MAX_TOP_K_FRACTION);
    assert_eq!(rows.len(), 10);
    assert_eq!(rows.iter().filter(|r| r.entity.id < id(20)).count(), 7);
    assert!(rows.iter().any(|r| !r.boosted));
    let only: Vec<_> = (1..=12).map(|n| ranked(n, 1, 1, 2.0, true)).collect();
    assert_eq!(diversify(only, 10, PPR_COMMUNITY_MAX_TOP_K_FRACTION).len(), 10);
}

#[test]
fn reserved_unboosted_matching_row_cannot_break_the_cap() {
    let mut pool: Vec<_> = (1..=12).map(|n| ranked(n, 1, 1, 2.0, true)).collect();
    pool.push(ranked(13, 1, 1, 0.1, false));
    pool.extend((20..=25).map(|n| ranked(n, 2, 2, 1.0, true)));
    let rows = diversify(pool, 10, PPR_COMMUNITY_MAX_TOP_K_FRACTION);
    assert_eq!(rows.iter().filter(|r| r.entity.id < id(20)).count(), 7);
    assert!(rows.iter().any(|r| r.entity.id == id(13)));
}

#[test]
fn mmr_breaks_ties_by_fine_then_coarse_novelty_and_ids() {
    let pool = vec![ranked(1, 1, 1, 1.0, true), ranked(2, 1, 1, 1.0, true),
        ranked(3, 2, 1, 1.0, true), ranked(4, 3, 2, 1.0, true)];
    let rows = diversify(pool.clone(), 4, PPR_COMMUNITY_MAX_TOP_K_FRACTION);
    assert_eq!(rows.iter().map(|r| r.entity.id).collect::<Vec<_>>(), vec![id(1), id(4), id(3), id(2)]);
    let reversed = diversify(pool.into_iter().rev().collect(), 4, PPR_COMMUNITY_MAX_TOP_K_FRACTION);
    assert_eq!(rows.iter().map(|r| r.entity.id).collect::<Vec<_>>(), reversed.iter().map(|r| r.entity.id).collect::<Vec<_>>());
    assert_eq!(entropy(&rows, false), 1.5);
}

#[test]
fn diversity_handles_zero_limit_small_k_missing_memberships_and_all_unboosted() {
    assert!(diversify(vec![ranked(1, 1, 1, 1.0, true)], 0, 0.7).is_empty());
    let rows = diversify(vec![ranked(1, 1, 1, 2.0, true), ranked(2, 2, 2, 1.0, false)], 1, 0.7);
    assert_eq!(rows[0].entity.id, id(2));
    let rows = diversify(vec![Ranked { entity: scored(3, 3.0), membership: None, boosted: false },
        Ranked { entity: scored(2, 2.0), membership: None, boosted: false },
        Ranked { entity: scored(1, 1.0), membership: None, boosted: false }], 3, 0.7);
    assert_eq!(rows.iter().map(|r| r.entity.id).collect::<Vec<_>>(), vec![id(3), id(2), id(1)]);
    assert!((entropy(&rows, true) - 3.0_f64.log2()).abs() < 1e-12);
}


#[test]
fn small_graph_family_keeps_connected_nested_partitions_and_stable_ids() {
    let entities: Vec<_> = (1..=8).map(id).collect();
    for mask in 0_u32..64 {
        let mut edges = Vec::new();
        for a in 1..=8 {
            for b in a + 1..=8 {
                if (mask >> ((a + b) % 6)) & 1 != 0 {
                    edges.push(edge(a, b, EdgeKind::About));
                    if (a * b + mask) % 3 == 0 { edges.push(edge(a, b, EdgeKind::Supports)); }
                }
            }
        }
        let (snapshot, _) = refresh(&entities, &edges, None, &[], 1);
        snapshot.validate(1).expect("nested, complete, content-addressed partition");
        assert_connected(&snapshot, &project_graph(&entities, &edges).expect("projection"));
        edges.reverse();
        let reversed: Vec<_> = entities.iter().copied().rev().collect();
        assert_eq!(snapshot, refresh(&reversed, &edges, None, &[], 1).0);
    }
}

#[test]
fn prior_consumes_session_usage_and_no_activation_leaves_the_input_untouched() {
    let snapshot = fixture(); let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    let fine = snapshot.nodes[&id(1)].fine;
    let usage = HashMap::from([(fine, 10)]);
    let context = CommunityBoostContext { ordered_seeds: &[scored(1, 1.0)], result_limit: 10, session_usage: &usage };
    let mut scores = vec![scored(2, 1.0), scored(17, 0.5)];
    apply_community_prior(&mut scores, &cache, &context, &experiment()).expect("prior");
    assert_eq!(scores.iter().find(|s| s.id == id(2)).expect("matching").score.to_bits(),
        community_multiplier(8, 100, 10, &experiment()).expect("multiplier").to_bits());
    let inactive = CommunityBoostContext { ordered_seeds: &[scored(1, 1.0), scored(9, 0.9)],
        result_limit: 0, session_usage: &usage };
    let before = scores.clone();
    assert_eq!(apply_community_prior(&mut scores, &cache, &inactive, &experiment()).expect("inactive"), CommunityBoostReport::default());
    assert_eq!(scores, before);
}

#[test]
fn incremental_refresh_detects_added_entities_without_a_separate_entity_frontier_entry() {
    let entities: Vec<_> = (1..=100).map(id).collect();
    let edges = clique(1, 4);
    let (old, _) = refresh(&entities, &edges, None, &[], 1);
    let mut added = entities; added.push(id(101));
    let mut changed_edges = edges; changed_edges.push(edge(3, 101, EdgeKind::About));
    let (new, report) = refresh(&added, &changed_edges, Some(&old), &[id(3)], 2);
    assert!(!report.full_recompute); assert_eq!(report.changed_entities, 2);
    assert_eq!(report.recomputed_entities, 4);
    assert_eq!(new, refresh(&added, &changed_edges, None, &[], 2).0);
}

#[test]
fn ordered_seed_evidence_survives_id_sort_and_does_not_fabricate_explicit_scores() {
    let ordered = ordered_seed_evidence(&[id(1), id(9), id(2), id(1)],
        &[scored(9, 1.0), scored(1, 1.5)]).expect("evidence");
    assert_eq!(ordered, vec![scored(1, 1.5), scored(9, 1.0), scored(2, 0.0)]);
    let snapshot = fixture();
    let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    assert!(activated_communities(&cache, &[scored(1, 0.0), scored(9, 0.0)]).expect("no evidence").is_empty());
    assert!(ordered_seed_evidence(&[id(1)], &[scored(1, f32::NAN)]).is_err());
}

#[test]
fn unknown_edge_frontier_still_forces_full_refresh_when_entities_were_added() {
    let entities: Vec<_> = (1..=100).map(id).collect();
    let mut edges = clique(1, 4);
    edges.extend(clique(10, 13));
    let (old, _) = refresh(&entities, &edges, None, &[], 1);
    let mut current = entities;
    current.push(id(101));
    edges.retain(|edge| edge.source != id(10) && edge.target != id(10));
    // The node-set difference cannot prove that unrelated edges did not change.
    let (snapshot, report) = refresh(&current, &edges, Some(&old), &[], 2);
    assert!(report.full_recompute);
    assert_eq!(snapshot, refresh(&current, &edges, None, &[], 2).0);
}


#[test]
fn deferred_diversity_uses_only_final_pool_and_keeps_fused_score_bits() {
    let snapshot = fixture();
    let cache = PprCommunityCache::new(&snapshot, 7).expect("cache");
    let usage = HashMap::new();
    let context = CommunityBoostContext {
        ordered_seeds: &[scored(1, 1.0)], result_limit: 2, session_usage: &usage,
    };
    let mut scores: Vec<_> = (2..=8).map(|n| scored(n, 1.0)).collect();
    scores.extend([scored(9, 0.9), scored(17, 0.8)]);
    let (report, boosted) = boost_community_scores(&mut scores, &cache, &context, &experiment()).expect("prior");
    assert_eq!(report.boosted_candidates, 7);
    assert_eq!(scores.len(), 9, "expansion must not truncate before filters and fusion");
    scores.retain(|row| row.id != id(9) && row.id != id(17));
    scores.extend((40..=44).map(|n| scored(n, 0.5))); // other fused channels
    let before: BTreeMap<_, _> = scores.iter().map(|row| (row.id, row.score.to_bits())).collect();
    let report = apply_community_diversity(&mut scores, &cache, &boosted, 10, &experiment()).expect("final diversity");
    assert_eq!(scores.len(), 10);
    assert_eq!(scores.iter().filter(|row| boosted.contains(&row.id)).count(), 7);
    for row in &scores {
        assert_eq!(row.score.to_bits(), before[&row.id]);
        assert_ne!(row.id, id(1)); // a seed/membership is not a result source
        assert_ne!(row.id, id(9));
        assert_ne!(row.id, id(17));
    }
    assert!(report.fine_entropy_bits > 0.0);
    assert!(report.coarse_entropy_bits > 0.0);
}
