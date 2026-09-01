use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rmpv::Value;

use crate::EdgeKind;
use crate::claim::ClaimSource;
use crate::code_sandbox::SandboxGuestTier;
use crate::code_symbol::{CodeSymbolGraph, code_symbol_entity_id};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSourceTrust {
    Trusted,
    Untrusted,
}

impl CodeSourceTrust {
    /// Stable trust label, for the host records that name an admission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentLane {
    Free,
    Review,
}

#[must_use]
pub const fn consent_lane_for(tier: SandboxGuestTier, source: CodeSourceTrust) -> ConsentLane {
    match (tier, source) {
        (SandboxGuestTier::FirstPartyDreamer, CodeSourceTrust::Trusted) => ConsentLane::Free,
        _ => ConsentLane::Review,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEmissionContext {
    pub tier: SandboxGuestTier,
    pub source_trust: CodeSourceTrust,
    pub dreamer_run_id: Option<String>,
    pub touched_symbols: Vec<EntityId>,
}

pub struct ReviewContext {
    authoring_dreamer_run_id: String,
    reviewer_run_id: String,
    code_artifact_refs: Vec<EntityId>,
    symbol_graph: CodeSymbolGraph,
}

impl ReviewContext {
    pub fn new(
        authoring_dreamer_run_id: String,
        reviewer_run_id: String,
        code_artifact_refs: Vec<EntityId>,
        symbol_graph: CodeSymbolGraph,
    ) -> Result<Self> {
        ReviewContextInput::new(
            &authoring_dreamer_run_id,
            &reviewer_run_id,
            &code_artifact_refs,
            &symbol_graph,
        )?;
        Ok(Self {
            authoring_dreamer_run_id,
            reviewer_run_id,
            code_artifact_refs,
            symbol_graph,
        })
    }
    pub(crate) fn as_input(&self) -> Result<ReviewContextInput<'_>> {
        ReviewContextInput::new(
            &self.authoring_dreamer_run_id,
            &self.reviewer_run_id,
            &self.code_artifact_refs,
            &self.symbol_graph,
        )
    }
}

pub struct ReviewContextInput<'a> {
    authoring_dreamer_run_id: &'a str,
    reviewer_run_id: &'a str,
    code_artifact_refs: &'a [EntityId],
    symbol_graph: &'a CodeSymbolGraph,
}

impl<'a> ReviewContextInput<'a> {
    pub fn new(
        authoring_dreamer_run_id: &'a str,
        reviewer_run_id: &'a str,
        code_artifact_refs: &'a [EntityId],
        symbol_graph: &'a CodeSymbolGraph,
    ) -> Result<Self> {
        if reviewer_run_id.is_empty() {
            return Err(Error::CodeReviewMissingReviewerRunId);
        }
        if reviewer_run_id == authoring_dreamer_run_id {
            return Err(Error::CodeReviewRunIdNotDistinct);
        }
        if code_artifact_refs.is_empty() {
            return Err(Error::CodeReviewMissingArtifactRefs);
        }
        Ok(Self {
            authoring_dreamer_run_id,
            reviewer_run_id,
            code_artifact_refs,
            symbol_graph,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlastRadiusWalk {
    pub reached_symbols: u64,
    pub reached_entities: u64,
    pub max_depth: u32,
}

impl BlastRadiusWalk {
    pub fn from_touched_symbols(
        graph: &CodeSymbolGraph,
        touched_symbols: &[EntityId],
    ) -> Result<Self> {
        if touched_symbols.is_empty() {
            return Err(Error::CodeBlastRadiusMissingTouchedSymbols);
        }
        let (adjacency, entities_by_symbol) = index_reference_graph(graph)?;
        let mut visited = BTreeSet::new();
        let mut reached_entities = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut max_depth = 0_u32;
        // Seeds stay a `BTreeSet`: the walk's reverse-BFS frontier order is the
        // sorted, deduped symbol order, not caller order.
        for seed in BTreeSet::from_iter(touched_symbols.iter().copied()) {
            if !entities_by_symbol.contains_key(&seed) {
                return Err(Error::CodeBlastRadiusUnknownSymbol(seed));
            }
            visited.insert(seed);
            queue.push_back((seed, 0_u32));
        }
        while let Some((symbol, depth)) = queue.pop_front() {
            max_depth = max_depth.max(depth);
            if let Some(ids) = entities_by_symbol.get(&symbol) {
                reached_entities.extend(ids.iter().copied());
            }
            for neighbor in adjacency.get(&symbol).into_iter().flatten() {
                if !entities_by_symbol.contains_key(neighbor) {
                    continue;
                }
                if visited.insert(*neighbor) {
                    queue.push_back((
                        *neighbor,
                        depth
                            .checked_add(1)
                            .ok_or(Error::ArithmeticOverflow("code blast-radius depth"))?,
                    ));
                }
            }
        }
        Ok(Self {
            reached_symbols: u64::try_from(visited.len())
                .map_err(|_| Error::ArithmeticOverflow("code blast-radius symbols"))?,
            reached_entities: u64::try_from(reached_entities.len())
                .map_err(|_| Error::ArithmeticOverflow("code blast-radius entities"))?,
            max_depth,
        })
    }
    /// The review lane's candidate evidence: one map, two readerships.
    ///
    /// The `code_blast_radius.v1` block is the review record a human reads and
    /// keeps its keys and byte-semantics exactly as before. The consolidation
    /// keys appended after it are the ONE evidence contract the GATE-12
    /// pre-commit floor decodes, so the walk's own artifact refs are what that
    /// floor resolves. This teaches the floor no second schema: it decodes
    /// `refs`/`chain`/`source_meet` and ignores every other key, exactly as it
    /// does for the promotion writer's envelope.
    ///
    /// The meet is `ToolOutput` because the walk is a host tool's artifact —
    /// the symbol graph read by the engine, not a model's assertion.
    pub fn to_evidence(self, reviewer_run_id: &str, code_artifact_refs: &[EntityId]) -> Value {
        let mut entries = vec![
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[0]),
                Value::from(BLAST_RADIUS_EVIDENCE_KIND),
            ),
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[1]),
                Value::from(reviewer_run_id),
            ),
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[2]),
                Value::Array(
                    code_artifact_refs
                        .iter()
                        .map(|id| Value::Binary(id.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[3]),
                Value::from(self.reached_symbols),
            ),
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[4]),
                Value::from(self.reached_entities),
            ),
            (
                Value::from(BLAST_RADIUS_EVIDENCE_KEYS[5]),
                Value::from(u64::from(self.max_depth)),
            ),
        ];
        let refs = code_artifact_refs.to_vec();
        entries.extend(consolidation_entries(refs, ClaimSource::ToolOutput));
        Value::Map(entries)
    }
}
pub const BLAST_RADIUS_EVIDENCE_KIND: &str = "code_blast_radius.v1";
/// Reader-facing shape name of the FREE lane's admission evidence.
///
/// The free lane cites the host's own admission record; naming the shape keeps
/// a reader able to tell the two lanes' evidence apart by the same `kind` key
/// the review map already carries.
pub const CODE_EMISSION_EVIDENCE_KIND: &str = "code_emission_admission.v1";
/// Every key a candidate-evidence map from this module carries, in order: the
/// six reader-facing blast-radius keys, then the three consolidation keys the
/// GATE-12 floor decodes (`dreamer_consolidation`'s encoder writes exactly
/// these, in exactly this order).
pub const BLAST_RADIUS_EVIDENCE_KEYS: [&str; 9] = [
    "kind",
    "reviewer_run_id",
    "code_artifact_refs",
    "reached_symbols",
    "reached_entities",
    "max_depth",
    "refs",
    "chain",
    "source_meet",
];

/// The consolidation-evidence entries of a candidate-evidence map, produced by
/// the ONE encoder that owns that shape so no writer here hand-rolls a second
/// spelling of it.
fn consolidation_entries(refs: Vec<EntityId>, source_meet: ClaimSource) -> Vec<(Value, Value)> {
    let encoded = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs,
        chain: Vec::new(),
        source_meet,
    });
    let Value::Map(entries) = encoded else {
        // The encoder's own contract is a map. If that ever changed, the
        // candidate would carry no admissible evidence and the door would
        // refuse it — fail-closed, never a silent unvalidated write.
        return Vec::new();
    };
    entries
}

/// The free lane's candidate evidence: the host's persisted code-emission
/// admission record, cited in the consolidation shape the floor decodes.
///
/// `ToolOutput` is the truthful meet — the record is a host sandbox artifact
/// (tier, source trust, run handles), not a model assertion.
fn code_emission_evidence(emission_record: EntityId) -> Value {
    let mut entries = vec![(
        Value::from(BLAST_RADIUS_EVIDENCE_KEYS[0]),
        Value::from(CODE_EMISSION_EVIDENCE_KIND),
    )];
    let refs = vec![emission_record];
    entries.extend(consolidation_entries(refs, ClaimSource::ToolOutput));
    Value::Map(entries)
}

pub struct CodeEmissionAdmission {
    pub lane: ConsentLane,
    pub dreamer_run_id: String,
    pub candidate_evidence: Option<Value>,
    /// The host-persisted code-emission record this admission cites on the
    /// free lane, as the dispatcher supplied it. `None` for the review lane,
    /// whose evidence is the blast-radius walk's own artifact refs.
    pub emission_record: Option<EntityId>,
}

/// Rules one code-emission write into its consent lane and stamps the
/// candidate evidence that lane cites.
///
/// `emission_record` is the host's persisted code-emission admission record,
/// minted and committed by the dispatcher BEFORE any door reads this evidence.
/// A free-lane admission that is handed one cites it; one handed `None` cites
/// nothing, and the GATE-12 floor then refuses the write. Both directions are
/// fail-closed: this function never invents a ref, and never suppresses the
/// floor.
pub fn admit_code_emission(
    tier: SandboxGuestTier,
    source: CodeSourceTrust,
    dreamer_run_id: Option<&str>,
    touched_symbols: &[EntityId],
    review: Option<&ReviewContextInput<'_>>,
    emission_record: Option<EntityId>,
) -> Result<CodeEmissionAdmission> {
    let dreamer_run_id = dreamer_run_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or(Error::CodeEmissionMissingDreamerRunId)?;
    let lane = consent_lane_for(tier, source);
    let candidate_evidence = match lane {
        ConsentLane::Free => emission_record.map(code_emission_evidence),
        ConsentLane::Review => {
            let review = review.ok_or(Error::CodeReviewContextRequired)?;
            if review.authoring_dreamer_run_id != dreamer_run_id {
                return Err(Error::CodeReviewAuthoringRunIdMismatch);
            }
            Some(
                BlastRadiusWalk::from_touched_symbols(review.symbol_graph, touched_symbols)?
                    .to_evidence(review.reviewer_run_id, review.code_artifact_refs),
            )
        }
    };
    Ok(CodeEmissionAdmission {
        lane,
        dreamer_run_id: dreamer_run_id.to_owned(),
        candidate_evidence,
        emission_record: match lane {
            ConsentLane::Free => emission_record,
            ConsentLane::Review => None,
        },
    })
}

/// Reverse adjacency (`Mentions` target -> sorted deduped sources) paired with
/// the per-symbol entity fan-out (symbol id plus any provenance claim id).
type ReferenceGraphMaps = (
    BTreeMap<EntityId, Vec<EntityId>>,
    BTreeMap<EntityId, BTreeSet<EntityId>>,
);

fn index_reference_graph(graph: &CodeSymbolGraph) -> Result<ReferenceGraphMaps> {
    let mut entities_by_symbol = BTreeMap::new();
    for symbol in &graph.manifest.symbols {
        let id = code_symbol_entity_id(&graph.manifest.repo_ref, symbol)?;
        let mut entities = BTreeSet::from([id]);
        if let Some(provenance) = symbol.provenance_claim_id {
            entities.insert(provenance);
        }
        entities_by_symbol.insert(id, entities);
    }
    let mut adjacency = BTreeMap::new();
    for edge in &graph.edges {
        if edge.kind == EdgeKind::Mentions {
            adjacency
                .entry(edge.target)
                .or_insert_with(Vec::new)
                .push(edge.source);
        }
    }
    for neighbors in adjacency.values_mut() {
        neighbors.sort();
        neighbors.dedup();
    }
    Ok((adjacency, entities_by_symbol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_symbol::{
        CodeChunk, CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision,
        derive_symbol_fingerprint,
    };
    use crate::codebase::RepoRef;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("test entity id")
    }

    fn graph(with_provenance: bool) -> (CodeSymbolGraph, Vec<EntityId>) {
        let repo =
            RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
                .expect("repo");
        let chunks = (0..5)
            .map(|n| CodeChunk::from_text(format!("src/{n}.rs"), 1, 1, "fn x() {}\n"))
            .collect::<Result<Vec<_>>>()
            .expect("chunks");
        let symbols = chunks
            .iter()
            .enumerate()
            .map(|(n, chunk)| {
                let path = format!("src/{n}.rs");
                CodeSymbolRevision::new(
                    path,
                    format!("s{n}"),
                    "function",
                    derive_symbol_fingerprint(
                        &chunk.path,
                        &format!("s{n}"),
                        "function",
                        std::slice::from_ref(chunk),
                    )
                    .expect("fingerprint"),
                    vec![n as u32],
                    with_provenance.then(|| id((n + 10) as u8)),
                    None,
                )
            })
            .collect();
        let manifest = CodeSymbolManifest::new(
            repo,
            Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            chunks,
            symbols,
        )
        .expect("manifest");
        let ids = manifest
            .symbols
            .iter()
            .map(|symbol| code_symbol_entity_id(&manifest.repo_ref, symbol).expect("symbol id"))
            .collect::<Vec<_>>();
        // B -> A, C -> B, D -> B (convergence), A -> C (cycle), and E unrelated.
        let edges = vec![
            CodeSymbolGraphEdge::new(ids[1], EdgeKind::Mentions, ids[0], 1.0),
            CodeSymbolGraphEdge::new(ids[2], EdgeKind::Mentions, ids[1], 1.0),
            CodeSymbolGraphEdge::new(ids[3], EdgeKind::Mentions, ids[1], 1.0),
            CodeSymbolGraphEdge::new(ids[0], EdgeKind::Mentions, ids[2], 1.0),
            CodeSymbolGraphEdge::new(ids[4], EdgeKind::Attached, ids[0], 1.0),
            // A well-shaped dangling endpoint must not count or be traversed.
            CodeSymbolGraphEdge::new(id(99), EdgeKind::Mentions, ids[0], 1.0),
        ];
        (CodeSymbolGraph::new(manifest, edges).expect("graph"), ids)
    }

    #[test]
    fn routes_fail_closed() {
        assert_eq!(
            consent_lane_for(
                SandboxGuestTier::FirstPartyDreamer,
                CodeSourceTrust::Trusted
            ),
            ConsentLane::Free
        );
        for tier in [
            SandboxGuestTier::FirstPartyDreamer,
            SandboxGuestTier::Foreign,
            SandboxGuestTier::Untrusted,
        ] {
            for trust in [CodeSourceTrust::Trusted, CodeSourceTrust::Untrusted] {
                if !(tier == SandboxGuestTier::FirstPartyDreamer
                    && trust == CodeSourceTrust::Trusted)
                {
                    assert_eq!(consent_lane_for(tier, trust), ConsentLane::Review);
                }
            }
        }
    }

    #[test]
    fn review_context_requires_distinct_ids_and_artifacts() {
        let (graph, ids) = graph(false);
        assert!(matches!(
            ReviewContextInput::new("author", "author", &ids[..1], &graph),
            Err(Error::CodeReviewRunIdNotDistinct)
        ));
        assert!(matches!(
            ReviewContextInput::new("author", "", &ids[..1], &graph),
            Err(Error::CodeReviewMissingReviewerRunId)
        ));
        assert!(matches!(
            ReviewContextInput::new("author", "review", &[], &graph),
            Err(Error::CodeReviewMissingArtifactRefs)
        ));
        assert!(ReviewContext::new("author".into(), "review".into(), vec![ids[0]], graph).is_ok());
    }

    #[test]
    fn bfs_counts_reverse_dependents_cycle_convergence_and_filters_attached() {
        let (graph, ids) = graph(true);
        let walk = BlastRadiusWalk::from_touched_symbols(&graph, &[ids[0]]).expect("walk");
        assert_eq!(walk.reached_symbols, 4);
        assert_eq!(walk.reached_entities, 8);
        assert_eq!(walk.max_depth, 2);
    }

    #[test]
    fn bfs_deduplicates_seeds_and_rejects_missing_or_empty_seeds() {
        let (graph, ids) = graph(false);
        let walk = BlastRadiusWalk::from_touched_symbols(&graph, &[ids[0], ids[0]]).expect("walk");
        assert_eq!(
            (walk.reached_symbols, walk.reached_entities, walk.max_depth),
            (4, 4, 2)
        );
        assert!(matches!(
            BlastRadiusWalk::from_touched_symbols(&graph, &[]),
            Err(Error::CodeBlastRadiusMissingTouchedSymbols)
        ));
        assert!(matches!(
            BlastRadiusWalk::from_touched_symbols(&graph, &[id(42)]),
            Err(Error::CodeBlastRadiusUnknownSymbol(_))
        ));
    }

    #[test]
    fn evidence_is_ordered_and_admission_trims() {
        let (graph, ids) = graph(false);
        let review =
            ReviewContextInput::new("run-1", "review-1", &ids[..1], &graph).expect("review");
        let admission = admit_code_emission(
            SandboxGuestTier::FirstPartyDreamer,
            CodeSourceTrust::Untrusted,
            Some("  run-1  "),
            &ids[..1],
            Some(&review),
            None,
        )
        .expect("admission");
        assert_eq!(admission.dreamer_run_id, "run-1");
        let Value::Map(entries) = admission.candidate_evidence.expect("evidence") else {
            panic!("map")
        };
        assert_eq!(
            entries
                .iter()
                .map(|(key, _)| key.as_str().unwrap())
                .collect::<Vec<_>>(),
            BLAST_RADIUS_EVIDENCE_KEYS
        );
        assert_eq!(entries[0].1.as_str(), Some(BLAST_RADIUS_EVIDENCE_KIND));
        // The reader block is unchanged AND the floor's one contract now rides
        // the same map: the walk's artifact refs are what the door resolves.
        let envelope =
            crate::dreamer_consolidation::decode_consolidation_evidence(&Value::Map(entries))
                .expect("the review map decodes")
                .expect("the review map carries the consolidation contract");
        assert_eq!(envelope.refs, ids[..1].to_vec());
        assert!(envelope.chain.is_empty());
        assert_eq!(envelope.source_meet, ClaimSource::ToolOutput);
    }

    /// The free lane cites the host's persisted admission record, in the same
    /// envelope the floor decodes — and never the review artifact shape.
    #[test]
    fn free_admission_cites_the_host_emission_record() {
        let record = id(0x5A);
        let admission = admit_code_emission(
            SandboxGuestTier::FirstPartyDreamer,
            CodeSourceTrust::Trusted,
            Some(" free-run "),
            &[],
            None,
            Some(record),
        )
        .expect("admission");
        assert_eq!(admission.lane, ConsentLane::Free);
        assert_eq!(admission.emission_record, Some(record));
        let evidence = admission.candidate_evidence.expect("free evidence");
        let Value::Map(entries) = &evidence else {
            panic!("map")
        };
        assert_eq!(entries[0].0.as_str(), Some(BLAST_RADIUS_EVIDENCE_KEYS[0]));
        assert_eq!(entries[0].1.as_str(), Some(CODE_EMISSION_EVIDENCE_KIND));
        assert_ne!(entries[0].1.as_str(), Some(BLAST_RADIUS_EVIDENCE_KIND));
        let envelope = crate::dreamer_consolidation::decode_consolidation_evidence(&evidence)
            .expect("the free map decodes")
            .expect("the free map carries the consolidation contract");
        assert_eq!(envelope.refs, vec![record]);
        assert!(envelope.chain.is_empty());
        assert_eq!(envelope.source_meet, ClaimSource::ToolOutput);
    }

    #[test]
    fn admission_free_has_no_evidence_and_review_failures_are_typed() {
        // No host record supplied, so there is nothing truthful to cite: the
        // admission stays evidence-free and the door's floor refuses the write.
        let free = admit_code_emission(
            SandboxGuestTier::FirstPartyDreamer,
            CodeSourceTrust::Trusted,
            Some(" run "),
            &[],
            None,
            None,
        )
        .expect("free");
        assert_eq!(free.lane, ConsentLane::Free);
        assert!(free.candidate_evidence.is_none());
        assert!(free.emission_record.is_none());
        assert!(matches!(
            admit_code_emission(
                SandboxGuestTier::FirstPartyDreamer,
                CodeSourceTrust::Trusted,
                Some(" "),
                &[],
                None,
                None
            ),
            Err(Error::CodeEmissionMissingDreamerRunId)
        ));
        assert!(matches!(
            admit_code_emission(
                SandboxGuestTier::FirstPartyDreamer,
                CodeSourceTrust::Untrusted,
                Some("run"),
                &[],
                None,
                None
            ),
            Err(Error::CodeReviewContextRequired)
        ));
        let (graph, ids) = graph(false);
        let review = ReviewContextInput::new("other", "review", &ids[..1], &graph).expect("review");
        assert!(matches!(
            admit_code_emission(
                SandboxGuestTier::FirstPartyDreamer,
                CodeSourceTrust::Untrusted,
                Some("run"),
                &ids[..1],
                Some(&review),
                None
            ),
            Err(Error::CodeReviewAuthoringRunIdMismatch)
        ));
    }
}
