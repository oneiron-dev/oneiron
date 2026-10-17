use std::cell::Cell;
use std::collections::BTreeMap;
use std::ops::ControlFlow;

use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::claim::{
    ClaimBody, ClaimReadStatus, PointRead, ScopedRead, ScopedReadActorKey, claim_surfaceable,
    decode_claim_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    BudgetLease, CallEnvelope, ContentPart, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId,
};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::decisions::{MembershipDecisions, judge};
use super::definition::{QueryScope, SavedQueryDefinition};
use super::evidence::{
    EVIDENCE_HASH_LEN, EvaluationOutcome, MatchDecision, MatchVerdict, RelevantEvidence,
    SavedQueryDerivationEnvelope, VerdictMemoKey, VerdictMemoRow, WakeEvaluationReport,
    compute_evidence_hash, put_verdict_memo, verdict_memo,
};
use super::filter::{HiddenDependencies, MatcherSpec, evaluate_filter, filter_dependencies};
use super::membership::MembershipCause;
use super::storage::{load_record, matcher_to_json};
use super::support::{
    EVALUATOR_VERSION, canonical_json_bytes, cosine_similarity_micros, edge_kind_from_name,
    hex_lower, invalid, rmpv_to_json, vector_pair_fingerprint,
};

/// The LLM dependency of a rubric-driven judge.
///
/// Backend, budget lease, and call envelope travel as ONE binding so no caller
/// can present a backend without a lease: the admission token is not an
/// optional decoration on the call, it is half of what makes the call legal.
/// The verdict is the membership question through the host's ladder, the
/// backend its first read.
pub struct SavedQueryJudgeBinding<'a> {
    /// Host-injected backend.
    pub backend: &'a dyn LlmBackend,
    /// Budget admission token.
    pub lease: &'a BudgetLease,
    /// Host-owned call envelope. Model policy is the host's, not this module's.
    pub envelope: &'a CallEnvelope,
    /// The host's ladder for the membership question
    /// ([`MembershipDecisions::shipped`] when it staffs none).
    pub decisions: &'a MembershipDecisions,
}

/// Staged evaluator over one vault.
///
/// `owner_read` and `owner_grants` are the saved query owner's authority AT
/// EVALUATION TIME. There is deliberately no viewer/caller principal on this
/// struct: a viewer cannot change membership because a viewer is not an
/// input to it.
pub struct SavedQueryEvaluator<'a> {
    /// Vault the evidence is read from.
    pub vault: &'a Vault,
    /// The owner's reach on the scope axes; intersected with the definition's
    /// declared scope. The sweep passes the unrestricted axes: the owner's
    /// read authority is `owner_read`.
    pub owner_grants: &'a QueryScope,
    /// The owner's read key ([`crate::saved_query::sweep_owner_read`]). The
    /// candidate and every row of evidence are read through its lane, so a
    /// query reads what its owner may read now and nothing more.
    pub owner_read: &'a ScopedReadActorKey,
    /// Judge dependency; absent means no LLM matcher can run.
    pub judge: Option<SavedQueryJudgeBinding<'a>>,
}

/// One entity evaluation request.
pub struct EvaluationRequest<'a> {
    /// The saved query.
    pub query_ref: EntityId,
    /// Campaign the membership consequence is scoped to.
    pub campaign_ref: EntityId,
    /// Entity being evaluated.
    pub entity_ref: EntityId,
    /// Definition to evaluate.
    pub definition: &'a SavedQueryDefinition,
    /// Why this evaluation is happening.
    pub cause: MembershipCause,
    /// Valid time of the evaluation.
    pub valid_at: u64,
    /// Detection time of the evaluation.
    pub detected_at: u64,
}

/// Whether a stage-2 judge actually ran, tracked so wake batches can honor
/// `max_judges_per_wake` without inferring it from the verdict.
struct StagedOutcome {
    outcome: EvaluationOutcome,
    judge_ran: bool,
}

/// One evidence collection, plus the vectors the fingerprints were taken from.
///
/// Stage 2 scores THESE vectors rather than re-reading them: each
/// `Vault::get_vector` opens its own read transaction, so a re-read could see a
/// re-embedding that landed after fingerprinting and store a verdict derived
/// from new vectors under the old vectors' evidence hash. A memo must be
/// derived from exactly the evidence its key names.
pub(super) struct CollectedEvidence {
    pub(super) evidence: RelevantEvidence,
    /// A relevant claim awaits its owner's critical confirm.
    pub(super) held: bool,
    /// What the owner's read withheld among the dependencies.
    pub(super) hidden: HiddenDependencies,
    pub(super) subject_vector: Option<Vec<f32>>,
    pub(super) exemplar_vectors: Vec<(EntityId, Option<Vec<f32>>)>,
}

impl SavedQueryEvaluator<'_> {
    /// Evaluates one entity against one definition.
    ///
    /// Order is the cost model: scope and read gates, evidence, memo, stage 1,
    /// stage 2. Stage 2 is reached from exactly one place — inside the stage-1 success
    /// branch — so a failing filter cannot spend a judge call.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the query is not evaluable or a judge is
    /// required but unbound; storage and backend errors propagate.
    pub async fn evaluate_entity(
        &self,
        request: &EvaluationRequest<'_>,
    ) -> Result<EvaluationOutcome> {
        self.evaluate_staged(request).await.map(|it| it.outcome)
    }

    async fn evaluate_staged(&self, request: &EvaluationRequest<'_>) -> Result<StagedOutcome> {
        if !request.definition.lifecycle.is_evaluable() {
            return Err(invalid("saved query is not active"));
        }

        // The authorization gate runs FIRST and is never memoized. A memo caches
        // a DERIVATION; caching an authorization outcome would let a verdict
        // outlive the grant that produced it — the owner loses the world, the
        // memo keeps answering "member".
        let Some(effective_scope) = request.definition.scope.intersect(self.owner_grants) else {
            return Self::denied_outcome(request, SAVED_QUERY_WHY_SCOPE_CLOSED);
        };

        // Evaluate against the definition AS IT WILL ACTUALLY RUN: the declared
        // scope narrowed to the owner's reach. That narrowed scope is what the
        // evidence hash covers, so a grant change the definition version cannot
        // see still invalidates the memo.
        let definition = SavedQueryDefinition {
            scope: effective_scope,
            ..request.definition.clone()
        };
        let collected = match self.admitted_evidence(request, &definition)? {
            ControlFlow::Continue(collected) => collected,
            ControlFlow::Break(answer) => return Ok(answer),
        };
        let evidence_hash = compute_evidence_hash(&definition, &collected.evidence)?;
        // A held claim may only exclude, and under a negation its absence
        // would include: the row fails closed until its owner answers, before
        // any memo (the hash cannot see a hold) and without writing one.
        if collected.held {
            return Ok(unmemoized(
                no_match("a relevant claim awaits its critical confirm"),
                evidence_hash,
            ));
        }
        // So does a row the owner's read withholds, wherever it could change
        // the verdict: it is not absent, only unread, and the hash covers
        // only what was read.
        if hidden_undecides(&definition, &collected) {
            return Ok(unmemoized(
                no_match(SAVED_QUERY_WHY_DEPENDENCY_UNREADABLE),
                evidence_hash,
            ));
        }
        let key = VerdictMemoKey {
            query_ref: request.query_ref,
            entity_ref: request.entity_ref,
            evidence_hash,
        };
        if let Some(memo) = verdict_memo(self.vault, &key)? {
            return Ok(StagedOutcome {
                outcome: EvaluationOutcome {
                    decision: MatchDecision {
                        verdict: memo.verdict,
                        why: memo.why,
                    },
                    evidence_hash,
                    memo_hit: true,
                },
                judge_ran: false,
            });
        }

        let (decision, judge_ran) =
            if evaluate_filter(&definition.filter, &collected.evidence, &collected.hidden)
                == Some(true)
            {
                self.run_stage_two(request.query_ref, &definition, &collected)
                    .await?
            } else {
                (no_match("stage-1 filter did not match"), false)
            };

        put_verdict_memo(
            self.vault,
            &VerdictMemoRow {
                key,
                definition_version: definition.definition_version,
                verdict: decision.verdict,
                why: decision.why.clone(),
                envelope: derivation_envelope(&evidence_hash, &definition.matcher)?,
                evaluated_at: request.detected_at,
            },
        )?;
        Ok(StagedOutcome {
            outcome: EvaluationOutcome {
                decision,
                evidence_hash,
                memo_hit: false,
            },
            judge_ran,
        })
    }

    /// Stage 0 and the evidence, both read through the owner's lane, which is
    /// gone again before any stage awaits. `Break` is an answer reached
    /// before any evidence or memo.
    ///
    /// The owner must read the candidate, and the candidate must be INSIDE
    /// the effective scope. A closed intersection is not the only way to be
    /// out of reach — a query declared for world A must not enroll a person
    /// who lives in world B or in no world at all, however well that person's
    /// claims read. Neither answer is memoized: each is authority, read fresh
    /// every time.
    fn admitted_evidence(
        &self,
        request: &EvaluationRequest<'_>,
        definition: &SavedQueryDefinition,
    ) -> Result<ControlFlow<StagedOutcome, CollectedEvidence>> {
        let lane = self.owner_lane(&definition.scope)?;
        if !lane.is_entity_readable(&request.entity_ref)? {
            return Self::denied_outcome(request, SAVED_QUERY_WHY_ENTITY_UNREADABLE)
                .map(ControlFlow::Break);
        }
        let scope_membership =
            self.scope_membership(&lane, request.entity_ref, &definition.scope)?;
        if !definition.scope.admits(&scope_membership) {
            let evidence = RelevantEvidence {
                entity_ref: request.entity_ref,
                claim_values: Vec::new(),
                edge_targets: Vec::new(),
                semantic_inputs: Vec::new(),
                scope_membership,
            };
            return Ok(ControlFlow::Break(unmemoized(
                no_match(SAVED_QUERY_WHY_ENTITY_OUTSIDE_SCOPE),
                compute_evidence_hash(definition, &evidence)?,
            )));
        }
        self.collect_evidence(
            &lane,
            definition,
            request.entity_ref,
            request.valid_at,
            scope_membership,
        )
        .map(ControlFlow::Continue)
    }

    /// The owner's lane for one evaluation: its key, admitting claims of
    /// every status (the evaluator applies its own effective-truth rule),
    /// narrowed to the query's effective worlds so its dependencies keep to
    /// them too. Base reality stays readable: the candidate and the records
    /// its edges reach live there.
    fn owner_lane(&self, scope: &QueryScope) -> Result<ScopedRead<'_>> {
        // A room turn's receipt counts nothing withheld, so a hidden row
        // could not fail closed under it.
        if self.owner_read.room_turn().is_some() {
            return Err(invalid(
                "a saved query reads under its owner's own key, never a room turn",
            ));
        }
        let lane = self
            .vault
            .scoped_read(self.owner_read.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        if scope.worlds.is_empty() {
            return Ok(lane);
        }
        Ok(lane.within_worlds(crate::pipeline::WorldAuthoritySet::new(
            true,
            scope.worlds.iter().copied(),
        )?))
    }

    /// The closed-scope and unreadable-candidate answer: no evidence is read,
    /// no memo is touched, and the reported hash is the definition over an
    /// EMPTY evidence set — an honest statement that nothing was examined,
    /// and one that cannot collide with the hash of a verdict derived while
    /// the grant still held.
    fn denied_outcome(request: &EvaluationRequest<'_>, why: &str) -> Result<StagedOutcome> {
        let evidence = RelevantEvidence {
            entity_ref: request.entity_ref,
            claim_values: Vec::new(),
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        Ok(unmemoized(
            no_match(why),
            compute_evidence_hash(request.definition, &evidence)?,
        ))
    }

    /// Stage 2. Only ever called from the stage-1 success branch.
    async fn run_stage_two(
        &self,
        query_ref: EntityId,
        definition: &SavedQueryDefinition,
        collected: &CollectedEvidence,
    ) -> Result<(MatchDecision, bool)> {
        let evidence = &collected.evidence;
        match &definition.matcher {
            MatcherSpec::Hard { expression } => Ok((
                if evaluate_filter(expression, evidence, &collected.hidden) == Some(true) {
                    MatchDecision {
                        verdict: MatchVerdict::Match,
                        why: "hard matcher expression matched".to_owned(),
                    }
                } else {
                    no_match("hard matcher expression did not match")
                },
                false,
            )),
            MatcherSpec::SemanticThreshold {
                exemplar_ref,
                minimum_similarity_micros,
            } => Ok((
                semantic_decision(collected, *exemplar_ref, *minimum_similarity_micros),
                false,
            )),
            MatcherSpec::LlmJudge {
                model_id,
                rubric,
                rubric_version,
            } => {
                let binding = self.judge.as_ref().ok_or_else(|| {
                    invalid("saved query judge requires an injected backend and budget lease")
                })?;
                let shell = judge_request(binding.envelope, model_id, rubric, evidence)?;
                let decision = judge(
                    binding,
                    definition.owner_actor,
                    query_ref,
                    shell,
                    rubric,
                    rubric_version,
                    evidence,
                )
                .await?;
                Ok((decision, true))
            }
        }
    }

    /// Evaluates a bounded slice of a candidate set.
    ///
    /// Degrades with VISIBLE progress: when a bound stops the batch,
    /// [`WakeEvaluationReport::resume_after`] names where to continue. A query
    /// that outruns its budget is never silently disabled.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] when the query is absent; evaluation errors
    /// propagate.
    pub async fn evaluate_wake_batch(
        &self,
        query_ref: EntityId,
        candidates: &[EntityId],
        now: u64,
    ) -> Result<WakeEvaluationReport> {
        let record = load_record(self.vault, query_ref)?.ok_or(Error::EntityNotFound)?;
        let mut report = WakeEvaluationReport {
            evaluated: 0,
            memo_hits: 0,
            judges_run: 0,
            resume_after: None,
        };
        // `resume_after` names the last entity actually VISITED, tracked rather
        // than derived from the loop index: an index-relative "previous
        // candidate" reports `None` at index 0, and `None` is documented to
        // mean the candidate set was exhausted.
        let mut last_visited = None;
        for entity_ref in candidates {
            if report.evaluated >= record.definition.eval.max_entities_per_wake {
                report.resume_after = last_visited;
                return Ok(report);
            }
            let staged = self
                .evaluate_staged(&EvaluationRequest {
                    query_ref,
                    campaign_ref: query_ref,
                    entity_ref: *entity_ref,
                    definition: &record.definition,
                    cause: MembershipCause::DataChange,
                    valid_at: now,
                    detected_at: now,
                })
                .await?;
            report.evaluated = report.evaluated.saturating_add(1);
            last_visited = Some(*entity_ref);
            if staged.outcome.memo_hit {
                report.memo_hits = report.memo_hits.saturating_add(1);
            }
            if staged.judge_ran {
                report.judges_run = report.judges_run.saturating_add(1);
                if report.judges_run >= record.definition.eval.max_judges_per_wake {
                    report.resume_after = Some(*entity_ref);
                    return Ok(report);
                }
            }
        }
        Ok(report)
    }

    /// Reads the entity's effective claims and edges through the owner's
    /// lane, narrowed to the declared axes and to the effective scope, and
    /// notes each dependency the lane withheld.
    fn collect_evidence(
        &self,
        lane: &ScopedRead<'_>,
        definition: &SavedQueryDefinition,
        entity_ref: EntityId,
        valid_at: u64,
        scope_membership: QueryScope,
    ) -> Result<CollectedEvidence> {
        let deps = filter_dependencies(&definition.filter, &definition.matcher);
        let mut hidden = HiddenDependencies::default();
        let (claim_values, held) = self.relevant_claim_values(
            lane,
            entity_ref,
            &deps.claim_predicates,
            definition,
            valid_at,
            &mut hidden,
        )?;
        let edge_targets =
            self.relevant_edge_targets(lane, entity_ref, &deps.edge_kinds, &mut hidden)?;
        // Stage 0 admitted the candidate, so its own vector is the owner's to
        // read; an exemplar's only once the lane admits it.
        let subject_vector = if deps.semantic_exemplars.is_empty() {
            None
        } else {
            self.vault.get_vector(&entity_ref)?
        };
        let mut exemplar_vectors = Vec::with_capacity(deps.semantic_exemplars.len());
        let mut semantic_inputs = Vec::with_capacity(deps.semantic_exemplars.len());
        for exemplar in &deps.semantic_exemplars {
            let against = if lane.is_ref_readable(exemplar)? {
                self.vault.get_vector(exemplar)?
            } else {
                hidden.exemplars = true;
                None
            };
            semantic_inputs.push((
                *exemplar,
                vector_pair_fingerprint(&subject_vector, &against),
            ));
            exemplar_vectors.push((*exemplar, against));
        }
        Ok(CollectedEvidence {
            evidence: RelevantEvidence {
                entity_ref,
                claim_values,
                edge_targets,
                semantic_inputs,
                scope_membership,
            },
            held,
            hidden,
            subject_vector,
            exemplar_vectors,
        })
    }

    /// The entity's own world/facet membership, narrowed to `scope`, from
    /// the edges the owner's lane admits.
    ///
    /// Worlds come from `in_world` edges and facets from `has_facet` edges,
    /// with a facet spelled as its FACET entity's canonical hex — the same
    /// spelling `gate.rs` uses for a facet reference in a scoped-read grant.
    /// A withheld edge is no membership: it can only leave the entity out.
    fn scope_membership(
        &self,
        lane: &ScopedRead<'_>,
        entity_ref: EntityId,
        scope: &QueryScope,
    ) -> Result<QueryScope> {
        let mut worlds = Vec::new();
        if !scope.worlds.is_empty() {
            for edge in admitted_edges_out(lane, entity_ref, EdgeKind::InWorld)? {
                if scope.worlds.contains(&edge.target) {
                    worlds.push(edge.target);
                }
            }
        }
        let mut facets = Vec::new();
        if !scope.facets.is_empty() {
            for edge in admitted_edges_out(lane, entity_ref, EdgeKind::HasFacet)? {
                let token = edge.target.to_hex();
                if scope.facets.contains(&token) {
                    facets.push(token);
                }
            }
        }
        worlds.sort_unstable();
        worlds.dedup();
        facets.sort();
        facets.dedup();
        Ok(QueryScope { worlds, facets })
    }

    /// The relevant values, and whether a relevant claim is held.
    ///
    /// The claims about the entity are listed and read through the owner's
    /// lane; a claim it withholds marks the claims hidden. Each body is
    /// effective truth at `valid_at` (see [`claim_effective_at`]), and whether
    /// it is held is read on the SAME snapshot as the body: an owner's answer
    /// landing between two reads would pass a stale body.
    fn relevant_claim_values(
        &self,
        lane: &ScopedRead<'_>,
        entity_ref: EntityId,
        predicates: &[String],
        definition: &SavedQueryDefinition,
        valid_at: u64,
        hidden: &mut HiddenDependencies,
    ) -> Result<(Vec<(String, Value)>, bool)> {
        if predicates.is_empty() {
            return Ok((Vec::new(), false));
        }
        let listed = lane.neighborhood_projected(
            &entity_ref,
            Some(EdgeKind::ClaimOf),
            None,
            usize::MAX,
            |_, neighbors| {
                Ok::<_, Error>(neighbors.map(|rows| {
                    rows.into_iter()
                        .filter(|row| !row.outbound)
                        .map(|row| row.edge.target)
                        .collect::<Vec<EntityId>>()
                }))
            },
        )?;
        let Some(claim_refs) = listed.value else {
            hidden.claims = true;
            return Ok((Vec::new(), false));
        };
        if listed.receipt.suppressed_count > 0 {
            hidden.claims = true;
        }
        let reads: Vec<_> = claim_refs.iter().copied().map(PointRead::id).collect();
        let withheld = Cell::new(false);
        let read = lane.read_projected_opaque(
            &reads,
            None,
            |_, _| {
                withheld.set(true);
                Ok::<_, Error>(false)
            },
            |txn, rows| -> Result<(Vec<(String, Value)>, bool)> {
                let mut values = Vec::new();
                let mut held = false;
                for row in rows.into_iter().flatten() {
                    if row.entity_type != ENTITY_TYPE_CLAIM {
                        continue;
                    }
                    // An erased claim keeps a header-only shell: no claim.
                    let Some(raw) = row.body.filter(|body| !body.is_empty()) else {
                        continue;
                    };
                    let body = decode_claim_body(&raw, true)?;
                    if !claim_effective_at(&body, valid_at)
                        || !predicates.contains(&body.predicate)
                        || !claim_in_scope(&body, &definition.scope)
                    {
                        continue;
                    }
                    // Its value is withheld; `evaluate_staged` decides the row.
                    if !crate::gate::claim_critical_confirm_settled_in_txn(
                        &self.vault.store,
                        txn,
                        &row.id,
                    )? {
                        held = true;
                        continue;
                    }
                    values.push((body.predicate, rmpv_to_json(&body.value)));
                }
                Ok((values, held))
            },
        )?;
        if withheld.get() {
            hidden.claims = true;
        }
        let (mut values, held) = read.value;
        // Claim discovery order is edge-index order; the hash must not depend
        // on it.
        values.sort_by(|left, right| {
            (&left.0, left.1.to_string()).cmp(&(&right.0, right.1.to_string()))
        });
        Ok((values, held))
    }

    /// The targets of the entity's relevant edges, each edge admitted with
    /// both endpoints by the owner's lane; a kind with a withheld edge is
    /// hidden.
    fn relevant_edge_targets(
        &self,
        lane: &ScopedRead<'_>,
        entity_ref: EntityId,
        edge_kinds: &[String],
        hidden: &mut HiddenDependencies,
    ) -> Result<Vec<(String, EntityId)>> {
        let mut targets = Vec::new();
        for name in edge_kinds {
            let Some(kind) = edge_kind_from_name(name) else {
                continue;
            };
            let read = lane.edges_out_of_kind(&entity_ref, kind)?;
            if read.receipt.suppressed_count > 0 || read.value.is_none() {
                hidden.edge_kinds.insert(name.clone());
            }
            targets.extend(
                read.value
                    .into_iter()
                    .flatten()
                    .map(|edge| (name.clone(), edge.target)),
            );
        }
        if edge_kinds.iter().any(|kind| kind == "task_owner")
            && let Some(owner) = self.vault.indexed_task_owner(entity_ref)?
        {
            if lane.is_ref_readable(&owner)? {
                targets.push(("task_owner".to_owned(), owner));
            } else {
                hidden.edge_kinds.insert("task_owner".to_owned());
            }
        }
        targets.sort_unstable();
        Ok(targets)
    }
}

/// The entity's outbound edges of `kind` the lane admits, both endpoints
/// included; none when it withholds the entity itself.
fn admitted_edges_out(
    lane: &ScopedRead<'_>,
    entity_ref: EntityId,
    kind: EdgeKind,
) -> Result<Vec<crate::EdgeInfo>> {
    Ok(lane
        .edges_out_of_kind(&entity_ref, kind)?
        .value
        .unwrap_or_default())
}

/// Whether a dependency the owner's read withheld leaves this candidate's
/// verdict undecided: stage 1 or a hard matcher it could flip, a judge that
/// would read only the admitted part of the evidence, or an exemplar the
/// owner may not read.
fn hidden_undecides(definition: &SavedQueryDefinition, collected: &CollectedEvidence) -> bool {
    let hidden = &collected.hidden;
    if hidden.is_empty() {
        return false;
    }
    match evaluate_filter(&definition.filter, &collected.evidence, hidden) {
        None => true,
        Some(false) => false,
        Some(true) => match &definition.matcher {
            MatcherSpec::Hard { expression } => {
                evaluate_filter(expression, &collected.evidence, hidden).is_none()
            }
            MatcherSpec::SemanticThreshold { .. } => hidden.exemplars,
            MatcherSpec::LlmJudge { .. } => true,
        },
    }
}

/// An answer no memo records: authority, a hold, or an undecided row.
fn unmemoized(decision: MatchDecision, evidence_hash: [u8; EVIDENCE_HASH_LEN]) -> StagedOutcome {
    StagedOutcome {
        outcome: EvaluationOutcome {
            decision,
            evidence_hash,
            memo_hit: false,
        },
        judge_ran: false,
    }
}

/// Whether a claim contributes to standing state at `at`: the engine's
/// read-admission predicate plus the valid-time window.
pub(super) fn claim_effective_at(body: &ClaimBody, at: u64) -> bool {
    claim_surfaceable(body)
        && body.valid_from.is_none_or(|from| from <= at)
        && body.valid_to.is_none_or(|to| at <= to)
}

/// Whether a claim's WORLD scope is inside the query's effective scope.
///
/// A world-less claim is base reality and is admitted under any world axis —
/// the same rule `gate.rs`'s `scoped_read_world_matches_claim` applies to a
/// scoped-read grant. A claim scoped to a world OUTSIDE the axis is not
/// evidence this query may read at all.
pub(super) fn claim_in_scope(body: &ClaimBody, scope: &QueryScope) -> bool {
    match body.world {
        None => scope.worlds.is_empty() || scope.worlds.contains(&crate::claim::base_world_id()),
        Some(world) => scope.worlds.is_empty() || scope.worlds.contains(&world),
    }
}

/// Scores the vectors the evidence hash was taken from — never a re-read.
pub(super) fn semantic_decision(
    collected: &CollectedEvidence,
    exemplar_ref: EntityId,
    floor_micros: u32,
) -> MatchDecision {
    let exemplar = collected
        .exemplar_vectors
        .iter()
        .find(|(id, _)| *id == exemplar_ref)
        .and_then(|(_, vector)| vector.as_ref());
    let (Some(subject), Some(exemplar)) = (collected.subject_vector.as_ref(), exemplar) else {
        // No vector is not "dissimilar", it is unknowable — and an unknowable
        // similarity must not admit membership.
        return no_match("semantic matcher found no vector to compare");
    };
    let similarity = cosine_similarity_micros(subject, exemplar);
    if similarity >= floor_micros {
        MatchDecision {
            verdict: MatchVerdict::Match,
            why: format!("similarity {similarity} reached floor {floor_micros}"),
        }
    } else {
        no_match(&format!(
            "similarity {similarity} below floor {floor_micros}"
        ))
    }
}

/// Builds the judge's request from the host's envelope and the owner's rubric.
///
/// The system message IS the owner's rubric and the user message IS the
/// evidence, both as canonical JSON; the membership read and its note each add
/// their own turn after them. This module selects no provider.
fn judge_request(
    envelope: &CallEnvelope,
    model_id: &str,
    rubric: &Value,
    evidence: &RelevantEvidence,
) -> Result<LlmRequest> {
    let model = ModelId::new(model_id.to_owned())
        .map_err(|_| invalid("saved query judge model_id is not provider/name@revision"))?;
    Ok(LlmRequest {
        model,
        envelope: envelope.clone(),
        messages: vec![
            json_message(LlmMessageRole::System, rubric)?,
            json_message(LlmMessageRole::User, &evidence_to_json(evidence))?,
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    })
}

fn json_message(role: LlmMessageRole, value: &Value) -> Result<LlmMessage> {
    let bytes = canonical_json_bytes(value)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::InvariantViolation("canonical JSON is not UTF-8"))?;
    Ok(LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    })
}

/// The judge's view of the evidence.
///
/// Claims are PAIRS, not a predicate-keyed object: an entity can carry two live
/// values for one predicate, and a map would silently show the judge only the
/// last one while the evidence hash covered both. What the judge reads and what
/// the memo key hashes have to be the same evidence.
pub(super) fn evidence_to_json(evidence: &RelevantEvidence) -> Value {
    let pairs = |entries: &mut dyn Iterator<Item = (String, Value)>| {
        Value::Array(
            entries
                .map(|(left, right)| Value::Array(vec![Value::String(left), right]))
                .collect(),
        )
    };
    let mut root = JsonMap::new();
    root.insert(
        "entity".to_owned(),
        Value::String(evidence.entity_ref.to_hex()),
    );
    root.insert(
        "claims".to_owned(),
        pairs(
            &mut evidence
                .claim_values
                .iter()
                .map(|(predicate, value)| (predicate.clone(), value.clone())),
        ),
    );
    root.insert(
        "edges".to_owned(),
        pairs(
            &mut evidence
                .edge_targets
                .iter()
                .map(|(kind, target)| (kind.clone(), Value::String(target.to_hex()))),
        ),
    );
    Value::Object(root)
}

fn derivation_envelope(
    evidence_hash: &[u8; EVIDENCE_HASH_LEN],
    matcher: &MatcherSpec,
) -> Result<SavedQueryDerivationEnvelope> {
    let model_id = match matcher {
        MatcherSpec::Hard { .. } => "hard".to_owned(),
        MatcherSpec::SemanticThreshold { .. } => "semantic_threshold".to_owned(),
        MatcherSpec::LlmJudge { model_id, .. } => model_id.clone(),
    };
    let params = canonical_json_bytes(&matcher_to_json(matcher))?;
    Ok(SavedQueryDerivationEnvelope {
        content_hash: hex_lower(evidence_hash),
        model_id,
        version: EVALUATOR_VERSION.to_owned(),
        params_hash: hex_lower(&Sha256::digest(&params)),
    })
}

/// Every judge rejection names ONE tool, so an operator grepping for judge
/// failures finds all of them.
pub(super) fn judge_failure(code: String) -> Error {
    Error::UpstreamToolFailure {
        tool: "saved_query.judge",
        code,
    }
}

/// The stage-0 answer when the CANDIDATE ENTITY is not in the effective scope:
/// its world membership, read from the evidence, does not satisfy the saved
/// query's declared scope.
///
/// Named because it is one of two textually similar scope refusals whose
/// causes are different — this one is per-candidate and reads evidence, while
/// [`SAVED_QUERY_WHY_SCOPE_CLOSED`] is the whole query being shut out by the
/// owner's grants and reads nothing. A caller rendering a `NoMatch` memo has
/// to tell them apart, and `why` is persisted verbatim in
/// [`crate::saved_query::VerdictMemoRow`], so the text is fixed: this constant
/// names the existing bytes, it does not change them.
pub const SAVED_QUERY_WHY_ENTITY_OUTSIDE_SCOPE: &str = "entity is outside the effective scope";

/// The denied answer when the OWNER GRANTS close the effective scope: no
/// evidence is read and no memo is written.
///
/// The sibling of [`SAVED_QUERY_WHY_ENTITY_OUTSIDE_SCOPE`]; see it for why
/// both are named.
pub const SAVED_QUERY_WHY_SCOPE_CLOSED: &str = "effective scope is closed against owner grants";

/// The answer when the owner's read does not admit the candidate itself.
const SAVED_QUERY_WHY_ENTITY_UNREADABLE: &str =
    "entity is not readable under the owner's authority";

/// The answer when a row the verdict depends on is withheld from the owner.
const SAVED_QUERY_WHY_DEPENDENCY_UNREADABLE: &str =
    "a relevant row is not readable under the owner's authority";

fn no_match(why: &str) -> MatchDecision {
    MatchDecision {
        verdict: MatchVerdict::NoMatch,
        why: why.to_owned(),
    }
}

/// What visiting one candidate cost a wake: what a wake loop outside this
/// module (the campaign enrollment wake) counts against the query's
/// `max_entities_per_wake` and `max_judges_per_wake`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WakeVisit {
    /// The verdict came from the memo.
    pub(crate) memo_hit: bool,
    /// A stage-2 judge actually ran.
    pub(crate) judge_ran: bool,
}

impl SavedQueryEvaluator<'_> {
    /// [`Self::evaluate_entity`], plus what the evaluation cost a wake, so a
    /// wake built outside this module counts judges that ran rather than
    /// inferring them from the verdict.
    ///
    /// # Errors
    ///
    /// As [`Self::evaluate_entity`].
    pub(crate) async fn evaluate_entity_visit(
        &self,
        request: &EvaluationRequest<'_>,
    ) -> Result<(EvaluationOutcome, WakeVisit)> {
        let staged = self.evaluate_staged(request).await?;
        let visit = WakeVisit {
            memo_hit: staged.outcome.memo_hit,
            judge_ran: staged.judge_ran,
        };
        Ok((staged.outcome, visit))
    }
}
