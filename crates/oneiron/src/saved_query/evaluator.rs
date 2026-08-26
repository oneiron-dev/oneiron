use std::collections::BTreeMap;

use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::claim::{ClaimBody, claim_surfaceable, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    BudgetLease, CallEnvelope, ContentPart, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId,
};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::definition::{QueryScope, SavedQueryDefinition};
use super::evidence::{
    EVIDENCE_HASH_LEN, EvaluationOutcome, MatchDecision, MatchVerdict, RelevantEvidence,
    SavedQueryDerivationEnvelope, VerdictMemoKey, VerdictMemoRow, WakeEvaluationReport,
    compute_evidence_hash, put_verdict_memo, verdict_memo,
};
use super::filter::{MatcherSpec, evaluate_filter, filter_dependencies};
use super::membership::MembershipCause;
use super::storage::{load_record, matcher_to_json};
use super::support::{
    EVALUATOR_VERSION, MAX_TEXT_BYTES, canonical_json_bytes, cosine_similarity_micros,
    edge_kind_from_name, hex_lower, invalid, rmpv_to_json, vector_pair_fingerprint,
};

/// The LLM dependency of a rubric-driven judge.
///
/// Backend, budget lease, and call envelope travel as ONE binding so no caller
/// can present a backend without a lease: the admission token is not an
/// optional decoration on the call, it is half of what makes the call legal.
pub struct SavedQueryJudgeBinding<'a> {
    /// Host-injected backend.
    pub backend: &'a dyn LlmBackend,
    /// Budget admission token.
    pub lease: &'a BudgetLease,
    /// Host-owned call envelope. Model policy is the host's, not this module's.
    pub envelope: &'a CallEnvelope,
}

/// Staged evaluator over one vault.
///
/// `owner_grants` is the saved query owner's reach AT EVALUATION TIME. There is
/// deliberately no viewer/caller principal on this struct: a viewer cannot
/// change membership because a viewer is not an input to it.
pub struct SavedQueryEvaluator<'a> {
    /// Vault the evidence is read from.
    pub vault: &'a Vault,
    /// The owner's reach; intersected with the definition's declared scope.
    pub owner_grants: &'a QueryScope,
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
    pub(super) subject_vector: Option<Vec<f32>>,
    pub(super) exemplar_vectors: Vec<(EntityId, Option<Vec<f32>>)>,
}

impl SavedQueryEvaluator<'_> {
    /// Evaluates one entity against one definition.
    ///
    /// Order is the cost model: scope gate, evidence, memo, stage 1, stage 2.
    /// Stage 2 is reached from exactly one place — inside the stage-1 success
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
            return Self::denied_outcome(request);
        };

        // Evaluate against the definition AS IT WILL ACTUALLY RUN: the declared
        // scope narrowed to the owner's reach. That narrowed scope is what the
        // evidence hash covers, so a grant change the definition version cannot
        // see still invalidates the memo.
        let definition = SavedQueryDefinition {
            scope: effective_scope,
            ..request.definition.clone()
        };
        let collected = self.collect_evidence(&definition, request.entity_ref, request.valid_at)?;
        let evidence_hash = compute_evidence_hash(&definition, &collected.evidence)?;
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

        // Stage 0: the entity must be INSIDE the effective scope. A closed
        // intersection is not the only way to be out of reach — a query
        // declared for world A must not enroll a person who lives in world B or
        // in no world at all, however well that person's claims read. The
        // entity's membership is in the evidence hash, so joining or leaving a
        // world invalidates this verdict instead of freezing it.
        let (decision, judge_ran) = if definition
            .scope
            .admits(&collected.evidence.scope_membership)
        {
            if evaluate_filter(&definition.filter, &collected.evidence) {
                self.run_stage_two(&definition, &collected).await?
            } else {
                (no_match("stage-1 filter did not match"), false)
            }
        } else {
            (no_match("entity is outside the effective scope"), false)
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

    /// The closed-scope answer: no evidence is read, no memo is touched, and the
    /// reported hash is the definition over an EMPTY evidence set — an honest
    /// statement that nothing was examined, and one that cannot collide with the
    /// hash of a verdict derived while the grant still held.
    fn denied_outcome(request: &EvaluationRequest<'_>) -> Result<StagedOutcome> {
        let evidence = RelevantEvidence {
            entity_ref: request.entity_ref,
            claim_values: Vec::new(),
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        Ok(StagedOutcome {
            outcome: EvaluationOutcome {
                decision: no_match("effective scope is closed against owner grants"),
                evidence_hash: compute_evidence_hash(request.definition, &evidence)?,
                memo_hit: false,
            },
            judge_ran: false,
        })
    }

    /// Stage 2. Only ever called from the stage-1 success branch.
    async fn run_stage_two(
        &self,
        definition: &SavedQueryDefinition,
        collected: &CollectedEvidence,
    ) -> Result<(MatchDecision, bool)> {
        let evidence = &collected.evidence;
        match &definition.matcher {
            MatcherSpec::Hard { expression } => Ok((
                if evaluate_filter(expression, evidence) {
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
                model_id, rubric, ..
            } => {
                let judge = self.judge.as_ref().ok_or_else(|| {
                    invalid("saved query judge requires an injected backend and budget lease")
                })?;
                let request = judge_request(judge.envelope, model_id, rubric, evidence)?;
                let decision = run_llm_judge(judge.backend, judge.lease, request).await?;
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

    /// Reads the entity's effective claims and edges, narrowed to the declared
    /// axes and to the effective scope.
    fn collect_evidence(
        &self,
        definition: &SavedQueryDefinition,
        entity_ref: EntityId,
        valid_at: u64,
    ) -> Result<CollectedEvidence> {
        let deps = filter_dependencies(&definition.filter, &definition.matcher);
        let scope_membership = self.scope_membership(entity_ref, &definition.scope)?;
        let claim_values =
            self.relevant_claim_values(entity_ref, &deps.claim_predicates, definition, valid_at)?;
        let edge_targets = self.relevant_edge_targets(entity_ref, &deps.edge_kinds)?;
        let subject_vector = if deps.semantic_exemplars.is_empty() {
            None
        } else {
            self.vault.get_vector(&entity_ref)?
        };
        let mut exemplar_vectors = Vec::with_capacity(deps.semantic_exemplars.len());
        let mut semantic_inputs = Vec::with_capacity(deps.semantic_exemplars.len());
        for exemplar in &deps.semantic_exemplars {
            let against = self.vault.get_vector(exemplar)?;
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
            subject_vector,
            exemplar_vectors,
        })
    }

    /// The entity's own world/facet membership, narrowed to `scope`.
    ///
    /// Worlds come from `in_world` edges and facets from `has_facet` edges,
    /// with a facet spelled as its FACET entity's canonical hex — the same
    /// spelling `gate.rs` uses for a facet reference in a scoped-read grant.
    fn scope_membership(&self, entity_ref: EntityId, scope: &QueryScope) -> Result<QueryScope> {
        if scope.worlds.is_empty() && scope.facets.is_empty() {
            return Ok(QueryScope::default());
        }
        let mut worlds = Vec::new();
        let mut facets = Vec::new();
        for edge in self.vault.edges_out(&entity_ref)? {
            match edge.kind {
                EdgeKind::InWorld if scope.worlds.contains(&edge.target) => {
                    worlds.push(edge.target);
                }
                EdgeKind::HasFacet => {
                    let token = edge.target.to_hex();
                    if scope.facets.contains(&token) {
                        facets.push(token);
                    }
                }
                _ => {}
            }
        }
        worlds.sort_unstable();
        worlds.dedup();
        facets.sort();
        facets.dedup();
        Ok(QueryScope { worlds, facets })
    }

    fn relevant_claim_values(
        &self,
        entity_ref: EntityId,
        predicates: &[String],
        definition: &SavedQueryDefinition,
        valid_at: u64,
    ) -> Result<Vec<(String, Value)>> {
        if predicates.is_empty() {
            return Ok(Vec::new());
        }
        let mut values = Vec::new();
        for edge in self.vault.edges_in(&entity_ref)? {
            if edge.kind != EdgeKind::ClaimOf {
                continue;
            }
            let Some(body) = self.effective_claim_body(&edge.target, valid_at)? else {
                continue;
            };
            if predicates.contains(&body.predicate) && claim_in_scope(&body, &definition.scope) {
                values.push((body.predicate, rmpv_to_json(&body.value)));
            }
        }
        // Claim discovery order is edge-index order; the hash must not depend
        // on it.
        values.sort_by(|left, right| {
            (&left.0, left.1.to_string()).cmp(&(&right.0, right.1.to_string()))
        });
        Ok(values)
    }

    /// The claim body at `claim_ref` IF it is effective truth at `valid_at`.
    ///
    /// "Active" alone is not effective: an `Active` `Proposed` claim is an
    /// unapproved suggestion, a `stale` derived claim is known to be behind its
    /// source, and a claim whose valid-time window has not opened (or has
    /// closed) is not true now. Membership derived from any of those would
    /// enroll a person on evidence the rest of the engine refuses to read, so
    /// this mirrors `claim.rs`'s `claim_surfaceable` plus `comm.rs`'s
    /// valid-time window rather than inventing a looser rule.
    fn effective_claim_body(
        &self,
        claim_ref: &EntityId,
        valid_at: u64,
    ) -> Result<Option<ClaimBody>> {
        if self.vault.get_entity_type(claim_ref)? != Some(ENTITY_TYPE_CLAIM) {
            return Ok(None);
        }
        let Some(raw) = self.vault.get(claim_ref)? else {
            return Ok(None);
        };
        let body = decode_claim_body(&raw, true)?;
        Ok(claim_effective_at(&body, valid_at).then_some(body))
    }

    fn relevant_edge_targets(
        &self,
        entity_ref: EntityId,
        edge_kinds: &[String],
    ) -> Result<Vec<(String, EntityId)>> {
        if edge_kinds.is_empty() {
            return Ok(Vec::new());
        }
        let wanted = edge_kinds
            .iter()
            .filter_map(|name| edge_kind_from_name(name).map(|kind| (kind, name.clone())))
            .collect::<Vec<(EdgeKind, String)>>();
        let mut targets = self
            .vault
            .edges_out(&entity_ref)?
            .into_iter()
            .filter_map(|edge| {
                wanted
                    .iter()
                    .find(|(kind, _)| *kind == edge.kind)
                    .map(|(_, name)| (name.clone(), edge.target))
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        Ok(targets)
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
        None => true,
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

/// Adjudicates one rubric through a host-injected backend.
///
/// The backend and the lease are both required arguments, so a judged verdict
/// cannot be produced without budget admission. The response must be a JSON
/// object naming a closed-set verdict; free prose is a decode failure, not a
/// coin flip.
///
/// # Errors
///
/// [`Error::UpstreamToolFailure`] when the backend fails or answers off-schema.
pub async fn run_llm_judge(
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    request: LlmRequest,
) -> Result<MatchDecision> {
    let response = backend
        .generate(request, lease)
        .await
        .map_err(|error| judge_failure(error.to_string()))?;
    let text = response
        .message
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .ok_or_else(|| judge_failure("response carried no text part".to_owned()))?;
    decode_judge_decision(text)
}

pub(super) fn decode_judge_decision(text: &str) -> Result<MatchDecision> {
    let parsed = serde_json::from_str::<Value>(text)
        .map_err(|_| judge_failure("response is not JSON".to_owned()))?;
    let verdict = parsed
        .get("verdict")
        .and_then(Value::as_str)
        .and_then(MatchVerdict::parse)
        .ok_or_else(|| judge_failure("verdict is not match/no_match".to_owned()))?;
    let why = parsed
        .get("why")
        .and_then(Value::as_str)
        .ok_or_else(|| judge_failure("response carried no why".to_owned()))?;
    Ok(MatchDecision {
        verdict,
        why: why.chars().take(MAX_TEXT_BYTES).collect(),
    })
}

/// Builds the judge request from the host's envelope and the owner's rubric.
///
/// No prompt text is authored here: the system message IS the owner's rubric
/// and the user message IS the evidence, both as canonical JSON. This module
/// selects no provider and writes no instructions.
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
fn judge_failure(code: String) -> Error {
    Error::UpstreamToolFailure {
        tool: "saved_query.judge",
        code,
    }
}

fn no_match(why: &str) -> MatchDecision {
    MatchDecision {
        verdict: MatchVerdict::NoMatch,
        why: why.to_owned(),
    }
}
