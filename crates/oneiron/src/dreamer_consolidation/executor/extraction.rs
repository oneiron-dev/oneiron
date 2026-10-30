//! Extraction request/response projection for one admitted branch; the
//! typed pack that decides which listed claim each candidate corrects is
//! its `corrections` child.

use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, CandidateRel};
use crate::dreamer_consolidation::extracted_people::MintNamespace;
use crate::dreamer_consolidation::provenance::KeptDecision;

mod cited;
mod corrections;
mod decided;
mod quote_binding;
mod wire;
pub(in crate::dreamer_consolidation) use cited::CitationCheck;
use corrections::Correction;
pub(in crate::dreamer_consolidation) use quote_binding::{QuoteBinding, bind_quote};
pub(in crate::dreamer_consolidation) use wire::{
    CallPins, ExtractedPerson, ExtractionReply, ReplyContext, check_extraction_reply,
    contract_reply, decode_ref, disagreeing_child_hashes, extraction_reply, reply_json,
    resolve_subject,
};
use wire::{entity_id_from_hex, parse_candidate};

impl ConsolidationExecutor<'_> {
    /// The extraction request over one child's `transcript`, rendered with
    /// `labels` (FIX 7506): the map and the person-mint `namespace` bind
    /// into the request's identity, so its memo is read only against them.
    pub(in crate::dreamer_consolidation) fn extraction_request(
        call: &RoleCall<'_>,
        transcript: &str,
        labels: &CallLabelMap,
        scope: &crate::llm::Scope,
        namespace: &MintNamespace,
    ) -> Result<LlmRequest> {
        let mut request = Self::request_over(call, None, transcript.to_owned(), scope)?;
        labels.bind_request(&mut request, Some(&namespace.identity()));
        Ok(request)
    }

    /// The extraction request over `source`, `source_rule` before it: a
    /// NOTE review's rule is `note_classification`'s (OF-073).
    pub(in crate::dreamer_consolidation) fn request_over(
        call: &RoleCall<'_>,
        source_rule: Option<String>,
        source: String,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let locality = call.inference.selected_locality().ok_or_else(|| {
            crate::Error::InvalidConfig("consolidation host binding needs locality".into())
        })?;
        let keyless = call.inference.selected_keyless();
        let prompt: ExtractionPrompt = serde_json::from_str(include_str!("extraction_prompt.json"))
            .map_err(|_| invalid_consolidation("shipped extraction prompt is not readable"))?;
        let text = |role, text: String| LlmMessage {
            role,
            content: vec![ContentPart::Text { text }],
        };
        let mut messages = vec![text(LlmMessageRole::System, prompt.system)];
        for example in prompt.examples {
            messages.push(text(LlmMessageRole::User, example.user));
            messages.push(text(LlmMessageRole::Assistant, example.assistant));
        }
        if let Some(rule) = source_rule {
            messages.push(text(LlmMessageRole::System, rule));
        }
        messages.push(text(LlmMessageRole::User, source));
        Ok(LlmRequest {
            model: call.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: scope.clone(),
                purpose: CallPurpose::Extraction,
                class: CallClass::Durable {
                    fallback: crate::llm::DeterministicFallback {
                        name: "json_rules_v1".into(),
                        config: Some(
                            serde_json::json!({"version":1,"rows":[{"failure":"fatal","value":{"candidates":[],"persons":[],"fallback":"model_unavailable"}}]}),
                        ),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("consolidation".into()),
                ),
                // No schema on any wire: a grammar built from one can strip
                // the claim fields. The reply meets the contract here instead.
                response_format: ResponseFormat::Text,
                locality,
                host_keyless: keyless,
            }.with_purpose_defaults(),
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        })
    }

    /// The candidates one child's `scope` can take from `response`, before
    /// the claim each corrects is decided, and how many it cannot. Its
    /// labels, quotes and declared people bind through `ctx`, its call's
    /// own map. Each keeps `sources`, the rows of the call that produced
    /// it. Decode never fails the partition over one candidate: one it
    /// cannot take (a candidate breaking a rule such as the evidence rules,
    /// or one in a reply stored before the step checked candidates) is not
    /// written, and is counted.
    pub(in crate::dreamer_consolidation) fn parse_candidates<'s>(
        response: &LlmResponse,
        resources: &BranchResources<'_>,
        scope: &'s crate::llm::Scope,
        ctx: ReplyContext<'_>,
        sources: &[EntityId],
    ) -> Result<(Vec<ParsedCandidate<'s>>, usize)> {
        let items = extraction_reply(response)?.candidates;
        let items = items.as_slice();
        // A child hash is not part of the return contract. If a model still
        // reports one, compare it with our pinned source reread only to flag
        // an integrity failure. It never enters dedup or the write envelope.
        for source_id in disagreeing_child_hashes(resources, &ctx.call, items) {
            tracing::warn!(
                target: "oneiron::dreamer",
                child_integrity = "evidence_hash_mismatch",
                source_id = %source_id.to_hex(),
                "child evidence hash disagrees with the ledger"
            );
        }
        let mut parsed = Vec::new();
        let mut skipped = 0_usize;
        for item in items {
            match parse_candidate(item, ctx, scope) {
                Ok(mut candidate) => {
                    candidate.sources = sources.to_vec();
                    parsed.push(candidate);
                }
                Err(reason) => {
                    skipped += 1;
                    tracing::warn!(
                        target: "oneiron::dreamer",
                        %reason,
                        "extracted candidate not written"
                    );
                }
            }
        }
        Ok((parsed, skipped))
    }

    /// The candidates the branch takes, each bound to the claim it corrects
    /// and keeping its correction's decisions, and whether any candidate waits
    /// on a role's answer: that one is not taken this pass.
    pub(in crate::dreamer_consolidation) fn build_candidates(
        parsed: Vec<ParsedCandidate<'_>>,
        corrections: &[Correction],
        mut skipped: usize,
        partition: &BranchAxes,
        resources: &BranchResources<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        now_ms: u64,
    ) -> (Vec<super::super::evidence::ExtractedCandidate>, bool) {
        let mut candidates = Vec::new();
        let mut waiting = false;
        for (candidate, correction) in parsed.into_iter().zip(corrections) {
            // Read again when the attempt comes back for the answer.
            if correction.waiting() {
                waiting = true;
                continue;
            }
            match build_candidate(
                candidate, correction, partition, resources, attempt_id, now_ms,
            ) {
                Ok(candidate) => candidates.push(candidate),
                Err(reason) => {
                    skipped += 1;
                    tracing::warn!(
                        target: "oneiron::dreamer",
                        %reason,
                        "extracted candidate not written"
                    );
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                target: "oneiron::dreamer",
                skipped,
                taken = candidates.len(),
                "extraction reply had candidates the branch could not take"
            );
        }
        (candidates, waiting)
    }
}

/// One extracted candidate as the reply states it, its evidence checked
/// against its child's scope.
pub(in crate::dreamer_consolidation) struct ParsedCandidate<'s> {
    scope: &'s crate::llm::Scope,
    subject: EntityId,
    /// Its own predicate, when that meets the claim grammar.
    predicate: Option<String>,
    value: serde_json::Value,
    confidence: f32,
    /// Its `rel`, a listed relationship label read back to its id (FIX
    /// 7575), or any other value as the reply wrote it.
    rel: Option<CandidateRel>,
    topic: Option<serde_json::Value>,
    locators: Vec<super::super::evidence::EvidenceLocator>,
    evidence_turn_refs: Vec<EntityId>,
    project: EntityId,
    prospective_queries: Vec<String>,
    /// The rows of the extraction call that produced it (FIX 11526).
    sources: Vec<EntityId>,
}

impl ParsedCandidate<'_> {
    /// The rows of the extraction call that produced it.
    pub(in crate::dreamer_consolidation) fn sources(&self) -> &[EntityId] {
        &self.sources
    }
}

/// One parsed candidate as the branch takes it, or why it is not written.
/// A candidate that corrects a listed claim binds to that head: its subject,
/// predicate, relationship and topic, so it routes to the head through the
/// conflict and grant doors, and the verdict skips it.
fn build_candidate(
    parsed: ParsedCandidate<'_>,
    correction: &Correction,
    partition: &BranchAxes,
    resources: &BranchResources<'_>,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<super::super::evidence::ExtractedCandidate> {
    let corrects = correction
        .corrects
        .map(|claim| resources.prior(claim))
        .transpose()?;
    build_resolved(
        parsed,
        corrects,
        &correction.decisions,
        partition,
        attempt_id,
        now_ms,
    )
}

/// [`build_candidate`] once the head it corrects, if any, is read.
fn build_resolved(
    parsed: ParsedCandidate<'_>,
    corrects: Option<&crate::dreamer_consolidation::PriorHead>,
    decisions: &[KeptDecision],
    partition: &BranchAxes,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<super::super::evidence::ExtractedCandidate> {
    let sources = Some(parsed.sources().to_vec());
    let (proposal, locators) =
        resolve_proposal(parsed, corrects, decisions, partition, attempt_id, now_ms)?;
    let extracted =
        super::super::evidence::ExtractedCandidate::new(proposal, locators)?.with_sources(sources);
    // Only a head the listing shows is a correction target.
    Ok(match corrects {
        Some(prior) => extracted.correcting(prior.claim_id),
        None => extracted,
    })
}

/// [`build_resolved`]'s proposal and its evidence before they join: what
/// the extraction step's citation check (FIX 7274) builds with no
/// correction to tell whether a candidate would build (FIX 7506).
fn resolve_proposal(
    parsed: ParsedCandidate<'_>,
    corrects: Option<&crate::dreamer_consolidation::PriorHead>,
    decisions: &[KeptDecision],
    partition: &BranchAxes,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<(
    PromotionCandidate,
    Vec<super::super::evidence::EvidenceLocator>,
)> {
    let scope = parsed.scope;
    let (subject, predicate) = match corrects {
        Some(prior) => {
            let ClaimSubject::Entity(subject) = prior.body.subject else {
                return Err(invalid_consolidation(
                    "extracted correction names a claim with no entity subject",
                ));
            };
            if parsed.subject != subject {
                return Err(invalid_consolidation(
                    "extracted correction names a claim about another subject",
                ));
            }
            (subject, prior.body.predicate.as_str())
        }
        None => (
            parsed.subject,
            parsed.predicate.as_deref().ok_or_else(|| {
                invalid_consolidation("extracted candidate's predicate breaks the claim grammar")
            })?,
        ),
    };
    let value = json_to_rmpv(&parsed.value);
    let rel = match (corrects, parsed.rel) {
        (Some(prior), _) => prior.body.rel.clone(),
        (None, None) => scope.relationship.clone(),
        // A relationship the call listed, by its label (FIX 7575).
        (None, Some(CandidateRel::Listed(rel))) => crate::claim::relationship_scope_of(Some(rel)),
        // A value that is no listed label is read as before.
        (None, Some(CandidateRel::Unlisted(value))) => crate::claim::relationship_scope_of(Some(
            value
                .as_str()
                .and_then(entity_id_from_hex)
                .ok_or_else(|| invalid_consolidation("invalid relationship ref"))?,
        )),
    };
    // A bound branch writes inside its relationship set: the whole set or a
    // narrower one, never a relationship outside it or `all`.
    if let Some(bound) = &scope.relationship
        && !rel.as_ref().is_some_and(|rel| rel.is_subset(bound))
    {
        return Err(invalid_consolidation(
            "extraction relationship crossed branch scope",
        ));
    }
    let mut candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        parsed.confidence,
    )
    .with_lexical_hints(parsed.prospective_queries);
    candidate = candidate.with_relationships(rel.clone());
    if let Some(world) = partition.world_ref {
        candidate = candidate.with_world(world);
    }
    let mut fields = Vec::new();
    if let Some(facet) = partition.facet_ref {
        fields.push((
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        ));
    }
    let topic = match corrects {
        Some(prior) => prior_topic(prior.body.scope.as_ref()),
        None => parsed.topic.as_ref().map(json_to_rmpv),
    };
    if let Some(topic) = topic {
        fields.push((Value::from("topic_key"), topic));
    }
    if parsed.project != crate::claim::default_project_id() {
        fields.push((
            Value::from(SCOPE_PROJECT_KEY),
            Value::Binary(parsed.project.as_bytes().to_vec()),
        ));
    }
    if !fields.is_empty() {
        candidate = candidate.with_scope(Value::Map(fields));
    }
    let facts = candidate_facts(&candidate)?;
    let claim_id = deterministic_claim_id(
        attempt_id,
        subject,
        predicate,
        &facts.value,
        partition.world_ref,
        partition.facet_ref,
        rel.as_ref(),
        facts.project,
        facts.topic.as_deref(),
    )?;
    // The wake's clock is milliseconds; a claim's times are Unix seconds
    // (FIX 8695).
    let at = now_ms / 1_000;
    Ok((
        PromotionCandidate {
            claim_id,
            candidate,
            evidence_turn_refs: parsed.evidence_turn_refs,
            // Extraction output from the working set carries no external
            // chain; a peer-derived candidate gets its hops from
            // `peer_answer_provenance_chain` at the landing seam.
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: ClaimSource::Generated,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            decisions: decisions.to_vec(),
        },
        parsed.locators,
    ))
}

/// The shipped extraction prompt, as data: the system text and the worked
/// examples sent as user and assistant turns before the transcript.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractionPrompt {
    system: String,
    examples: Vec<WorkedExample>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkedExample {
    user: String,
    assistant: String,
}

/// The question key a stored head was filed under, as its scope map holds it.
fn prior_topic(scope: Option<&Value>) -> Option<Value> {
    let Some(Value::Map(fields)) = scope else {
        return None;
    };
    fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("topic_key")).then(|| value.clone()))
}
