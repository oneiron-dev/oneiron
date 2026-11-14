//! Extraction request/response projection for one admitted branch; the
//! typed pack that decides which listed claim each candidate corrects is
//! its `corrections` child.

use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, CandidateRel};
use crate::dreamer_consolidation::extracted_people::MintNamespace;
use crate::dreamer_consolidation::provenance::KeptDecision;

pub(in crate::dreamer_consolidation) use super::decisions::identity_choice::identity_round_specs;
pub(in crate::dreamer_consolidation) use super::decisions::{
    ChoiceSpec, ConflictRows, DecisionKeyPart, NONE, PartMark, key_part_bytes, key_part_text,
    page_or_whole,
};
pub(in crate::dreamer_consolidation) use super::merge_resolution::{
    ESCALATE, RESOLUTIONS, conflict_identity_specs, resolution_choice_spec, resolution_final_prep,
    resolution_spans_predicates,
};

mod cited;
pub(in crate::dreamer_consolidation) mod corrections;
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
use wire::{authored_fallback, entity_id_from_hex, parse_candidate};

impl ConsolidationExecutor<'_> {
    /// The extraction request over one child's `transcript`, rendered with
    /// `labels` (FIX 7506): the map and the person-mint `namespace` bind
    /// into the request's identity, so its memo is read only against them.
    pub(in crate::dreamer_consolidation) fn extraction_request(
        call: &RoleCall<'_>,
        prompt: &ExtractionPrompt,
        transcript: &str,
        labels: &CallLabelMap,
        scope: &oneiron_model::llm::Scope,
        namespace: &MintNamespace,
    ) -> Result<LlmRequest> {
        let mut request = Self::request_over(call, prompt, None, transcript.to_owned(), scope)?;
        labels.bind_request(&mut request, Some(&namespace.identity()));
        Ok(request)
    }

    /// The extraction request over `source` in `prompt`'s words, `source_rule`
    /// before it: a NOTE review's rule is `note_classification`'s (OF-073).
    pub(in crate::dreamer_consolidation) fn request_over(
        call: &RoleCall<'_>,
        prompt: &ExtractionPrompt,
        source_rule: Option<String>,
        source: String,
        scope: &oneiron_model::llm::Scope,
    ) -> Result<LlmRequest> {
        let locality = call.inference.selected_locality().ok_or_else(|| {
            crate::Error::InvalidConfig("consolidation host binding needs locality".into())
        })?;
        let keyless = call.inference.selected_keyless();
        let paid = call.inference.selected_paid();
        let text = |role, text: String| LlmMessage {
            role,
            content: vec![ContentPart::Text {
                text,
                signature: None,
            }],
        };
        let mut messages = vec![text(LlmMessageRole::System, prompt.system.clone())];
        for example in &prompt.examples {
            messages.push(text(LlmMessageRole::User, example.user.clone()));
            messages.push(text(LlmMessageRole::Assistant, example.assistant.clone()));
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
                    fallback: oneiron_model::llm::DeterministicFallback {
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
                host_paid: paid,
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
        scope: &'s oneiron_model::llm::Scope,
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
        let authored = authored_fallback(response);
        let mut parsed = Vec::new();
        let mut skipped = 0_usize;
        for item in items {
            match parse_candidate(item, ctx, scope, authored) {
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
    scope: &'s oneiron_model::llm::Scope,
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

/// One candidate's proposed relationship as plain assembly input: the branch
/// set it inherits, or the narrower set it narrows to.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) enum PackRelationship {
    /// No proposed relationship: the candidate inherits its scope's set.
    Inherit,
    /// The proposed relationship ids, narrowed inside the scope's set.
    Set(Vec<EntityId>),
}

/// The listed head a candidate corrects, as identity assembly takes it: the
/// head's own subject, predicate, relationship set and topic, which the
/// candidate binds to through the conflict and grant doors.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct CorrectsPrior {
    /// The head's entity subject, which the operand repeats.
    pub(in crate::dreamer_consolidation) subject: EntityId,
    /// The head predicate, which the operand repeats.
    pub(in crate::dreamer_consolidation) predicate: String,
    /// The head relationship set.
    pub(in crate::dreamer_consolidation) rel: crate::claim::RelationshipScope,
    /// The head topic as its scope map holds it, when it holds one.
    pub(in crate::dreamer_consolidation) topic: Option<Value>,
}

impl CorrectsPrior {
    /// `head` as a correction target: its entity subject with its predicate,
    /// relationship set and filed topic. A head with no entity subject is no
    /// correction target.
    pub(in crate::dreamer_consolidation) fn from_head(
        head: &crate::dreamer_consolidation::PriorHead,
    ) -> Result<Self> {
        let crate::claim::ClaimSubject::Entity(subject) = head.body.subject else {
            return Err(invalid_consolidation(
                "extracted correction names a claim with no entity subject",
            ));
        };
        Ok(Self {
            subject,
            predicate: head.body.predicate.clone(),
            rel: head.body.rel.clone(),
            topic: prior_topic(head.body.scope.as_ref()),
        })
    }
}

/// One candidate's identity as plain assembly input: what native parsing and
/// the bound pack both project before the claim below is built.
#[derive(Debug, Clone)]
pub(in crate::dreamer_consolidation) struct CandidateAssemblyInput<'a> {
    /// The operand subject.
    pub(in crate::dreamer_consolidation) subject: EntityId,
    /// The operand predicate, when it carries one to check: native passes
    /// none while correcting, since it binds the head predicate unwatched,
    /// and the bound path always passes its checked predicate, which must
    /// repeat the head predicate while correcting.
    pub(in crate::dreamer_consolidation) predicate: Option<&'a str>,
    /// The proposed value as JSON.
    pub(in crate::dreamer_consolidation) value: &'a serde_json::Value,
    /// The proposed relationship.
    pub(in crate::dreamer_consolidation) rel: PackRelationship,
    /// The proposed topic, when it carries one.
    pub(in crate::dreamer_consolidation) topic: Option<&'a serde_json::Value>,
    /// The head it corrects, when it corrects one.
    pub(in crate::dreamer_consolidation) corrects: Option<CorrectsPrior>,
    /// The extraction confidence the assembled claim carries.
    pub(in crate::dreamer_consolidation) confidence: f32,
    /// The prospective query hints the assembled claim carries.
    pub(in crate::dreamer_consolidation) lexical_hints: Vec<String>,
    /// The project its sources share.
    pub(in crate::dreamer_consolidation) project: EntityId,
    /// The partition world axis, when the branch names one.
    pub(in crate::dreamer_consolidation) world: Option<EntityId>,
    /// The partition facet axis, when the branch names one.
    pub(in crate::dreamer_consolidation) facet: Option<EntityId>,
    /// The scope relationship set it assembles inside, when bound.
    pub(in crate::dreamer_consolidation) scope_relationship: Option<&'a BTreeSet<EntityId>>,
}

/// `input` as the identity claim native building and the bound check derive
/// the same id from: the corrected head's subject, predicate, relationship
/// set and topic while correcting, else the operand's own, with the
/// relationship checked inside the bound set and the world, facet, topic and
/// project stamped as native stamps them.
pub(in crate::dreamer_consolidation) fn assemble_identity_candidate(
    input: &CandidateAssemblyInput<'_>,
) -> Result<ClaimCandidate> {
    let (subject, predicate) = match &input.corrects {
        Some(prior) => {
            if input.subject != prior.subject {
                return Err(invalid_consolidation(
                    "extracted correction names a claim about another subject",
                ));
            }
            if let Some(echo) = input.predicate
                && echo != prior.predicate
            {
                return Err(invalid_consolidation(
                    "extracted correction predicate differs from its corrected claim",
                ));
            }
            (prior.subject, prior.predicate.clone())
        }
        None => (
            input.subject,
            input
                .predicate
                .ok_or_else(|| {
                    invalid_consolidation(
                        "extracted candidate's predicate breaks the claim grammar",
                    )
                })?
                .to_owned(),
        ),
    };
    // No grammar check here: native wire parsing validated a supplied
    // predicate already, and a corrected prior's predicate is never
    // revalidated (it may reserve namespaces); the bound check validates its
    // own operand before assembly.
    let value = json_to_rmpv(input.value);
    let rel = match (&input.corrects, &input.rel) {
        (Some(prior), _) => prior.rel.clone(),
        (None, PackRelationship::Inherit) => input
            .scope_relationship
            .map(|ids| ids.iter().copied().collect()),
        (None, PackRelationship::Set(ids)) => Some(ids.iter().copied().collect()),
    };
    // A bound branch writes inside its relationship set: the whole set or a
    // narrower one, never a relationship outside it or `all`.
    if let Some(bound) = input.scope_relationship
        && !rel
            .as_ref()
            .is_some_and(|rel| rel.iter().all(|id| bound.contains(id)))
    {
        return Err(invalid_consolidation(
            "extraction relationship crossed branch scope",
        ));
    }
    let mut candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        input.confidence,
    )
    .with_lexical_hints(input.lexical_hints.clone());
    candidate = candidate.with_relationships(rel);
    if let Some(world) = input.world {
        candidate = candidate.with_world(world);
    }
    let mut fields = Vec::new();
    if let Some(facet) = input.facet {
        fields.push((
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        ));
    }
    let topic = match &input.corrects {
        Some(prior) => prior.topic.clone(),
        None => input.topic.map(json_to_rmpv),
    };
    if let Some(topic) = topic {
        fields.push((Value::from("topic_key"), topic));
    }
    if input.project != crate::claim::default_project_id() {
        fields.push((
            Value::from(SCOPE_PROJECT_KEY),
            Value::Binary(input.project.as_bytes().to_vec()),
        ));
    }
    if !fields.is_empty() {
        candidate = candidate.with_scope(Value::Map(fields));
    }
    Ok(candidate)
}

/// The deterministic claim id `candidate` writes under in `attempt`: the
/// native id over its stamped subject, predicate, value, world, facet,
/// relationship set, project and topic. Native building and the bound check
/// derive through this function from the same assembled claim.
pub(in crate::dreamer_consolidation) fn claim_id_for_identity(
    attempt: crate::attempt_queue::AttemptId,
    candidate: &ClaimCandidate,
) -> Result<EntityId> {
    let facts = candidate_facts(candidate)?;
    deterministic_claim_id(
        attempt,
        facts.subject,
        &facts.predicate,
        &facts.value,
        facts.world,
        facts.facet,
        facts.rel.as_ref(),
        facts.project,
        facts.topic.as_deref(),
    )
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
    let corrects = corrects.map(CorrectsPrior::from_head).transpose()?;
    let (candidate, claim_id) = {
        let rel = match (&corrects, &parsed.rel) {
            (Some(_), _) | (None, None) => PackRelationship::Inherit,
            // A relationship the call listed, by its label (FIX 7575).
            (None, Some(CandidateRel::Listed(rel))) => PackRelationship::Set(vec![*rel]),
            // A value that is no listed label is read as before.
            (None, Some(CandidateRel::Unlisted(value))) => PackRelationship::Set(vec![
                value
                    .as_str()
                    .and_then(entity_id_from_hex)
                    .ok_or_else(|| invalid_consolidation("invalid relationship ref"))?,
            ]),
        };
        let input = CandidateAssemblyInput {
            subject: parsed.subject,
            predicate: match &corrects {
                Some(_) => None,
                None => parsed.predicate.as_deref(),
            },
            value: &parsed.value,
            rel,
            topic: parsed.topic.as_ref(),
            corrects,
            confidence: parsed.confidence,
            lexical_hints: parsed.prospective_queries.clone(),
            project: parsed.project,
            world: partition.world_ref,
            facet: partition.facet_ref,
            scope_relationship: parsed.scope.relationship.as_ref(),
        };
        let candidate = assemble_identity_candidate(&input)?;
        let claim_id = claim_id_for_identity(attempt_id, &candidate)?;
        (candidate, claim_id)
    };
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

/// The extraction prompt, as data: the system text and the worked examples
/// sent as user and assistant turns before the transcript. Every extraction
/// and NOTE review asks in these words. The engine ships one
/// ([`Self::shipped`]); a host asks in its own ([`Self::from_json`]), since
/// prompts belong to the host layer (ARCH-0026 #dreamer-seat-open, ARCH-0053
/// OF-334). Only the words change: the reply contract, its check and the
/// decode stay the engine's.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionPrompt {
    system: String,
    examples: Vec<WorkedExample>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkedExample {
    user: String,
    assistant: String,
}

impl ExtractionPrompt {
    /// The shipped prompt (`extraction_prompt.json`), word for word what the
    /// engine asks with when the host words none.
    ///
    /// # Errors
    /// The shipped file does not read.
    pub fn shipped() -> Result<Self> {
        Self::from_json(include_str!("extraction_prompt.json"))
            .map_err(|_| invalid_consolidation("shipped extraction prompt is not readable"))
    }

    /// A prompt written in the shipped file's shape: `{"system": "...",
    /// "examples": [{"user": "...", "assistant": "..."}]}`. The examples may
    /// be empty.
    ///
    /// # Errors
    /// [`crate::Error::InvalidConfig`]: `text` is not that shape, names
    /// another key, or leaves the system text or a turn of an example blank.
    pub fn from_json(text: &str) -> Result<Self> {
        let prompt: Self = serde_json::from_str(text)
            .map_err(|error| crate::Error::InvalidConfig(format!("extraction prompt: {error}")))?;
        if prompt.system.trim().is_empty() {
            return Err(crate::Error::InvalidConfig(
                "extraction prompt: the system text is blank".into(),
            ));
        }
        if let Some(index) = prompt.examples.iter().position(|example| {
            example.user.trim().is_empty() || example.assistant.trim().is_empty()
        }) {
            return Err(crate::Error::InvalidConfig(format!(
                "extraction prompt: example {index} has a blank turn"
            )));
        }
        Ok(prompt)
    }
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
