//! Extraction request/response projection for one admitted branch, and the
//! typed pack that decides which listed claim each candidate corrects.

use super::decisions::{id_options, named_id};
use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::extracted_people::MintNamespace;
use crate::dreamer_consolidation::neighbourhood::Neighbourhood;
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::llm::decision::AnswerContract;
use crate::llm::decision::catalogue::CORRECTION;

mod cited;
mod quote_binding;
mod wire;
pub(in crate::dreamer_consolidation) use cited::CitationCheck;
pub(in crate::dreamer_consolidation) use wire::{
    CallPins, ExtractedPerson, ReplyContext, check_extraction_reply, decode_ref,
    disagreeing_child_hashes, extraction_reply, resolve_subject,
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

    /// The extraction request over one NOTE (OF-073): the same prompt and
    /// reply contract, with the NOTE's markdown as the only source, after
    /// the entities `listed` it names. The call names each by a label
    /// (FIX 7506): the note is `N1`, each listed entity `P<n>`. A citation
    /// quotes the note's words, and the review binds each quote to the exact
    /// text it read. It also asks the note's importance.
    /// `sealed_pad` is a sealed scratchpad's review and how it asks for
    /// the pad's `keep` lines (ARCH-0032 #scratchpad-marks). Returns the
    /// request and the label map its reply is read through, bound into the
    /// request's identity with the person-mint `namespace`.
    pub(in crate::dreamer_consolidation) fn note_request(
        call: &RoleCall<'_>,
        note: EntityId,
        listed: &Neighbourhood,
        markdown: &str,
        sealed_pad: Option<PadAsk>,
        scope: &crate::llm::Scope,
        namespace: &MintNamespace,
    ) -> Result<(LlmRequest, CallLabelMap)> {
        let mut labels = CallLabelMap::default();
        // The review holds no prior head: its listing shows entities only.
        let listing = listed.render(&mut labels, |_| false);
        let id = labels.assign(LabelKind::Note, note);
        let mut rule = format!(
            "The source is one note, not a conversation. Cite it as \
             {{\"source\": \"{id}\", \"quote\": \"<a short run of words copied \
             exactly from the note>\"}}: quote enough words that they occur only once \
             in the note. A person the note names, added under \"persons\", has \
             \"evidence_turn_refs\": [\"{id}\"]. Also give the object a key \
             \"importance\": a number from 0 to 1 for how much the note itself matters \
             to keep."
        );
        match sealed_pad {
            Some(PadAsk::First { keep }) => {
                rule.push_str(
                    " The note is a sealed scratchpad. Blank lines held text its writer \
                     marked scratch: cite none of them.",
                );
                if keep {
                    rule.push_str(
                        " A line headed [keep] or [pin keep] states a fact its writer \
                         asked to keep: extract each one.",
                    );
                }
                rule.push_str(" Decide each other line on its own.");
            }
            Some(PadAsk::Missed) => rule.push_str(
                " The note is a sealed scratchpad, asked again. Blank lines were read \
                 before or marked scratch: cite none of them. Each line left is headed \
                 [keep] or [pin keep]: a fact its writer asked to keep that the last \
                 review grounded no belief in. Extract each one.",
            ),
            None => {}
        }
        let mut request = Self::request_over(
            call,
            Some(rule),
            format!("{listing}note {id}\n{markdown}"),
            scope,
        )?;
        labels.bind_request(&mut request, Some(&namespace.identity()));
        Ok((request, labels))
    }

    fn request_over(
        call: &RoleCall<'_>,
        source_rule: Option<String>,
        source: String,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let locality = call.inference.selected_locality().ok_or_else(|| {
            crate::Error::InvalidConfig("consolidation host binding needs locality".into())
        })?;
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
            }.with_purpose_defaults(),
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }

    /// The candidates one child's `scope` can take from `response`, before
    /// the claim each corrects is decided, and how many it cannot. Its
    /// labels, quotes and declared people bind through `ctx`, its call's
    /// own map. Decode never fails the partition over one candidate: one it
    /// cannot take (a candidate breaking a rule such as the evidence rules,
    /// or one in a reply stored before the step checked candidates) is not
    /// written, and is counted.
    pub(in crate::dreamer_consolidation) fn parse_candidates<'s>(
        response: &LlmResponse,
        resources: &BranchResources<'_>,
        scope: &'s crate::llm::Scope,
        ctx: ReplyContext<'_>,
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
                Ok(candidate) => parsed.push(candidate),
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

    /// Which listed claim each parsed candidate corrects, in order. A
    /// candidate whose subject the listing shows claims about, that its child
    /// may read and write, gets one question over `none` and those claims'
    /// ids, all candidates in one pack; one with no such claim, or no answer,
    /// corrects none. The pack's ask goes to its candidates' project's route,
    /// or to the owners when they span projects. None when the step trapped.
    pub(in crate::dreamer_consolidation) async fn decide_corrections(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &crate::dreamer_wake::WakePassDeadline,
        parsed: &[ParsedCandidate<'_>],
        resources: &BranchResources<'_>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<Correction>>> {
        let mut questions = Vec::new();
        // Each candidate's question indexes, and every listed claim asked about.
        let mut asks: Vec<Vec<usize>> = vec![Vec::new(); parsed.len()];
        let mut listed: Vec<(EntityId, EntityId, &str, &str)> = Vec::new();
        let pins = resources.pins();
        for (position, candidate) in parsed.iter().enumerate() {
            let shown: Vec<_> = pins
                .correctable(candidate.subject, candidate.scope)
                .collect();
            let ids: Vec<EntityId> = shown.iter().map(|(claim, ..)| *claim).collect();
            for (group, options) in id_options(&ids, true).into_iter().enumerate() {
                let (position_key, group_key) = (position.to_string(), group.to_string());
                asks[position].push(questions.len());
                questions.push(CORRECTION.question(
                    &[position_key.as_bytes(), group_key.as_bytes()],
                    self.decisions.correction_wording.clone(),
                    AnswerContract::Choice { options },
                )?);
            }
            for (claim, predicate, value) in shown {
                if !listed.iter().any(|row| row.0 == claim) {
                    listed.push((claim, candidate.subject, predicate, value));
                }
            }
        }
        if questions.is_empty() {
            return Ok(Some(parsed.iter().map(|_| Correction::none()).collect()));
        }
        let state = correction_state(parsed, &asks, &questions, &listed);
        let asked: Vec<&ParsedCandidate<'_>> = parsed
            .iter()
            .zip(&asks)
            .filter(|(_, asked)| !asked.is_empty())
            .map(|(candidate, _)| candidate)
            .collect();
        // The pack reads the listed claims and candidates drawn from these
        // turns. The turns also keep one extraction's asks apart from
        // another's over the same listing.
        let mut evidence: Vec<EntityId> = listed.iter().map(|row| row.0).collect();
        let mut turns: Vec<EntityId> = asked
            .iter()
            .flat_map(|candidate| candidate.evidence_turn_refs.iter().copied())
            .filter(|turn| !evidence.contains(turn))
            .collect();
        turns.sort_unstable();
        turns.dedup();
        evidence.extend(turns);
        let project = asked
            .first()
            .map(|candidate| candidate.project)
            .filter(|project| asked.iter().all(|candidate| candidate.project == *project));
        let to = self.ask_route(step_ctx.vault, project)?;
        // The pack is the attempt's one correction read: the attempt names it.
        let key =
            EntityId::from_bytes(*step_ctx.attempt_id.as_bytes()).map_err(crate::Error::from)?;
        let Some(decided) = self
            .decide(
                step_ctx, pass, resources, &to, key, &questions, &evidence, &state, charges,
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            asks.iter()
                .map(|asked| {
                    let decisions: Vec<KeptDecision> =
                        asked.iter().map(|&at| decided[at].clone()).collect();
                    Correction {
                        corrects: named_id(decisions.iter().collect()),
                        decisions,
                    }
                })
                .collect(),
        ))
    }

    /// The candidates the branch takes, each bound to the claim it corrects
    /// and keeping its correction's decisions, and whether any candidate waits
    /// on a role's answer: that one is not taken this pass.
    pub(in crate::dreamer_consolidation) fn build_candidates(
        parsed: Vec<ParsedCandidate<'_>>,
        corrections: &[Correction],
        mut skipped: usize,
        partition: &ConsolidationPartitionKey,
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

/// How a sealed scratchpad's review asks for its `keep` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) enum PadAsk {
    /// The first read: scratch lines blanked; `keep` when a line is marked
    /// `keep`.
    First { keep: bool },
    /// The one re-ask (FIX 2240): only the `keep` lines the last review
    /// grounded no belief in are left; every other line is blank.
    Missed,
}

/// What the correction pack decided for one parsed candidate: the listed
/// claim it corrects, if any, and its questions' decisions.
pub(in crate::dreamer_consolidation) struct Correction {
    corrects: Option<EntityId>,
    decisions: Vec<KeptDecision>,
}

impl Correction {
    /// A candidate the pack asked nothing about: it corrects none.
    fn none() -> Self {
        Self {
            corrects: None,
            decisions: Vec::new(),
        }
    }

    /// Whether one of its questions waits on a role's answer.
    fn waiting(&self) -> bool {
        self.decisions.iter().any(KeptDecision::waiting)
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
    rel: Option<serde_json::Value>,
    topic: Option<serde_json::Value>,
    locators: Vec<super::super::evidence::EvidenceLocator>,
    evidence_turn_refs: Vec<EntityId>,
    project: EntityId,
    prospective_queries: Vec<String>,
}

/// The candidates and the listed claims as the correction pack reads them:
/// each candidate with its questions, subject, predicate and value, each
/// value as its JSON text, cut shorter (halving) until the whole fits.
fn correction_state(
    parsed: &[ParsedCandidate<'_>],
    asks: &[Vec<usize>],
    questions: &[crate::llm::decision::DecisionQuestion],
    listed: &[(EntityId, EntityId, &str, &str)],
) -> serde_json::Value {
    let values: Vec<String> = parsed
        .iter()
        .map(|candidate| candidate.value.to_string())
        .collect();
    let longest = values
        .iter()
        .map(String::len)
        .chain(listed.iter().map(|row| row.3.len()))
        .max()
        .unwrap_or(0);
    crate::llm::decision::fit_state(longest, |cut| {
        let candidates: Vec<serde_json::Value> = parsed
            .iter()
            .zip(asks)
            .zip(&values)
            .filter(|((_, asked), _)| !asked.is_empty())
            .map(|((candidate, asked), value)| {
                let ids: Vec<String> = asked.iter().map(|&at| questions[at].id.to_hex()).collect();
                serde_json::json!({
                    "questions": ids,
                    "subject": candidate.subject.to_hex(),
                    "predicate": candidate.predicate,
                    "value": crate::llm::decision::cut_text(value, cut),
                })
            })
            .collect();
        let listed: Vec<serde_json::Value> = listed
            .iter()
            .map(|(claim, subject, predicate, value)| {
                serde_json::json!({
                    "claim": claim.to_hex(),
                    "subject": subject.to_hex(),
                    "predicate": predicate,
                    "value": crate::llm::decision::cut_text(value, cut),
                })
            })
            .collect();
        serde_json::json!({
            "candidates": candidates,
            "listed": listed,
            "cut_at_bytes": cut,
        })
    })
}

/// One parsed candidate as the branch takes it, or why it is not written.
/// A candidate that corrects a listed claim binds to that head: its subject,
/// predicate, relationship and topic, so it routes to the head through the
/// conflict and grant doors, and the verdict skips it.
fn build_candidate(
    parsed: ParsedCandidate<'_>,
    correction: &Correction,
    partition: &ConsolidationPartitionKey,
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
    partition: &ConsolidationPartitionKey,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<super::super::evidence::ExtractedCandidate> {
    let (proposal, locators) =
        resolve_proposal(parsed, corrects, decisions, partition, attempt_id, now_ms)?;
    let extracted = super::super::evidence::ExtractedCandidate::new(proposal, locators)?;
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
    partition: &ConsolidationPartitionKey,
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
        (Some(prior), _) => prior.body.rel,
        (None, None) => scope.relationship,
        // Not advertised, and no call shows a relationship id; still read
        // as before (FIX 7506 left this one route unlabelled).
        (None, Some(value)) => Some(
            value
                .as_str()
                .and_then(entity_id_from_hex)
                .ok_or_else(|| invalid_consolidation("invalid relationship ref"))?,
        ),
    };
    if scope.relationship.is_some_and(|bound| rel != Some(bound)) {
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
    if let Some(rel) = rel {
        candidate = candidate.with_relationship(rel);
    }
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
        rel,
        facts.project,
        facts.topic.as_deref(),
    )?;
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
            occurred: TimeRange {
                start: now_ms,
                end: now_ms,
            },
            learned_at: now_ms,
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
