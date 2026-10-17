//! Extraction request/response projection for one admitted branch, and the
//! typed pack that decides which listed claim each candidate corrects.

use super::decisions::{id_options, named_id};
use super::*;
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::llm::FinishReason;
use crate::llm::decision::AnswerContract;
use crate::llm::decision::catalogue::CORRECTION;

impl ConsolidationExecutor<'_> {
    pub(in crate::dreamer_consolidation) fn extraction_request(
        call: &RoleCall<'_>,
        partition: &ConsolidationPartitionKey,
        transcript: &str,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        Self::request_over(
            call,
            None,
            format!(
                "conversation {}\n{transcript}",
                bytes_to_hex_lower(partition.conversation_ref.as_bytes())
            ),
            scope,
        )
    }

    /// The extraction request over one NOTE (OF-073): the same prompt and
    /// reply contract, with the NOTE's markdown as the only source. Its
    /// byte ranges count over that markdown, so the review can check each
    /// one against the exact text it read.
    /// `sealed_pad` is a sealed scratchpad's review: `Some(keep)`, `keep`
    /// when a line is marked `keep` (ARCH-0032 #scratchpad-marks).
    pub(in crate::dreamer_consolidation) fn note_request(
        call: &RoleCall<'_>,
        note: EntityId,
        markdown: &str,
        sealed_pad: Option<bool>,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let id = bytes_to_hex_lower(note.as_bytes());
        let mut rule = format!(
            "The source is one note, not a conversation. Cite it as \
             {{\"source_id\": \"{id}\", \"byte_range\": [start, end]}}, a range of \
             UTF-8 bytes of the note's markdown, which starts on the line after its \
             header. Also give the object a key \"importance\": a number from 0 to 1 \
             for how much the note itself matters to keep."
        );
        if let Some(keep) = sealed_pad {
            rule.push_str(
                " The note is a sealed scratchpad. Blank lines held text its writer \
                 marked scratch: cite none of them.",
            );
            if keep {
                rule.push_str(
                    " A line headed [keep] or [pin keep] states a fact its writer asked \
                     to keep: extract each one.",
                );
            }
            rule.push_str(" Decide each other line on its own.");
        }
        Self::request_over(call, Some(rule), format!("note {id}\n{markdown}"), scope)
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
    /// the claim each corrects is decided, and how many it cannot. Decode
    /// never fails the partition over one candidate: one it cannot take (a
    /// candidate breaking a rule such as the evidence rules, or one in a reply
    /// stored before the step checked candidates) is not written, and is
    /// counted.
    pub(in crate::dreamer_consolidation) fn parse_candidates<'s>(
        response: &LlmResponse,
        resources: &BranchResources<'_>,
        scope: &'s crate::llm::Scope,
    ) -> Result<(Vec<ParsedCandidate<'s>>, usize)> {
        let items = extraction_reply(response)?.candidates;
        let items = items.as_slice();
        // A child hash is not part of the return contract. If a model still
        // reports one, compare it with our pinned source reread only to flag
        // an integrity failure. It never enters dedup or the write envelope.
        for source_id in disagreeing_child_hashes(resources, items) {
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
            match parse_candidate(item, resources, scope) {
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
        for (position, candidate) in parsed.iter().enumerate() {
            let shown: Vec<_> = resources
                .known()
                .shown_about(candidate.subject)
                .filter(|(claim, ..)| {
                    resources.prior(*claim).is_ok()
                        && resources.source_version(claim).is_ok_and(|version| {
                            candidate.scope.allows_read(&version)
                                && candidate.scope.allows_write(&version)
                        })
                })
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
        let key = EntityId::from_bytes(*step_ctx.attempt_id.as_bytes()).map_err(crate::Error::from)?;
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
}

/// One candidate's reading of the reply and of the branch's pinned
/// resources, or why it is not written; an error is this candidate's alone.
fn parse_candidate<'s>(
    item: &serde_json::Value,
    resources: &BranchResources<'_>,
    scope: &'s crate::llm::Scope,
) -> Result<ParsedCandidate<'s>> {
    // A candidate that names no value carries no claim.
    let value = item
        .get("value")
        .filter(|value| !value.is_null())
        .ok_or_else(|| invalid_consolidation("extracted candidate names no value"))?
        .clone();
    let subject = item
        .get("subject")
        .and_then(|value| value.as_str())
        .and_then(entity_id_from_hex)
        .ok_or_else(|| invalid_consolidation("extracted candidate names no subject"))?;
    // The contract's predicate rule is the claim grammar's.
    let predicate = item
        .get("predicate")
        .and_then(|value| value.as_str())
        .filter(|predicate| crate::claim::validate_predicate(predicate, false).is_ok())
        .map(str::to_owned);
    let confidence = item
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.5) as f32;
    let refs = item
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_consolidation("candidate evidence_refs must be an array"))?;
    let locators: Vec<_> = refs
        .iter()
        .map(decode_model_locator)
        .collect::<Result<_>>()?;
    let mut evidence_turn_refs: Vec<_> = locators.iter().map(|entry| entry.source_id()).collect();
    evidence_turn_refs.sort_unstable();
    evidence_turn_refs.dedup();
    for id in &evidence_turn_refs {
        if !scope.allows_read(&resources.source_version(id)?) {
            return Err(invalid_consolidation(
                "extracted evidence crossed its child slice",
            ));
        }
    }
    // A claim drawn from two projects' turns has no one audience, and a
    // project-bound branch writes only its own project's.
    let project = resources
        .evidence_project(&evidence_turn_refs)?
        .ok_or_else(|| {
            invalid_consolidation("extracted candidate's sources share no one branch project")
        })?;
    Ok(ParsedCandidate {
        scope,
        subject,
        predicate,
        value,
        confidence,
        rel: item.get("rel").filter(|value| !value.is_null()).cloned(),
        topic: item
            .get("topic_key")
            .filter(|value| !value.is_null())
            .cloned(),
        locators,
        evidence_turn_refs,
        project,
    })
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
    let scope = parsed.scope;
    let corrects = correction
        .corrects
        .map(|claim| resources.prior(claim))
        .transpose()?;
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
    );
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
    let extracted = super::super::evidence::ExtractedCandidate::new(
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
            decisions: correction.decisions.clone(),
        },
        parsed.locators,
    )?;
    // Only a head the listing shows is a correction target.
    Ok(match corrects {
        Some(prior) => extracted.correcting(prior.claim_id),
        None => extracted,
    })
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

/// An extraction reply in its contract's shape: an object whose
/// `candidates`, when present, are objects, and whose `persons`, when
/// present, each name a 32-hex id, a name and at least one 32-hex turn.
/// `importance` is a NOTE review's, read by that review only. Other keys
/// are outside the contract and read by no one.
#[derive(serde::Deserialize)]
pub(in crate::dreamer_consolidation) struct ExtractionReply {
    #[serde(default, deserialize_with = "objects")]
    pub(in crate::dreamer_consolidation) candidates: Vec<serde_json::Value>,
    #[serde(default)]
    pub(in crate::dreamer_consolidation) persons: Vec<ExtractedPerson>,
    #[serde(default)]
    pub(in crate::dreamer_consolidation) importance: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
pub(in crate::dreamer_consolidation) struct ExtractedPerson {
    pub(in crate::dreamer_consolidation) id: String,
    pub(in crate::dreamer_consolidation) name: String,
    pub(in crate::dreamer_consolidation) evidence_turn_refs: Vec<String>,
}

fn objects<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<serde_json::Value>, D::Error> {
    let items: Vec<serde_json::Map<String, serde_json::Value>> =
        serde::Deserialize::deserialize(deserializer)?;
    Ok(items.into_iter().map(serde_json::Value::Object).collect())
}

/// `response`'s extraction reply, refused unless it has the contract's
/// shape. Its candidates' fields are [`check_extraction_reply`]'s, so a
/// reply stored before that check still reads here.
///
/// One narrow repair runs first: a reply that stopped one `}` short (it
/// parses to the end and ends on the candidates' `]`) gets exactly one `}`
/// appended, and the result must still parse and meet the contract. No
/// other text is mended.
pub(in crate::dreamer_consolidation) fn extraction_reply(
    response: &LlmResponse,
) -> Result<ExtractionReply> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let text = text.trim();
    let reply = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(reply) => reply,
        Err(error)
            if error.is_eof()
                && response.finish_reason == FinishReason::Stop
                && text.starts_with('{')
                && text.ends_with(']') =>
        {
            serde_json::from_str(&format!("{text}}}"))
                .map_err(|_| invalid_consolidation("extraction response must be JSON"))?
        }
        Err(_) => return Err(invalid_consolidation("extraction response must be JSON")),
    };
    // A derived struct also reads a JSON array positionally; the contract
    // names objects only.
    let objects = reply.is_object()
        && reply
            .get("persons")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|people| people.iter().all(serde_json::Value::is_object));
    if !objects {
        return Err(invalid_consolidation(
            "extraction response breaks its contract",
        ));
    }
    let reply: ExtractionReply = serde_json::from_value(reply)
        .map_err(|_| invalid_consolidation("extraction response breaks its contract"))?;
    let hex = |id: &str| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !reply.persons.iter().all(|person| {
        hex(&person.id)
            && !person.name.is_empty()
            && !person.evidence_turn_refs.is_empty()
            && person.evidence_turn_refs.iter().all(|turn| hex(turn))
    }) {
        return Err(invalid_consolidation(
            "extraction response breaks its contract",
        ));
    }
    Ok(reply)
}

/// The extraction step's check: the reply meets the contract, each of its
/// candidates included, or it is refused and never memoized, so the next
/// run asks again. A candidate names a 32-hex `subject`, a string
/// `predicate`, a `value` that is not null, a `confidence` from 0 to 1, and
/// one or more evidence refs as decode reads them. A candidate that meets
/// them but breaks a rule (the predicate grammar, or a source or project the
/// branch must hold) is decode's to skip, never a refusal.
pub(in crate::dreamer_consolidation) fn check_extraction_reply(
    response: &LlmResponse,
) -> std::result::Result<(), String> {
    let reply = extraction_reply(response).map_err(|error| error.to_string())?;
    for (index, candidate) in reply.candidates.iter().enumerate() {
        if let Some(field) = contract_fault(candidate) {
            return Err(format!(
                "extraction candidate {index} breaks its contract at {field}"
            ));
        }
    }
    Ok(())
}

/// The first contract field `candidate` gets wrong, if any.
fn contract_fault(candidate: &serde_json::Value) -> Option<&'static str> {
    let id = |field: &str| {
        candidate
            .get(field)
            .and_then(serde_json::Value::as_str)
            .and_then(entity_id_from_hex)
            .is_some()
    };
    let confidence = candidate
        .get("confidence")
        .and_then(serde_json::Value::as_f64);
    let refs = candidate
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array);
    [
        ("subject", id("subject")),
        (
            "predicate",
            candidate
                .get("predicate")
                .is_some_and(serde_json::Value::is_string),
        ),
        (
            "value",
            candidate.get("value").is_some_and(|value| !value.is_null()),
        ),
        (
            "confidence",
            confidence.is_some_and(|confidence| (0.0..=1.0).contains(&confidence)),
        ),
        (
            "evidence_refs",
            refs.is_some_and(|refs| {
                !refs.is_empty() && refs.iter().all(|cited| decode_model_locator(cited).is_ok())
            }),
        ),
    ]
    .into_iter()
    .find_map(|(field, met)| (!met).then_some(field))
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

pub(in crate::dreamer_consolidation) fn entity_id_from_hex(hex: &str) -> Option<EntityId> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        raw[index] = (high << 4) | low;
    }
    EntityId::from_bytes(raw).ok()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A diagnostic side channel for out-of-contract hashes in the raw model
/// response. The typed child return cannot carry them as evidence authority.
pub(in crate::dreamer_consolidation) fn disagreeing_child_hashes(
    resources: &BranchResources<'_>,
    items: &[serde_json::Value],
) -> Vec<EntityId> {
    let mut disagreements = Vec::new();
    for item in items {
        let Some(hashes) = item
            .get("evidence_hashes")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        let locators: Vec<_> = item
            .get("evidence_refs")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| decode_model_locator(value).ok())
            .collect();
        for (raw_id, value) in hashes {
            let (Some(id), Some(reported)) = (entity_id_from_hex(raw_id), value.as_str()) else {
                continue;
            };
            // A diagnostic is never a new citation and cannot veto a valid
            // judgement. Match only typed citations that the parent can read
            // at its ledger pin; CLAIMs and TURN ranges retain their kind.
            let cited: Vec<_> = locators
                .iter()
                .copied()
                .filter(|locator| locator.source_id() == id)
                .map(super::super::evidence::EvidenceLocator::reference)
                .collect();
            let Ok(verified) = resources.verify_evidence_refs(&cited) else {
                continue;
            };
            if !verified.is_empty()
                && verified.iter().all(|entry| {
                    !reported.eq_ignore_ascii_case(&bytes_to_hex_lower(&entry.content_hash))
                })
            {
                disagreements.push(id);
            }
        }
    }
    disagreements.sort_unstable();
    disagreements.dedup();
    disagreements
}

pub(in crate::dreamer_consolidation) fn decode_model_locator(
    value: &serde_json::Value,
) -> Result<super::super::evidence::EvidenceLocator> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_consolidation("evidence locator must be an object"))?;
    let source_id = object
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .and_then(entity_id_from_hex)
        .ok_or_else(|| invalid_consolidation("invalid evidence source id"))?;
    let claim_id = object
        .get("claim_id")
        .map(|value| {
            value
                .as_str()
                .and_then(entity_id_from_hex)
                .ok_or_else(|| invalid_consolidation("invalid evidence claim id"))
        })
        .transpose()?;
    let byte_range = object
        .get("byte_range")
        .map(|value| {
            let pair = value
                .as_array()
                .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?;
            let [start, end] = pair.as_slice() else {
                return Err(invalid_consolidation("invalid evidence byte range"));
            };
            Ok((
                usize::try_from(
                    start
                        .as_u64()
                        .ok_or_else(|| invalid_consolidation("invalid range start"))?,
                )
                .map_err(|_| invalid_consolidation("range start overflow"))?,
                usize::try_from(
                    end.as_u64()
                        .ok_or_else(|| invalid_consolidation("invalid range end"))?,
                )
                .map_err(|_| invalid_consolidation("range end overflow"))?,
            ))
        })
        .transpose()?;
    match (claim_id, byte_range) {
        (Some(claim), None) => super::super::evidence::EvidenceLocator::claim(source_id, claim),
        (None, Some((start, end))) => {
            super::super::evidence::EvidenceLocator::turn_range(source_id, start, end)
        }
        _ => Err(invalid_consolidation(
            "evidence must cite a claim or a byte range",
        )),
    }
}
