//! Extraction request/response projection for one admitted branch.

use super::*;
use crate::llm::FinishReason;

impl ConsolidationExecutor<'_> {
    pub(super) fn extraction_request(
        call: &RoleCall<'_>,
        partition: &ConsolidationPartitionKey,
        transcript: &str,
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
        messages.push(text(
            LlmMessageRole::User,
            format!(
                "conversation {}\n{transcript}",
                bytes_to_hex_lower(partition.conversation_ref.as_bytes())
            ),
        ));
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

    pub(super) fn decode_candidates(
        &self,
        partition: &ConsolidationPartitionKey,
        response: &LlmResponse,
        resources: &BranchResources<'_>,
        scope: &crate::llm::Scope,
        attempt_id: crate::attempt_queue::AttemptId,
        now_ms: u64,
    ) -> Result<Vec<super::super::evidence::ExtractedCandidate>> {
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

        let mut candidates = Vec::new();
        for item in items {
            // A candidate that names no value carries no claim.
            if item.get("value").is_none_or(serde_json::Value::is_null) {
                tracing::warn!(
                    target: "oneiron::dreamer",
                    "extracted candidate names no value; not written"
                );
                continue;
            }
            // A candidate naming a listed claim corrects it and binds to that
            // head: its subject, predicate, relationship and topic, so it
            // routes to the head through the conflict and grant doors. A
            // claim the branch does not hold is not one it may name.
            let corrects = match item.get("corrects") {
                None | Some(serde_json::Value::Null) => None,
                Some(named) => match named
                    .as_str()
                    .and_then(entity_id_from_hex)
                    .map(|id| resources.prior(id))
                {
                    Some(Ok(prior)) => Some(prior),
                    _ => {
                        tracing::warn!(
                            target: "oneiron::dreamer",
                            "extracted correction names a claim the branch does not hold; not written"
                        );
                        continue;
                    }
                },
            };
            let named = item
                .get("subject")
                .and_then(|value| value.as_str())
                .and_then(entity_id_from_hex);
            let (subject, predicate) = match corrects {
                Some(prior) => {
                    let ClaimSubject::Entity(subject) = prior.body.subject else {
                        continue;
                    };
                    if named.is_some_and(|named| named != subject) {
                        tracing::warn!(
                            target: "oneiron::dreamer",
                            "extracted correction names a claim about another subject; not written"
                        );
                        continue;
                    }
                    (subject, prior.body.predicate.as_str())
                }
                None => {
                    let Some(subject) = named else {
                        continue;
                    };
                    let Some(predicate) = item.get("predicate").and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    // The contract's predicate rule is the claim grammar's.
                    if crate::claim::validate_predicate(predicate, false).is_err() {
                        tracing::warn!(
                            target: "oneiron::dreamer",
                            "extracted candidate's predicate breaks the claim grammar; not written"
                        );
                        continue;
                    }
                    (subject, predicate)
                }
            };
            let confidence = item
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5) as f32;
            let value = json_to_rmpv(item.get("value").unwrap_or(&serde_json::Value::Null));
            let rel = match (corrects, item.get("rel")) {
                (Some(prior), _) => prior.body.rel,
                (None, None | Some(serde_json::Value::Null)) => scope.relationship,
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
            let refs = item
                .get("evidence_refs")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| invalid_consolidation("candidate evidence_refs must be an array"))?;
            let locators: Vec<_> = refs
                .iter()
                .map(decode_model_locator)
                .collect::<Result<_>>()?;
            let mut evidence_turn_refs: Vec<_> =
                locators.iter().map(|entry| entry.source_id()).collect();
            evidence_turn_refs.sort_unstable();
            evidence_turn_refs.dedup();
            // A claim drawn from two projects' turns has no one audience, and
            // a project-bound branch writes only its own project's.
            let Some(project) = resources.evidence_project(&evidence_turn_refs)? else {
                tracing::warn!(
                    target: "oneiron::dreamer",
                    "extracted candidate's sources share no one branch project; not written"
                );
                continue;
            };

            let mut candidate =
                ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence);
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
                None => item
                    .get("topic_key")
                    .filter(|value| !value.is_null())
                    .map(json_to_rmpv),
            };
            if let Some(topic) = topic {
                fields.push((Value::from("topic_key"), topic));
            }
            if project != crate::claim::default_project_id() {
                fields.push((
                    Value::from(SCOPE_PROJECT_KEY),
                    Value::Binary(project.as_bytes().to_vec()),
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
                    evidence_turn_refs,
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
                },
                locators,
            )?;
            // Only a head the listing showed is a correction target; one held
            // only for a replay's scope binds, but the verdict judges it.
            candidates.push(match corrects {
                Some(prior) if resources.known().shows(prior.claim_id) => {
                    extracted.correcting(prior.claim_id)
                }
                _ => extracted,
            });
        }
        Ok(candidates)
    }
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

/// An extraction reply that meets its contract: an object whose
/// `candidates`, when present, are objects, and whose `persons`, when
/// present, each name a 32-hex id, a name and at least one 32-hex turn.
/// Other keys are outside the contract and read by no one.
#[derive(serde::Deserialize)]
pub(in crate::dreamer_consolidation) struct ExtractionReply {
    #[serde(default, deserialize_with = "objects")]
    pub(in crate::dreamer_consolidation) candidates: Vec<serde_json::Value>,
    #[serde(default)]
    pub(in crate::dreamer_consolidation) persons: Vec<ExtractedPerson>,
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

/// `response`'s extraction reply, refused unless it meets the contract.
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

/// The question key a stored head was filed under, as its scope map holds it.
fn prior_topic(scope: Option<&Value>) -> Option<Value> {
    let Some(Value::Map(fields)) = scope else {
        return None;
    };
    fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("topic_key")).then(|| value.clone()))
}

fn entity_id_from_hex(hex: &str) -> Option<EntityId> {
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

fn decode_model_locator(
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
