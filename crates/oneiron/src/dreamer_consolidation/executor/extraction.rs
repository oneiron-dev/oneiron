//! Extraction request/response projection for one admitted branch.

use super::*;

impl ConsolidationExecutor<'_> {
    pub(super) fn extraction_request(
        &self,
        partition: &ConsolidationPartitionKey,
        transcript: &str,
        scope: &crate::llm::Scope,
    ) -> LlmRequest {
        let system = "Extract durable memory claims from the conversation transcript. \
             Respond with JSON: {\"candidates\": [{\"subject\": \"<32-hex entity id>\", \
             \"predicate\": \"<dotted.predicate>\", \"value\": <json>, \"confidence\": <0..1>, \
             \"evidence_turn_refs\": [\"<32-hex turn id>\"]}]}. Only claims stated by the \
             user or assistant; never invent evidence refs.";
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                scope: scope.clone(),
                purpose: CallPurpose::Extraction,
                class: CallClass::Durable {
                    fallback: crate::llm::DeterministicFallback {
                        name: "json_rules_v1".into(),
                        config: Some(
                            serde_json::json!({"version":1,"rows":[{"failure":"fatal","value":{"candidates":[],"people":[],"fallback":"model_unavailable"}}]}),
                        ),
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Extraction,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: super::super::extracted_people::extraction_response_schema(),
                },
                locality: ModelLocality::OwnServer,
            }.with_purpose_defaults(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: format!(
                            "conversation {}\n{transcript}",
                            bytes_to_hex_lower(partition.conversation_ref.as_bytes())
                        ),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        }
    }

    pub(super) fn decode_candidates(
        &self,
        partition: &ConsolidationPartitionKey,
        response: &LlmResponse,
        scope: &crate::llm::Scope,
        attempt_id: crate::attempt_queue::AttemptId,
        now_ms: u64,
    ) -> Result<Vec<PromotionCandidate>> {
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let parsed: serde_json::Value = serde_json::from_str(text.trim())
            .map_err(|_| invalid_consolidation("extraction response must be JSON"))?;
        let Some(items) = parsed.get("candidates").and_then(|value| value.as_array()) else {
            return Ok(Vec::new());
        };

        let mut candidates = Vec::new();
        for item in items {
            let Some(subject) = item
                .get("subject")
                .and_then(|value| value.as_str())
                .and_then(entity_id_from_hex)
            else {
                continue;
            };
            let Some(predicate) = item.get("predicate").and_then(|value| value.as_str()) else {
                continue;
            };
            let confidence = item
                .get("confidence")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.5) as f32;
            let value = json_to_rmpv(item.get("value").unwrap_or(&serde_json::Value::Null));
            let rel = match item.get("rel") {
                None | Some(serde_json::Value::Null) => scope.relationship,
                Some(value) => Some(
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
            let evidence_turn_refs: Vec<EntityId> = item
                .get("evidence_turn_refs")
                .and_then(|value| value.as_array())
                .map(|refs| {
                    refs.iter()
                        .filter_map(|entry| entry.as_str().and_then(entity_id_from_hex))
                        .collect()
                })
                .unwrap_or_default();

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
            if let Some(topic) = item.get("topic_key").filter(|value| !value.is_null()) {
                fields.push((Value::from("topic_key"), json_to_rmpv(topic)));
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
                facts.topic.as_deref(),
            );
            candidates.push(PromotionCandidate {
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
            });
        }
        Ok(candidates)
    }
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
