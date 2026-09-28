//! Extraction request/response projection for one admitted branch.

use super::*;

impl ConsolidationExecutor<'_> {
    pub(super) fn extraction_request(
        &self,
        partition: &ConsolidationPartitionKey,
        transcript: &str,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let locality = self.inference.selected_locality().ok_or_else(|| {
            crate::Error::InvalidConfig("consolidation host binding needs locality".into())
        })?;
        let system = r#"Extract durable memory claims from the conversation transcript.
Respond with JSON: {"candidates":[{"subject":"<32-hex entity id>","predicate":"<dotted.predicate>","value":<json>,"confidence":<0..1>,"evidence_refs":[{"source_id":"<32-hex id>","byte_range":[start,end]}]}]}.
Each evidence ref names a source id and either a UTF-8 byte range in the displayed turn text (start inclusive, end exclusive) or claim_id. Only claims stated by the user or assistant; never invent evidence refs."#;
        Ok(LlmRequest {
            model: self.model.clone(),
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
                response_format: ResponseFormat::Json {
                    schema: super::super::extracted_people::extraction_response_schema(),
                },
                locality,
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
            candidates.push(super::super::evidence::ExtractedCandidate::new(
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
            )?);
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
