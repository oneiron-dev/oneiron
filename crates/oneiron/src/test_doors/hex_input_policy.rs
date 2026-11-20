//! Doors for `tests/hex_input_policy.rs` (UC-07 PR 6, HEX-CASE-POLICY = A):
//! whether six hex spellings read through the production decoders, each as
//! its door reads it. Thin wrappers over the named items only; every
//! assertion stays in the test file.

/// Whether a turn span carrying `fingerprint` pins it
/// (`ConversationTurnSpan::pinned_fingerprint`).
#[must_use]
pub fn turn_span_fingerprint_reads(fingerprint: &str) -> bool {
    let span = crate::compaction::ConversationTurnSpan {
        turn: crate::EntityId::from_bytes([7; 16]).expect("fixture turn id"),
        role: "user".to_owned(),
        messages: Vec::new(),
        fingerprint: fingerprint.to_owned(),
    };
    span.pinned_fingerprint().is_some()
}

/// Whether a self-writer receipt carrying `snapshot_hash` reads its snapshot
/// (`CompactionExecution::snapshot`).
#[must_use]
pub fn compaction_snapshot_reads(snapshot_hash: &str) -> bool {
    let execution = crate::compaction::CompactionExecution {
        writer: crate::EntityId::from_bytes([7; 16]).expect("fixture writer id"),
        caller_origin: crate::agent_dispatch::CallerOrigin::Unknown,
        source: oneiron_model::llm::SelfCompactionSource::RetainedTurns,
        admitted_model: "test-model".to_owned(),
        served_provider: None,
        served_model: None,
        usage: crate::compaction::CompactionUsage::default(),
        rejected_tries: Vec::new(),
        step_hash: None,
        home: Vec::new(),
        prefix_sources: Vec::new(),
        snapshot_hash: Some(snapshot_hash.to_owned()),
        snapshot_len: Some(1),
        step: None,
        rejected_steps: Vec::new(),
        step_unfiled: None,
        evidence: None,
        calls: Vec::new(),
    };
    execution.snapshot().is_some()
}

/// Whether a craft verdict carrying `candidate_hash` reads as a verdict
/// (`actor_claims::verdict_stamp`).
#[must_use]
pub fn craft_verdict_reads(candidate_hash: &str) -> bool {
    let resident = crate::EntityId::from_bytes([9; 16]).expect("fixture resident id");
    let mut body = crate::claim::ClaimBody::new(
        crate::actor_claims::PREDICATE_ACTOR_LESSON,
        crate::claim::ClaimSubject::Entity(resident),
        rmpv::Value::from("a distilled note"),
        1.0,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .expect("fixture verdict body");
    body.source = Some(crate::claim::ClaimSource::Generated);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(crate::actor_claims::ACTOR_CLAIM_LINEAGE_KEY),
        rmpv::Value::from(crate::claim::ClaimSource::Generated.as_str()),
    )]));
    let attempt = "0123456789abcdef0123456789abcdef";
    let candidate = "0123456789abcdef0123456789abcdef";
    let owner = "0123456789abcdef0123456789abcdef";
    let receipt = format!("gate:{candidate}");
    body.evidence = Some(rmpv::Value::Map(vec![
        (rmpv::Value::from("at"), rmpv::Value::from(1_u64)),
        (
            rmpv::Value::from("lane"),
            rmpv::Value::from("resident_dream"),
        ),
        (rmpv::Value::from("attempt"), rmpv::Value::from(attempt)),
        (rmpv::Value::from("candidate"), rmpv::Value::from(candidate)),
        (
            rmpv::Value::from("candidate_hash"),
            rmpv::Value::from(candidate_hash),
        ),
        (rmpv::Value::from("verdict"), rmpv::Value::from("approved")),
        (rmpv::Value::from("owner"), rmpv::Value::from(owner)),
        (
            rmpv::Value::from("receipt"),
            rmpv::Value::from(receipt.as_str()),
        ),
    ]));
    crate::actor_claims::verdict_stamp(&body).is_some()
}

/// Whether `text` reads as a model subject id
/// (`dreamer_consolidation::entity_id_from_hex`).
#[must_use]
pub fn extraction_subject_id_reads(text: &str) -> bool {
    crate::dreamer_consolidation::entity_id_from_hex(text).is_some()
}

/// Whether `text` reads as a stored projection digest (`digest_from_value`).
#[must_use]
pub fn projection_digest_reads(text: &str) -> bool {
    crate::origin::secret_projection::claims::digest_from_value(&rmpv::Value::from(text)).is_ok()
}

/// Whether `text` reads as a fan-out plan digest argument
/// (`verbs::decode_plan_digest`).
#[must_use]
pub fn fanout_plan_digest_reads(text: &str) -> bool {
    crate::verbs::decode_plan_digest(text).is_ok()
}
