use super::*;
use crate::access_grant::AccessGrant;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
};
use crate::config::{HnswConfig, VaultConfig};
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::store::{GateDecisionId, PendingGateConsentRecord, Store};
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), test_config())?;
    Ok((dir, vault))
}

fn entity(seed: u8) -> EntityId {
    let mut bytes = [seed; ENTITY_ID_LEN];
    bytes[0] = seed.max(1);
    EntityId::from_bytes(bytes).expect("test entity id")
}

fn field_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn projected_receipt(
    receipt_id: &str,
    receipt_kind: ReceiptKind,
    occurred_at: u64,
    outcome: &str,
    job_ref: Option<&str>,
    trigger_ref: Option<&str>,
    fields: &[(&str, &str)],
) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: receipt_id.to_owned(),
        receipt_kind,
        occurred_at,
        actor: Some("agent-alpha".to_owned()),
        on_behalf_of: Some("owner".to_owned()),
        outcome: outcome.to_owned(),
        job_ref: job_ref.map(str::to_owned),
        trigger_ref: trigger_ref.map(str::to_owned),
        policy_trace: Vec::new(),
        fields: field_map(fields),
    }
}

fn append_gate_decision(
    vault: &Vault,
    created_at: u64,
    actor: &str,
    outcome: &str,
    reason: &str,
) -> Result<GateDecisionId> {
    append_gate_decision_for_claim(vault, created_at, actor, outcome, reason, entity(0x41))
}

fn append_gate_decision_for_claim(
    vault: &Vault,
    created_at: u64,
    actor: &str,
    outcome: &str,
    reason: &str,
    claim_id: EntityId,
) -> Result<GateDecisionId> {
    let decision_id = GateDecisionId::now();
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(
            wtxn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at,
                outcome: outcome.to_owned(),
                reason_codes: vec![reason.to_owned()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".to_owned(),
                actor_ref: Some(actor.to_owned()),
                content_kind: "external_effect".to_owned(),
                policy_manifest_version: "test-policy".to_owned(),
                claim_id: Some(*claim_id.as_bytes()),
                grant_ref: None,
                diff_handle: vec![0xA5],
                read_frontier_hash: [0xB6; 32],
            },
        )
    })?;
    Ok(decision_id)
}

fn gate_system_notice(audience: &str, body: &str) -> GateSystemNoticeRecord {
    GateSystemNoticeRecord {
        notice_type: "policy_block".to_owned(),
        channel: "EF-196/OF-221".to_owned(),
        voice: "system".to_owned(),
        audience: audience.to_owned(),
        body: body.to_owned(),
        row_ref: None,
        setting_change_offer: None,
    }
}

fn append_pending_gate_consent(
    vault: &Vault,
    created_at: u64,
    actor: &str,
    claim_id: EntityId,
    reason: &str,
    dreamer_run_id: Option<&str>,
) -> Result<GateDecisionId> {
    let decision_id =
        append_gate_decision_for_claim(vault, created_at, actor, "pending", reason, claim_id)?;
    vault.with_write_txn(|wtxn| {
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &PendingGateConsentRecord {
                version: 0,
                claim_id: *claim_id.as_bytes(),
                decision_id,
                created_at,
                diff_handle: vec![0xA5],
                read_frontier_hash: [0xB6; 32],
                reason_codes: vec![reason.to_owned()],
                dreamer_run_id: dreamer_run_id.map(str::to_owned),
            },
        )
    })?;
    Ok(decision_id)
}

fn provenance(actor: EntityId) -> CompanionProvenance {
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("receipt fixture")).unwrap(),
        ClaimApprovalStatus::Approved,
    );
    CompanionProvenance::from_envelope(&envelope)
}

fn companion_record(actor: EntityId) -> CompanionRecord {
    CompanionRecord::persona(
        CompanionScope::neutral(),
        entity(0x51),
        rmpv::Value::from("persona"),
        provenance(actor),
        CompanionExportClassification::Portable,
    )
}

fn put_federation_grant(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
    let grant = FederationGrant::new(
        FederationGrantScope::vault(7),
        entity(0x61),
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let body = encode_federation_grant_body(&grant)?;
    vault.with_write_txn(|wtxn| {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        payload.push(ENTITY_TYPE_FEDERATION_GRANT);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&body);
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;

        let type_key = Store::encode_type_key(ENTITY_TYPE_FEDERATION_GRANT, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        let temporal_key = Store::encode_temporal_key(learned_at, &id);
        vault
            .store
            .temporal_occurred_start
            .put(wtxn, &temporal_key, &[])?;
        vault.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
        Ok(())
    })
}

fn put_redaction_floor_receipt(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 4);
    payload.push(ENTITY_TYPE_REDACTION_AUDIT);
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(b"seal");
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        let temporal_key = Store::encode_temporal_key(learned_at, &id);
        vault
            .store
            .temporal_occurred_start
            .put(wtxn, &temporal_key, &[])?;
        vault.store.temporal_learned.put(wtxn, &temporal_key, &[])?;
        Ok(())
    })
}

#[test]
fn receipt_query_deserializes_missing_limit_with_default() -> Result<()> {
    let query: ReceiptQuery = serde_json::from_str(r#"{"outcome":"held"}"#)
        .map_err(|_| Error::InvariantViolation("receipt query json fixture"))?;
    assert_eq!(query.limit, DEFAULT_RECEIPT_QUERY_LIMIT);
    assert_eq!(query.outcome.as_deref(), Some("held"));
    assert_eq!(query.job_ref, None);
    Ok(())
}

#[test]
fn receipt_record_job_ref_is_optional_for_legacy_json() -> Result<()> {
    let receipt: ReceiptRecord = serde_json::from_str(
        r#"{
                "receipt_id": "outbound:intent:legacy",
                "receipt_kind": "outbound",
                "occurred_at": 10,
                "outcome": "delivered_to_channel",
                "trigger_ref": "run:ad-hoc"
            }"#,
    )
    .map_err(|_| Error::InvariantViolation("receipt json fixture"))?;

    assert_eq!(receipt.job_ref, None);
    Ok(())
}

#[test]
fn receipt_query_job_ref_filter_matches_legacy_projection_fields() {
    let receipt = projected_receipt(
        "outbound:intent:legacy",
        ReceiptKind::Outbound,
        10,
        "delivered_to_channel",
        None,
        Some("intent:legacy"),
        &[("brief_ref", "brief:party")],
    );
    let unrelated = projected_receipt(
        "outbound:intent:other",
        ReceiptKind::Outbound,
        11,
        "delivered_to_channel",
        None,
        Some("intent:other"),
        &[("brief_ref", "brief:other")],
    );

    let filtered = finalize_receipt_query_records(
        vec![unrelated, receipt],
        &ReceiptQuery::new(10).with_job_ref("party"),
        None,
    );

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].receipt_id, "outbound:intent:legacy");
}

#[test]
fn receipt_query_job_ref_filter_chain_walks_before_limit() {
    let records = vec![
        projected_receipt(
            "outbound:intent:unrelated",
            ReceiptKind::Outbound,
            50,
            "delivered_to_channel",
            None,
            Some("intent:unrelated"),
            &[("brief_ref", "brief:other")],
        ),
        projected_receipt(
            "gate:run-planning",
            ReceiptKind::Gate,
            10,
            "started",
            None,
            Some("run:planning"),
            &[("parent_ref", "brief:party")],
        ),
        projected_receipt(
            "outbound:intent:invite-aki",
            ReceiptKind::Outbound,
            11,
            "delivered_to_channel",
            None,
            Some("intent:invite-aki"),
            &[("run_ref", "run:planning"), ("budget_debit", "4")],
        ),
    ];

    let filtered =
        finalize_receipt_query_records(records, &ReceiptQuery::new(2).with_job_ref("party"), None);

    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered[0].receipt_id, "outbound:intent:invite-aki");
    assert_eq!(filtered[1].receipt_id, "gate:run-planning");
}

#[test]
fn receipt_query_job_ref_filter_uses_unfiltered_lineage_index() {
    let lineage = vec![
        projected_receipt(
            "gate:run-planning",
            ReceiptKind::Gate,
            10,
            "started",
            None,
            Some("run:planning"),
            &[("parent_ref", "brief:party")],
        ),
        projected_receipt(
            "outbound:intent:invite-aki",
            ReceiptKind::Outbound,
            11,
            "delivered_to_channel",
            None,
            Some("intent:invite-aki"),
            &[("run_ref", "run:planning"), ("budget_debit", "4")],
        ),
    ];
    let visible = vec![lineage[1].clone()];

    let filtered = finalize_receipt_query_records(
        visible,
        &ReceiptQuery::new(10)
            .with_kind(ReceiptKind::Outbound)
            .with_outcome("delivered_to_channel")
            .with_job_ref("party"),
        Some(&lineage),
    );

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].receipt_id, "outbound:intent:invite-aki");
}

#[test]
fn outbound_intent_receipt_propagates_job_ref() {
    let intent = OutboundIntent {
        actor: "agent-alpha".to_owned(),
        on_behalf_of: Some("owner".to_owned()),
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        content_ref: None,
        idempotency_key: None,
        dedupe_key: None,
        intent_source: "brief_run".to_owned(),
        trigger_ref: "intent:invite-kenji".to_owned(),
        job_ref: Some("brief:party".to_owned()),
    };

    let receipt = outbound_intent_receipt(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        &intent,
        42,
        "delivered_to_channel",
    );

    assert_eq!(receipt.receipt_kind, ReceiptKind::Outbound);
    assert_eq!(receipt.actor.as_deref(), Some("agent-alpha"));
    assert_eq!(receipt.on_behalf_of.as_deref(), Some("owner"));
    assert_eq!(receipt.job_ref.as_deref(), Some("brief:party"));
    assert_eq!(receipt.trigger_ref.as_deref(), Some("intent:invite-kenji"));
    assert_eq!(
        receipt.fields.get("intent_ref").map(String::as_str),
        Some("intent:invite-kenji")
    );
    assert_eq!(
        receipt.fields.get("target").map(String::as_str),
        Some("kenji@example.com")
    );
}

#[test]
fn receipt_query_returns_mixed_kinds_and_filters() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    append_gate_decision(
        &vault,
        10,
        "agent-alpha",
        "pending",
        "gate.pending.actor_ceiling",
    )?;

    let identity_actor = entity(0x50);
    vault.create_companion_record(&entity(0x52), &companion_record(identity_actor), 20)?;

    let access_grant =
        AccessGrant::companion_profile_read(entity(0x60), entity(0x62), entity(0x63), 30);
    vault.create_access_grant(&entity(0x64), &access_grant)?;
    put_federation_grant(&vault, entity(0x65), 40)?;

    let receipts = vault.receipts(ReceiptQuery::new(10))?;
    let kinds: BTreeSet<_> = receipts
        .iter()
        .map(|receipt| receipt.receipt_kind)
        .collect();
    assert!(kinds.contains(&ReceiptKind::Gate));
    assert!(kinds.contains(&ReceiptKind::IdentityLifecycle));
    assert!(kinds.contains(&ReceiptKind::ScopedRead));
    assert!(kinds.contains(&ReceiptKind::Share));

    let gate = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(gate.len(), 1);
    assert_eq!(gate[0].actor.as_deref(), Some("agent-alpha"));

    let by_actor = vault.receipts(ReceiptQuery::new(10).with_actor(identity_actor.to_hex()))?;
    assert_eq!(by_actor.len(), 1);
    assert_eq!(by_actor[0].receipt_kind, ReceiptKind::IdentityLifecycle);

    let by_outcome = vault.receipts(ReceiptQuery::new(10).with_outcome("active"))?;
    assert_eq!(by_outcome.len(), 1);
    assert_eq!(by_outcome[0].receipt_kind, ReceiptKind::ScopedRead);

    let recent = vault.receipts(ReceiptQuery::new(10).with_time_bounds(Some(35), None))?;
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].receipt_kind, ReceiptKind::Share);
    Ok(())
}

#[test]
fn gate_receipt_query_paginates_past_legacy_scan_window() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.map_size = 128 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config)?;
    let target_actor = "agent-before-legacy-window";
    let target_id = append_gate_decision(
        &vault,
        3,
        target_actor,
        "pending",
        "gate.pending.actor_ceiling",
    )?;

    // The target has the older UUIDv7 decision id but the later event time.
    // Connector-key gate rows can have this shape because their `created_at`
    // is caller-supplied; selection must follow occurred_at, not scan order.
    std::thread::sleep(std::time::Duration::from_millis(2));
    vault.with_write_txn(|wtxn| {
        let mut decision = GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at: 2,
            outcome: "pending".to_owned(),
            reason_codes: vec!["gate.pending.actor_ceiling".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "agent".to_owned(),
            actor_ref: Some("agent-noise".to_owned()),
            content_kind: "claim".to_owned(),
            policy_manifest_version: "test-policy".to_owned(),
            claim_id: Some(*entity(0x42).as_bytes()),
            grant_ref: None,
            diff_handle: vec![0xA5],
            read_frontier_hash: [0xB6; 32],
        };
        for _ in 0..MAX_RECEIPT_QUERY_SCAN {
            decision.decision_id = GateDecisionId::now();
            vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        }
        Ok(())
    })?;

    reset_gate_receipt_pages_scanned();
    let recent = vault.receipts(ReceiptQuery::new(1).with_kind(ReceiptKind::Gate))?;
    assert_eq!(recent.len(), 1);
    assert_eq!(
        recent[0].receipt_id,
        format!("gate:{}", target_id.to_hex()),
        "newest selection follows occurred_at across decision-id pages"
    );
    assert_eq!(
        gate_receipt_pages_scanned(),
        2,
        "non-monotonic timestamps require scanning every decision-id page"
    );
    assert_eq!(
        gate_receipt_max_buffered(),
        1,
        "full pagination must retain only query.limit matching receipts"
    );

    reset_gate_receipt_pages_scanned();
    let receipts = vault.receipts(
        ReceiptQuery::new(1)
            .with_kind(ReceiptKind::Gate)
            .with_actor(target_actor),
    )?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].receipt_id,
        format!("gate:{}", target_id.to_hex())
    );
    assert_eq!(
        gate_receipt_pages_scanned(),
        2,
        "a filtered query must continue past the first page for an older match"
    );
    assert_eq!(gate_receipt_max_buffered(), 1);
    Ok(())
}

#[test]
fn gate_receipt_system_notice_selection_is_order_independent() {
    let decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 10,
        outcome: "block".to_owned(),
        reason_codes: vec!["gate.policy_model.block".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: vec![
            gate_system_notice("owner", "owner row details"),
            gate_system_notice(SYSTEM_NOTICE_AUDIENCE_ALL, "all audience notice"),
            gate_system_notice(
                SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY,
                "third-party safe notice",
            ),
        ],
        actor_class: "policy_model".to_owned(),
        actor_ref: Some("agent-alpha".to_owned()),
        content_kind: "outbound_content".to_owned(),
        policy_manifest_version: "test-policy".to_owned(),
        claim_id: None,
        grant_ref: None,
        diff_handle: vec![0xA5],
        read_frontier_hash: [0xB6; 32],
    };

    let receipt = gate_decision_receipt(&decision);
    assert_eq!(
        receipt
            .fields
            .get("system_notice_audience")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
    );
    assert_eq!(
        receipt.fields.get("system_notice").map(String::as_str),
        Some("third-party safe notice")
    );

    let notices = vec![
        gate_system_notice("owner", "owner row details"),
        gate_system_notice(SYSTEM_NOTICE_AUDIENCE_ALL, "all audience notice"),
    ];
    assert_eq!(
        select_gate_system_notice_for_receipt(&notices).map(|notice| notice.audience.as_str()),
        Some(SYSTEM_NOTICE_AUDIENCE_ALL)
    );

    let notices = vec![gate_system_notice("owner", "owner row details")];
    assert_eq!(
        select_gate_system_notice_for_receipt(&notices).map(|notice| notice.audience.as_str()),
        Some("owner")
    );
}

#[test]
fn receipt_query_filters_negative_space_outcomes_identically() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    append_gate_decision(&vault, 10, "agent-alpha", "delivered", "gate.allow")?;
    append_gate_decision(
        &vault,
        11,
        "agent-alpha",
        "held",
        "gate.pending.external_effect_authority",
    )?;
    append_gate_decision(
        &vault,
        12,
        "agent-beta",
        "let_go",
        "gate.pending.external_effect_authority",
    )?;

    let held = vault.receipts(ReceiptQuery::new(10).with_outcome("held"))?;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].outcome, "held");

    let let_go = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
    assert_eq!(let_go.len(), 1);
    assert_eq!(let_go[0].actor.as_deref(), Some("agent-beta"));

    let delivered = vault.receipts(ReceiptQuery::new(10).with_outcome("delivered"))?;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].outcome, "delivered");
    Ok(())
}

#[test]
fn pending_tray_returns_current_asks_with_age_hold_reason_and_receipt_view() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let old_claim = entity(0x81);
    let recent_claim = entity(0x82);
    let gone_claim = entity(0x83);
    append_pending_gate_consent(
        &vault,
        10,
        "agent-alpha",
        old_claim,
        "gate.pending.external_effect_authority",
        Some("dreamer-run-a"),
    )?;
    append_pending_gate_consent(
        &vault,
        30,
        "agent-beta",
        recent_claim,
        "gate.pending.source_trust",
        None,
    )?;
    append_gate_decision_for_claim(
        &vault,
        40,
        "agent-gamma",
        "let_go",
        "gate.pending.gap_decayed",
        gone_claim,
    )?;

    let asks = vault.pending_tray(PendingTrayQuery::at(50, 10))?;
    assert_eq!(asks.len(), 2);

    let old = &asks[0];
    assert_eq!(old.claim_id, old_claim.to_hex());
    assert_eq!(old.created_at, 10);
    assert_eq!(old.age_secs, 40);
    assert_eq!(old.hold_reason, "gate.pending.external_effect_authority");
    assert_eq!(
        old.hold_reasons,
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(old.dreamer_run_id.as_deref(), Some("dreamer-run-a"));
    assert_eq!(old.receipt_view.component, RECEIPT_VIEW_COMPONENT);
    assert_eq!(old.receipt_view.receipt.receipt_kind, ReceiptKind::Gate);
    assert_eq!(old.receipt_view.receipt.outcome, "pending");
    assert_eq!(
        old.receipt_view.receipt.actor.as_deref(),
        Some("agent-alpha")
    );
    assert_eq!(
        old.receipt_view.receipt.trigger_ref.as_deref(),
        Some(format!("claim:{}", old_claim.to_hex()).as_str())
    );

    let recent = &asks[1];
    assert_eq!(recent.claim_id, recent_claim.to_hex());
    assert_eq!(recent.age_secs, 20);
    assert_eq!(recent.hold_reason, "gate.pending.source_trust");
    assert!(
        asks.iter()
            .all(|ask| ask.claim_id.as_str() != gone_claim.to_hex())
    );
    Ok(())
}

#[test]
fn let_go_pending_ask_emits_receipt_before_clearing_tray() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let claim_id = entity(0x84);
    append_pending_gate_consent(
        &vault,
        10,
        "agent-alpha",
        claim_id,
        "gate.pending.external_effect_authority",
        Some("dreamer-run-a"),
    )?;

    let emitted = vault
        .let_go_pending_ask_at(&claim_id, 99)?
        .expect("age-out must emit a receipt");
    assert_eq!(emitted.receipt_kind, ReceiptKind::Gate);
    assert_eq!(emitted.outcome, "let_go");
    assert_eq!(emitted.actor.as_deref(), Some("agent-alpha"));
    assert_eq!(
        emitted.trigger_ref.as_deref(),
        Some(format!("claim:{}", claim_id.to_hex()).as_str())
    );
    assert_eq!(emitted.policy_trace, vec!["gate.pending.gap_decayed"]);

    assert!(
        vault
            .pending_tray(PendingTrayQuery::at(100, 10))?
            .is_empty()
    );
    let let_go = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
    assert_eq!(let_go.len(), 1);
    assert_eq!(let_go[0], emitted);

    assert!(vault.let_go_pending_ask_at(&claim_id, 120)?.is_none());
    let still_one = vault.receipts(ReceiptQuery::new(10).with_outcome("let_go"))?;
    assert_eq!(still_one.len(), 1);
    Ok(())
}

#[test]
fn receipt_query_never_returns_floor_redaction_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let floor_id = entity(0x70);
    put_redaction_floor_receipt(&vault, floor_id, 50)?;
    append_gate_decision(
        &vault,
        10,
        "agent-alpha",
        "pending",
        "gate.pending.actor_ceiling",
    )?;

    let all = vault.receipts(ReceiptQuery::new(10))?;
    assert!(
        all.iter()
            .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
    );

    for kind in [
        ReceiptKind::Outbound,
        ReceiptKind::Gate,
        ReceiptKind::IdentityLifecycle,
        ReceiptKind::ScopedRead,
        ReceiptKind::Share,
    ] {
        let rows = vault.receipts(ReceiptQuery::new(10).with_kind(kind))?;
        assert!(
            rows.iter()
                .all(|receipt| !receipt.receipt_id.contains(&floor_id.to_hex()))
        );
    }
    Ok(())
}

#[test]
fn brief_projection_returns_multi_session_party_tree_and_budget() {
    let receipts = vec![
        projected_receipt(
            "outbound:intent:invite-yuki",
            ReceiptKind::Outbound,
            100,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:invite-yuki"),
            &[
                ("run_ref", "run:planning"),
                ("intent_ref", "intent:invite-yuki"),
                ("counterparty_ref", "person:yuki"),
                ("grant_ref", "party-grant"),
                ("budget_debit", "3"),
            ],
        ),
        projected_receipt(
            "outbound:intent:invite-kenji",
            ReceiptKind::Outbound,
            101,
            "held",
            Some("brief:party"),
            Some("intent:invite-kenji"),
            &[
                ("run_ref", "run:planning"),
                ("intent_ref", "intent:invite-kenji"),
                ("counterparty_ref", "person:kenji"),
                ("grant_ref", "party-grant"),
                ("budget_debit", "2"),
            ],
        ),
        projected_receipt(
            "outbound:intent:invite-mika",
            ReceiptKind::Outbound,
            102,
            "suppressed",
            Some("brief:party"),
            Some("intent:invite-mika"),
            &[
                ("run_ref", "run:followup"),
                ("intent_ref", "intent:invite-mika"),
                ("counterparty_ref", "person:mika"),
                ("first_touch", "user_introduction"),
                ("opt_out", "false"),
                ("promo_consent", "true"),
                ("budget_debit", "1"),
            ],
        ),
        projected_receipt(
            "gate:bundle-party",
            ReceiptKind::Gate,
            103,
            "approved",
            Some("brief:party"),
            Some("bundle:party-invites"),
            &[
                ("run_ref", "run:planning"),
                ("bundle_ref", "bundle:party-invites"),
                ("event", "bundle"),
            ],
        ),
        projected_receipt(
            "scoped_read:party-grant:created",
            ReceiptKind::ScopedRead,
            90,
            "active",
            Some("brief:party"),
            Some("access_grant:party-grant"),
            &[("grant_ref", "party-grant")],
        ),
    ];

    let projection = project_receipts_by_brief("brief:party", receipts.clone());

    assert_eq!(projection.brief_ref, "brief:party");
    assert_eq!(projection.runs.len(), 2);
    assert_eq!(projection.consent_grants.len(), 1);
    assert_eq!(projection.bundles.len(), 1);
    assert_eq!(projection.budget_debit_total, 6);

    let planning = projection
        .runs
        .iter()
        .find(|run| run.run_ref == "run:planning")
        .expect("planning run");
    let outcomes = planning
        .intents
        .iter()
        .flat_map(|intent| {
            intent
                .receipts
                .iter()
                .map(|receipt| receipt.outcome.as_str())
        })
        .collect::<BTreeSet<_>>();
    assert!(outcomes.contains("delivered_to_channel"));
    assert!(outcomes.contains("held"));
    assert_eq!(
        planning.direct_receipts[0].trigger_ref.as_deref(),
        Some("bundle:party-invites")
    );

    let counterparties = project_receipts_by_counterparty(receipts.clone());
    let mika = counterparties
        .iter()
        .find(|projection| projection.counterparty_ref == "person:mika")
        .expect("mika counterparty projection");
    assert_eq!(mika.first_touch.as_deref(), Some("user_introduction"));
    assert_eq!(mika.opt_out, Some(false));
    assert_eq!(mika.promo_consent, Some(true));

    let grant = project_receipts_by_grant("party-grant", receipts);
    let sends = grant
        .receipts
        .iter()
        .filter(|receipt| receipt.receipt_kind == ReceiptKind::Outbound)
        .count();
    assert_eq!(sends, 2);
    assert_eq!(grant.budget_debit_total, 5);
}

#[test]
fn projections_avoid_grant_trigger_collisions_and_consent_false_positive() {
    let receipts = vec![
        projected_receipt(
            "gate:bundle-party-grant",
            ReceiptKind::Gate,
            100,
            "approved",
            Some("brief:party"),
            Some("bundle:party-grant"),
            &[("bundle_ref", "bundle:party-grant")],
        ),
        projected_receipt(
            "outbound:grant-trigger",
            ReceiptKind::Outbound,
            101,
            "delivered_to_channel",
            Some("brief:party"),
            Some("access_grant:party-grant"),
            &[("grant_ref", "party-grant"), ("budget_debit", "2")],
        ),
    ];

    let grant = project_receipts_by_grant("party-grant", receipts.clone());
    assert_eq!(grant.receipts.len(), 1);
    assert_eq!(grant.receipts[0].receipt_id, "outbound:grant-trigger");
    assert_eq!(grant.budget_debit_total, 2);

    let brief = project_receipts_by_brief("brief:party", receipts);
    assert_eq!(brief.bundles.len(), 1);
    assert!(brief.consent_grants.is_empty());
}

#[test]
fn counterparty_projection_preserves_latest_contact_flags() {
    let receipts = vec![
        projected_receipt(
            "outbound:older",
            ReceiptKind::Outbound,
            10,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:older"),
            &[
                ("counterparty_ref", "kenji@example.com"),
                ("opt_out", "true"),
                ("promo_consent", "false"),
            ],
        ),
        projected_receipt(
            "outbound:newer",
            ReceiptKind::Outbound,
            20,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:newer"),
            &[
                ("counterparty_ref", "kenji@example.com"),
                ("opt_out", "false"),
                ("promo_consent", "true"),
            ],
        ),
    ];

    let projections = project_receipts_by_counterparty(receipts);

    assert_eq!(projections.len(), 1);
    assert_eq!(projections[0].opt_out, Some(false));
    assert_eq!(projections[0].promo_consent, Some(true));
}

#[test]
fn counterparty_projection_joins_contact_records() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let identity_ref = entity(0x91);
    let contact =
        CounterpartyContactRecord::user_introduction(identity_ref, "kenji@example.com", 10)?
            .with_promo_consent(true, 11)?
            .opted_out(CounterpartyOptOutReason::Stop, 12)?;
    vault.create_counterparty_contact(&entity(0x92), &contact)?;
    let identity_ref_hex = identity_ref.to_hex();
    let receipts = vec![projected_receipt(
        "outbound:joined-contact",
        ReceiptKind::Outbound,
        20,
        "delivered_to_channel",
        Some("brief:party"),
        Some("intent:joined-contact"),
        &[
            ("counterparty_ref", "kenji@example.com"),
            ("channel_identity_ref", identity_ref_hex.as_str()),
            ("budget_debit", "2"),
        ],
    )];

    let contacts = counterparty_contact_records_for_receipts(&vault, &receipts)?;
    let projections = project_receipts_by_counterparty_with_contacts(receipts, &contacts);

    assert_eq!(projections.len(), 1);
    assert_eq!(
        projections[0].first_touch.as_deref(),
        Some("user_introduction")
    );
    assert_eq!(projections[0].opt_out, Some(true));
    assert_eq!(projections[0].promo_consent, Some(true));
    assert_eq!(projections[0].budget_debit_total, 2);
    Ok(())
}

#[test]
fn counterparty_projection_combines_multi_identity_contacts_conservatively() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    let identity_a = entity(0x71);
    let identity_b = entity(0x72);
    let opted_out = CounterpartyContactRecord::inbound_first(identity_a, "kenji@example.com", 5)?
        .opted_out(CounterpartyOptOutReason::Stop, 8)?;
    let consented =
        CounterpartyContactRecord::user_introduction(identity_b, "kenji@example.com", 10)?
            .with_promo_consent(true, 11)?;
    vault.create_counterparty_contact(&entity(0x73), &opted_out)?;
    vault.create_counterparty_contact(&entity(0x74), &consented)?;
    let identity_a_hex = identity_a.to_hex();
    let identity_b_hex = identity_b.to_hex();
    let receipts = vec![
        projected_receipt(
            "outbound:identity-a",
            ReceiptKind::Outbound,
            20,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:identity-a"),
            &[
                ("counterparty_ref", "kenji@example.com"),
                ("channel_identity_ref", identity_a_hex.as_str()),
            ],
        ),
        projected_receipt(
            "outbound:identity-b",
            ReceiptKind::Outbound,
            21,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:identity-b"),
            &[
                ("counterparty_ref", "kenji@example.com"),
                ("channel_identity_ref", identity_b_hex.as_str()),
            ],
        ),
    ];

    let contacts = counterparty_contact_records_for_receipts(&vault, &receipts)?;
    let projections = project_receipts_by_counterparty_with_contacts(receipts, &contacts);

    assert_eq!(projections.len(), 1);
    assert_eq!(projections[0].first_touch.as_deref(), Some("inbound_first"));
    assert_eq!(projections[0].opt_out, Some(true));
    assert_eq!(projections[0].promo_consent, Some(false));
    Ok(())
}

#[test]
fn grant_projection_filters_before_projection_limit() {
    let receipts = vec![
        projected_receipt(
            "outbound:unrelated-newer",
            ReceiptKind::Outbound,
            50,
            "delivered_to_channel",
            Some("brief:other"),
            Some("intent:unrelated"),
            &[("grant_ref", "other-grant"), ("budget_debit", "9")],
        ),
        projected_receipt(
            "outbound:grant-newer",
            ReceiptKind::Outbound,
            20,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:grant-newer"),
            &[("grant_ref", "party-grant"), ("budget_debit", "3")],
        ),
        projected_receipt(
            "outbound:grant-older",
            ReceiptKind::Outbound,
            10,
            "delivered_to_channel",
            Some("brief:party"),
            Some("intent:grant-older"),
            &[("grant_ref", "party-grant"), ("budget_debit", "2")],
        ),
    ];

    let projection = project_receipts_by_grant_limited("party-grant", receipts, 1);

    assert_eq!(projection.receipts.len(), 1);
    assert_eq!(projection.receipts[0].receipt_id, "outbound:grant-newer");
    assert_eq!(projection.budget_debit_total, 5);
}

#[test]
fn brief_projection_chain_walks_when_job_ref_is_absent() {
    let receipts = vec![
        projected_receipt(
            "gate:run-planning",
            ReceiptKind::Gate,
            10,
            "started",
            None,
            Some("run:planning"),
            &[("parent_ref", "brief:party")],
        ),
        projected_receipt(
            "outbound:intent:invite-aki",
            ReceiptKind::Outbound,
            11,
            "delivered_to_channel",
            None,
            Some("intent:invite-aki"),
            &[
                ("run_ref", "run:planning"),
                ("counterparty_ref", "person:aki"),
                ("budget_debit", "4"),
            ],
        ),
    ];

    let projection = project_receipts_by_brief("brief:party", receipts);

    assert_eq!(projection.runs.len(), 1);
    assert_eq!(projection.runs[0].run_ref, "run:planning");
    assert_eq!(projection.runs[0].intents.len(), 1);
    assert_eq!(
        projection.runs[0].intents[0].receipts[0]
            .trigger_ref
            .as_deref(),
        Some("intent:invite-aki")
    );
    assert_eq!(projection.budget_debit_total, 4);
}

#[test]
fn brief_projection_chain_walks_nested_runs() {
    let receipts = vec![
        projected_receipt(
            "gate:run-parent",
            ReceiptKind::Gate,
            10,
            "started",
            None,
            Some("run:parent"),
            &[("parent_ref", "brief:party")],
        ),
        projected_receipt(
            "gate:run-child",
            ReceiptKind::Gate,
            11,
            "started",
            None,
            Some("run:child"),
            &[("parent_ref", "run:parent")],
        ),
        projected_receipt(
            "outbound:intent:child",
            ReceiptKind::Outbound,
            12,
            "delivered_to_channel",
            None,
            Some("intent:child"),
            &[
                ("run_ref", "run:child"),
                ("intent_ref", "intent:child"),
                ("budget_debit", "5"),
            ],
        ),
    ];

    let projection = project_receipts_by_brief("brief:party", receipts);
    let child = projection
        .runs
        .iter()
        .find(|run| run.run_ref == "run:child")
        .expect("child run should chain back to brief");

    assert_eq!(child.intents.len(), 1);
    assert_eq!(child.intents[0].intent_ref, "intent:child");
    assert_eq!(child.intents[0].receipts.len(), 1);
    assert_eq!(projection.budget_debit_total, 5);
}

fn test_prompt_stamp() -> PromptRecompileStamp {
    PromptRecompileStamp {
        schema_version: crate::prompt::PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION.to_owned(),
        prompt_path: "eiri/v3.md".to_owned(),
        compiled_at_secs: 1_700_000_000,
        source_fingerprint: "feedbead".to_owned(),
        resolved_fingerprint: "deadbeef".to_owned(),
        source_paths: vec!["eiri/v3.md".to_owned()],
    }
}

fn test_memory_board(claim_score: f32) -> EiriMemoryBoard {
    use crate::eiri::EIRI_CONTEXT_VERSION_V4;
    use crate::eiri::EiriMemoryBoardBudget;
    use crate::eiri::EiriMemoryBoardRow;
    use crate::eiri::EiriMemoryBoardSlot;
    use crate::eiri::EiriMemoryBoardSource;

    let row =
        |row_index: usize, seed: u8, slot: EiriMemoryBoardSlot, score: f32| EiriMemoryBoardRow {
            row_index,
            slot,
            source: EiriMemoryBoardSource::Result,
            id: entity(seed).to_hex(),
            short_id: format!("mem{seed:02x}"),
            content_hash: format!("{seed:02x}"),
            entity_type: if slot == EiriMemoryBoardSlot::Claims {
                crate::registry::ENTITY_TYPE_CLAIM
            } else {
                crate::registry::ENTITY_TYPE_SUMMARY
            },
            asset_ref: None,
            score,
        };

    EiriMemoryBoard {
        version: EIRI_CONTEXT_VERSION_V4.to_owned(),
        budget: EiriMemoryBoardBudget::new(2, 0, 1, 0, 0, 0),
        rows: vec![
            row(0, 0x21, EiriMemoryBoardSlot::Claims, claim_score),
            row(1, 0x22, EiriMemoryBoardSlot::Claims, 0.25),
            row(2, 0x31, EiriMemoryBoardSlot::Summaries, 0.125),
        ],
        companion: None,
        disclosure: None,
    }
}

#[test]
fn context_receipt_field_set_rides_emit_receipts_and_round_trips() {
    let board = test_memory_board(0.5);
    let context = ContextReceiptFields::from_assembly(&test_prompt_stamp(), &board)
        .expect("assembled board stamps")
        .substrate_ref(format!("model:{}", entity(0x77).to_hex()))
        .model("test-model-v1")
        .reasoning_effort("high")
        .prompt_input_ref("prompt:cafe1234");

    assert_eq!(
        context.persona_compile_stamp,
        "oneiron.prompt_recompile.v1:deadbeef"
    );
    assert_eq!(
        context.activated_memory_ids,
        vec![
            entity(0x21).to_hex(),
            entity(0x22).to_hex(),
            entity(0x31).to_hex(),
        ]
    );
    assert!(context.board_state_ref.starts_with("board:"));
    assert_eq!(
        context.board_state_ref,
        eiri_memory_board_state_ref(&board).expect("assembled board hashes")
    );

    let mut receipt = projected_receipt(
        "outbound:intent:say-it",
        ReceiptKind::Outbound,
        100,
        "delivered_to_channel",
        Some("brief:party"),
        Some("intent:say-it"),
        &[("intent_ref", "intent:say-it")],
    );
    append_context_receipt_fields(&mut receipt, &context).expect("emit receipt accepts stamp");

    assert_eq!(
        receipt
            .fields
            .get(FIELD_ACTIVATED_MEMORY_IDS)
            .map(String::as_str),
        Some(
            format!(
                "{},{},{}",
                entity(0x21).to_hex(),
                entity(0x22).to_hex(),
                entity(0x31).to_hex()
            )
            .as_str()
        )
    );
    assert_eq!(
        receipt.fields.get(FIELD_MODEL).map(String::as_str),
        Some("test-model-v1")
    );
    assert_eq!(receipt.context_receipt_fields(), Some(context));
}

#[test]
fn context_receipt_field_set_is_rejected_on_non_emit_receipts() {
    let context =
        ContextReceiptFields::from_assembly(&test_prompt_stamp(), &test_memory_board(0.5))
            .expect("assembled board stamps");

    for kind in [
        ReceiptKind::Gate,
        ReceiptKind::IdentityLifecycle,
        ReceiptKind::ScopedRead,
        ReceiptKind::Share,
    ] {
        assert!(!kind.is_emit_adjacent());
        let mut receipt = projected_receipt(
            &format!("{}:receipt", kind.as_str()),
            kind,
            100,
            "allow",
            None,
            None,
            &[],
        );
        let fields_before = receipt.fields.clone();
        let error = append_context_receipt_fields(&mut receipt, &context)
            .expect_err("non-emit receipts never carry emit context");
        assert!(matches!(error, Error::EmitAdjacentReceiptRequired { .. }));
        assert_eq!(receipt.fields, fields_before, "rejection must not write");
    }

    // Extraction is kind-gated too: context keys smuggled onto a non-emit
    // receipt stay unreadable through the field-set surface.
    let mut smuggled = projected_receipt(
        "gate:receipt",
        ReceiptKind::Gate,
        100,
        "allow",
        None,
        None,
        &[],
    );
    context.append_to_fields(&mut smuggled.fields);
    assert_eq!(smuggled.context_receipt_fields(), None);
}

#[test]
fn board_state_ref_records_the_board_as_shown() -> Result<()> {
    let board = test_memory_board(0.5);
    assert_eq!(
        eiri_memory_board_state_ref(&board)?,
        eiri_memory_board_state_ref(&test_memory_board(0.5))?,
        "same board as shown, same ref"
    );
    assert_ne!(
        eiri_memory_board_state_ref(&board)?,
        eiri_memory_board_state_ref(&test_memory_board(0.75))?,
        "retrieval drift changes the ref"
    );
    Ok(())
}

#[test]
fn session_local_receipt_log_deletes_off_record_emit_receipts_at_close() {
    let emit_receipt = |receipt_id: &str| {
        projected_receipt(
            receipt_id,
            ReceiptKind::Outbound,
            100,
            "delivered_to_channel",
            None,
            None,
            &[],
        )
    };

    let mut off_record = SessionLocalReceiptLog::off_record("session:off-record");
    off_record
        .record(emit_receipt("outbound:intent:one"))
        .expect("emit receipt rides the session log");
    off_record
        .record(emit_receipt("outbound:intent:two"))
        .expect("emit receipt rides the session log");
    assert!(off_record.is_off_record());
    assert_eq!(
        off_record.receipts().len(),
        2,
        "visible while session lives"
    );

    let closed = off_record.close();
    assert!(closed.off_record);
    assert_eq!(closed.deleted, 2);
    assert!(closed.retained.is_empty(), "deleted with the transcript");

    let mut on_record = SessionLocalReceiptLog::on_record("session:on-record");
    on_record
        .record(emit_receipt("outbound:intent:three"))
        .expect("emit receipt rides the session log");
    let closed = on_record.close();
    assert!(!closed.off_record);
    assert_eq!(closed.deleted, 0);
    assert_eq!(closed.retained.len(), 1);

    // Floor receipts persist through their own substrates and must never
    // become deletable via session close.
    let mut log = SessionLocalReceiptLog::off_record("session:off-record");
    let error = log
        .record(projected_receipt(
            "gate:floor",
            ReceiptKind::Gate,
            100,
            "allow",
            None,
            None,
            &[],
        ))
        .expect_err("floor receipts never ride the session log");
    assert!(matches!(error, Error::EmitAdjacentReceiptRequired { .. }));
    assert!(log.receipts().is_empty());
}

#[test]
fn family_projections_never_carry_context_fields() -> Result<()> {
    let (_tmp, vault) = temp_vault()?;
    append_gate_decision(&vault, 10, "agent-alpha", "allow", "gate.allow")?;

    let receipts = vault.receipts(ReceiptQuery::new(50))?;
    assert!(!receipts.is_empty());
    for receipt in receipts {
        assert!(!receipt.receipt_kind.is_emit_adjacent());
        assert_eq!(receipt.context_receipt_fields(), None);
        for key in [
            FIELD_PERSONA_COMPILE_STAMP,
            FIELD_ACTIVATED_MEMORY_IDS,
            FIELD_BOARD_STATE_REF,
            FIELD_SUBSTRATE_REF,
            FIELD_MODEL,
            FIELD_REASONING_EFFORT,
            FIELD_PROMPT_INPUT_REF,
        ] {
            assert!(
                !receipt.fields.contains_key(key),
                "{} leaked the context field {key}",
                receipt.receipt_id
            );
        }
    }
    Ok(())
}

#[test]
fn disclosure_stamp_rides_emit_receipts_and_reads_optionally() {
    let board = test_memory_board(0.5);
    let context = ContextReceiptFields::from_assembly(&test_prompt_stamp(), &board)
        .expect("assembled board stamps")
        .disclosure_stamp("mode=supervised;interlocutors=owner:owner,known_contact:kenji");

    let mut receipt = projected_receipt(
        "outbound:intent:say-it",
        ReceiptKind::Outbound,
        100,
        "delivered_to_channel",
        Some("brief:party"),
        Some("intent:say-it"),
        &[("intent_ref", "intent:say-it")],
    );
    append_context_receipt_fields(&mut receipt, &context).expect("emit receipt accepts stamp");
    assert_eq!(
        receipt
            .fields
            .get(FIELD_DISCLOSURE_STAMP)
            .map(String::as_str),
        Some("mode=supervised;interlocutors=owner:owner,known_contact:kenji")
    );
    assert_eq!(receipt.context_receipt_fields(), Some(context));

    // Receipts stamped before the disclosure clamp existed read back with
    // the field absent; the three existing fields keep their required-ness.
    let mut legacy = projected_receipt(
        "outbound:intent:older",
        ReceiptKind::Outbound,
        100,
        "delivered_to_channel",
        Some("brief:party"),
        Some("intent:older"),
        &[("intent_ref", "intent:older")],
    );
    let legacy_context = ContextReceiptFields::from_assembly(&test_prompt_stamp(), &board)
        .expect("assembled board stamps");
    append_context_receipt_fields(&mut legacy, &legacy_context).expect("emit receipt");
    let read_back = legacy.context_receipt_fields().expect("field-set reads");
    assert_eq!(read_back.disclosure_stamp, None);
}

/// MS-01 (ARCH-0055) SPEC-CONTRADICTION: the earlier perimeter regression
/// claimed out-of-window rows must not charge the cap. That contract was the
/// bug: it capped candidates, not WORK, and allowed an unbounded ledger walk.
/// The ruled security property caps every visited row. Because UUID mint
/// order is not `at` order, the bounded scan can starve the older-minted
/// in-window receipt below; an `at`-ordered index or cursor pagination is a
/// separate deferred design item.
#[test]
fn identity_topology_receipt_scan_caps_visited_rows() -> Result<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
    };

    let dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.map_size = 256 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config)?;
    for seed in [0x61_u8, 0x62, 0x63, 0x64] {
        vault.put_entity(
            &entity(seed),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }
    let merge = |sources: Vec<EntityId>, survivor: EntityId| {
        IdentityTopologyOp::Merge(MergeOp {
            sources,
            survivor,
            evidence: IdentityOpEvidence::default(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        })
    };

    // The in-window receipt has the OLDEST mint id (scanned LAST).
    vault.apply_identity_topology_op(
        &merge(vec![entity(0x62)], entity(0x61)),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        1_000,
    )?;

    // Newer-minted, BACKDATED, parked events — more than the scan cap.
    let proposed = IdentityOpWrite {
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Proposed,
        confidence: 1.0,
        actor: None,
    };
    let flood = merge(vec![entity(0x64)], entity(0x63));
    vault.with_write_txn(|wtxn| {
        for _ in 0..=MAX_RECEIPT_QUERY_SCAN {
            vault.apply_identity_topology_op_in_txn(wtxn, &flood, &proposed, 10)?;
        }
        Ok(())
    })?;

    let receipts = vault.receipts(
        ReceiptQuery::new(10)
            .with_kind(ReceiptKind::IdentityLifecycle)
            .with_time_bounds(Some(500), Some(2_000)),
    )?;
    assert!(
        receipts.is_empty(),
        "the visited-row work cap must stop before an older-minted receipt hidden by the flood"
    );
    Ok(())
}
