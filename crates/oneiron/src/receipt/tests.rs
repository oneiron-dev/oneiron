use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body,
};
use crate::store::{GateDecisionId, PendingGateConsentRecord, Store};
use crate::temporal::TimeRange;

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), embedding_test_config())?;
    Ok((dir, vault))
}

use crate::error::ClaimError;
use crate::test_util::{embedding_test_config, entity};

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

#[test]
fn durable_send_receipt_requires_explicit_outcome() {
    #[derive(Serialize)]
    struct MissingOutcomeReceipt {
        version: u8,
        task_ref: String,
        transport_dispatched: bool,
        receipt: ReceiptRecord,
    }

    let task_ref = entity(0x5E);
    let task_ref_hex = task_ref.to_hex();
    let receipt = ReceiptRecord {
        receipt_id: "outbound:required-outcome".to_owned(),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: 10,
        actor: None,
        on_behalf_of: None,
        outcome: "delivered_to_channel".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: field_map(&[
            (FIELD_TASK_REF, task_ref_hex.as_str()),
            (FIELD_TRANSPORT_DISPATCHED, "true"),
        ]),
    };
    let encoded = rmp_serde::to_vec_named(&MissingOutcomeReceipt {
        version: SEND_RECEIPT_RECORD_VERSION,
        task_ref: task_ref_hex,
        transport_dispatched: true,
        receipt,
    })
    .expect("encode missing-outcome fixture");

    // Discriminating: restoring the old serde default would decode this row
    // as Delivered and silently recreate receipt resend authority.
    assert!(decode_durable_send_receipt(task_ref.as_bytes(), &encoded).is_err());
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
                redacted_at: None,
            },
        )
    })?;
    Ok(decision_id)
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

fn put_federation_grant(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
    let grant = FederationGrant::new(
        FederationGrantScope::vault(7),
        entity(0x61),
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let body = encode_federation_grant_body(&grant)?;
    vault.with_write_txn(|wtxn| {
        let payload = crate::test_util::entity_record(
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        );
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

#[test]
fn gate_receipt_query_paginates_past_legacy_scan_window() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = embedding_test_config();
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
            claim_id: Some(*entity(0x53).as_bytes()),
            grant_ref: None,
            diff_handle: vec![0xA5],
            read_frontier_hash: [0xB6; 32],
            redacted_at: None,
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
        "newest selection follows occurred_at across decision-id pages",
    );
    assert!(
        gate_receipt_max_buffered() <= 1,
        "full pagination must retain at most query.limit matching receipts",
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
        format!("gate:{}", target_id.to_hex()),
    );
    assert!(
        gate_receipt_max_buffered() <= 1,
        "filtered pagination must retain at most query.limit matching receipts",
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

fn test_prompt_stamp() -> PromptRecompileStamp {
    PromptRecompileStamp {
        schema_version: crate::prompt::PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION.to_owned(),
        prompt_path: "eiri/v3.md".to_owned(),
        compiled_at_secs: 1_700_000_000,
        source_fingerprint: "feedbead".to_owned(),
        resolved_fingerprint: "deadbeef".to_owned(),
        assembled_fingerprint: None,
        source_paths: vec!["eiri/v3.md".to_owned()],
    }
}

fn test_memory_board(claim_score: f32) -> MemoriesSection {
    use crate::context_board::MEMORIES_SECTION_VERSION_V4;
    use crate::context_board::MemoriesBudget;
    use crate::context_board::MemoryRow;
    use crate::context_board::MemorySlot;
    use crate::context_board::MemorySource;

    let row = |row_index: usize, seed: u8, slot: MemorySlot, score: f32| MemoryRow {
        row_index,
        slot,
        source: MemorySource::Result,
        id: entity(seed).to_hex(),
        short_id: format!("mem{seed:02x}"),
        content_hash: format!("{seed:02x}"),
        entity_type: if slot == MemorySlot::Claims {
            crate::registry::ENTITY_TYPE_CLAIM
        } else {
            crate::registry::ENTITY_TYPE_SUMMARY
        },
        asset_ref: None,
        score,
        claim_source: None,
        world: None,
        tier: crate::context_board::MemoryTier::Snippet,
        snippet: None,
    };

    MemoriesSection {
        version: MEMORIES_SECTION_VERSION_V4.to_owned(),
        budget: MemoriesBudget::new(2, 0, 1, 0, 0, 0),
        rows: vec![
            row(0, 0x21, MemorySlot::Claims, claim_score),
            row(1, 0x22, MemorySlot::Claims, 0.25),
            row(2, 0x31, MemorySlot::Summaries, 0.125),
        ],
        companion: None,
        disclosure: None,
    }
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
        assert!(matches!(
            error,
            Error::Claim(ClaimError::EmitAdjacentReceiptRequired { .. })
        ));
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
    assert!(matches!(
        error,
        Error::Claim(ClaimError::EmitAdjacentReceiptRequired { .. })
    ));
    assert!(log.receipts().is_empty());
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

    const SCAN_CAP: usize = 8;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), embedding_test_config())?;
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
        for _ in 0..=SCAN_CAP {
            vault.apply_identity_topology_op_in_txn(wtxn, &flood, &proposed, 10)?;
        }
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let receipts = super::identity_kind::identity_topology_receipts(
        &vault,
        &rtxn,
        &ReceiptQuery::new(10)
            .with_kind(ReceiptKind::IdentityLifecycle)
            .with_time_bounds(Some(500), Some(2_000)),
        SCAN_CAP,
    )?;
    assert!(
        receipts.is_empty(),
        "the visited-row work cap must stop before an older-minted receipt hidden by the flood"
    );
    Ok(())
}

// ─── ONE-1737 · ARCH-0053 §2 pack-manifest receipt fields ───────────────

fn manifest_receipt() -> ReceiptRecord {
    projected_receipt(
        "attempt:oracle",
        ReceiptKind::Outbound,
        20,
        "completed",
        None,
        None,
        &[],
    )
}

/// The terminal receipt carries the FULL accumulated manifest, split by kind,
/// in append order — never sorted, never deduped: the sequence IS the evidence.
#[test]
fn pack_manifest_projects_both_kinds_in_append_order() -> Result<()> {
    let manifest = [
        ManifestEntry::new(ManifestKind::Skill, "pdf", "3", 11),
        ManifestEntry::new(ManifestKind::ActorClaim, "actor.lesson", "7", 12),
        ManifestEntry::new(ManifestKind::Skill, "index", "1", 13),
    ];
    let mut receipt = manifest_receipt();

    append_pack_manifest_fields(&mut receipt, &manifest)?;

    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["pdf@3".to_owned(), "index@1".to_owned()]),
        "skills keep manifest order, not sorted order"
    );
    assert_eq!(
        receipt.pack_manifest_actor_claims(),
        Some(vec!["actor.lesson@7".to_owned()])
    );
    Ok(())
}

/// Repeated pulls of the same skill@version stay repeated: collapsing them
/// would erase how many times the pack reached for it.
#[test]
fn repeated_pulls_are_not_deduped() -> Result<()> {
    let manifest = [
        ManifestEntry::new(ManifestKind::Skill, "pdf", "3", 11),
        ManifestEntry::new(ManifestKind::Skill, "pdf", "3", 12),
    ];
    let mut receipt = manifest_receipt();

    append_pack_manifest_fields(&mut receipt, &manifest)?;

    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["pdf@3".to_owned(), "pdf@3".to_owned()])
    );
    Ok(())
}

/// The stamped ledger is keyed by receipt id, so a fabricated `receipt_ref`
/// resolves to nothing even while a real receipt sits beside it. Attribution's
/// evidence door rests on exactly this property.
#[test]
fn the_pack_receipt_ledger_resolves_only_ids_it_stamped() -> Result<()> {
    use crate::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    };

    let (_dir, vault) = temp_vault()?;
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "pack".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::Skill, "index", "1", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("the enqueued attempt is claimable");
    };
    assert!(
        queue
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: "worker".to_owned(),
                attempt_count: leased.attempt_count,
                now: 13,
            })
            .is_err(),
        "skill-bearing attempt cannot settle without a model"
    );
    assert!(attempt_pack_receipt(&vault, &attempt_pack_receipt_id(&attempt.id))?.is_none());
    assert_eq!(
        queue.get(attempt.id)?.unwrap().state,
        crate::attempt_queue::AttemptState::Leased
    );
    queue.set_executor_model(
        attempt.id,
        "worker",
        leased.attempt_count,
        "fixture/model@1",
    )?;
    queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;

    assert!(
        attempt_pack_receipt(&vault, &attempt_pack_receipt_id(&attempt.id))?.is_some(),
        "the id the queue stamped resolves"
    );
    assert_eq!(
        attempt_pack_receipt(&vault, "attempt:00000000000000000000000000000000")?,
        None,
        "a well-formed but unstamped attempt id resolves to nothing"
    );
    assert_eq!(
        attempt_pack_receipt(&vault, "receipt:fabricated")?,
        None,
        "a receipt id from another namespace never resolves here"
    );
    Ok(())
}

/// Pack receipt rows persist for the life of the vault — unlike the attempt
/// events they project from, which drain — so an uncapped family scan degrades
/// monotonically with attempt history and is attacker-growable. The scan is
/// therefore bounded, the bound keeps the NEWEST rows (the family query is
/// newest-first by contract), and a bound that fires SAYS SO rather than
/// answering from a silent prefix.
#[test]
fn the_pack_receipt_scan_stops_at_the_family_cap_and_signals_it() -> Result<()> {
    // A big-endian index in the leading id bytes: fixed-width lowercase hex
    // sorts lexicographically by index, so ledger key order reproduces the
    // mint order a real UUIDv7 attempt id carries.
    fn flood_receipt_id(index: u32) -> String {
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        let id = AttemptId::from_bytes(&bytes).expect("16 bytes is a well-formed attempt id");
        attempt_pack_receipt_id(&id)
    }

    let dir = tempfile::tempdir()?;
    let mut config = embedding_test_config();
    // A cap-sized ledger outgrows the 16 MiB default test map.
    config.map_size = 256 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config)?;

    let cap = u32::try_from(MAX_RECEIPT_QUERY_SCAN).expect("the scan cap fits in u32");
    let oldest = flood_receipt_id(0);
    let newest = flood_receipt_id(cap);

    // Exactly ONE row past the cap: the smallest ledger that must truncate.
    let mut receipt = projected_receipt("", ReceiptKind::Outbound, 0, "completed", None, None, &[]);
    vault.with_write_txn(|wtxn| {
        for index in 0..=cap {
            receipt.receipt_id = flood_receipt_id(index);
            receipt.occurred_at = u64::from(index);
            put_attempt_pack_receipt_for_test(&vault.store, wtxn, &receipt)?;
        }
        Ok(())
    })?;

    reset_attempt_pack_scan_capped();
    let scanned = attempt_pack_receipts(&vault)?;

    assert_eq!(
        scanned.len(),
        MAX_RECEIPT_QUERY_SCAN,
        "the scan terminates at the family work cap instead of walking the ledger"
    );
    assert_eq!(
        attempt_pack_scan_capped(),
        1,
        "a truncated scan raises the cap signal exactly once"
    );
    assert!(
        scanned.iter().any(|receipt| receipt.receipt_id == newest),
        "the cap keeps the newest row"
    );
    assert!(
        !scanned.iter().any(|receipt| receipt.receipt_id == oldest),
        "the row the cap discards is the oldest one, never the newest"
    );

    let public = vault.receipts(ReceiptQuery::new(1).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(
        attempt_pack_scan_capped(),
        2,
        "the public query door is bounded by the same cap"
    );
    assert_eq!(
        public.len(),
        1,
        "the public door still honours the caller's limit"
    );
    assert_eq!(
        public[0].receipt_id, newest,
        "newest-first answers from the capped set, not from its oldest edge"
    );
    Ok(())
}

#[test]
fn brief_share_preserves_legacy_share_receipt_bytes_and_namespaces() -> Result<()> {
    use crate::persona_snapshot::PersonaSnapshotExportRecord;

    let (_dir, vault, issuer, share) = crate::share::tests::fixture()?;
    let federation_id = entity(0x83);
    let snapshot_id = entity(0x84);
    let brief_id = entity(0x85);
    put_federation_grant(&vault, federation_id, 40)?;
    let snapshot = PersonaSnapshotExportRecord {
        subject_ref: entity(0x53),
        audience_ref: Some("audience".to_owned()),
        identity_line: "Snapshot fixture".to_owned(),
        compiled_at_secs: 10,
        stale_after_secs: 20,
        compiled_fingerprint: "ab".repeat(32),
        takes_included: false,
        granted_by: issuer.entity_ref().to_hex(),
        granted_at_secs: 30,
        exported_at_secs: 40,
        included_row_ids: vec!["row:one".to_owned()],
        struck_row_ids: vec!["row:two".to_owned()],
        artifact_fingerprint: "cd".repeat(32),
    };
    vault.put_persona_snapshot_export(&snapshot_id, &snapshot)?;
    let query = ReceiptQuery::new(20).with_kind(ReceiptKind::Share);
    let before = vault.receipts(query.clone())?;
    let expected_federation = ReceiptRecord {
        receipt_id: format!("share:{}", federation_id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: 40,
        actor: Some(entity(0x61).to_hex()),
        on_behalf_of: None,
        outcome: "granted".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("federation_grant:{}", federation_id.to_hex())),
        policy_trace: Vec::new(),
        fields: field_map(&[
            ("role", "viewer"),
            ("preset", "read_only"),
            ("scope", "vault"),
            ("vault_id", "7"),
        ]),
    };
    let expected_snapshot = ReceiptRecord {
        receipt_id: format!("share:persona_snapshot:{}", snapshot_id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: 40,
        actor: Some(issuer.entity_ref().to_hex()),
        on_behalf_of: None,
        outcome: "exported".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("persona_snapshot_export:{}", snapshot_id.to_hex())),
        policy_trace: Vec::new(),
        fields: BTreeMap::from([
            (
                "persona_compile_stamp".to_owned(),
                format!("oneiron.persona_snapshot_compile.v1:{}", "ab".repeat(32)),
            ),
            ("subject_ref".to_owned(), entity(0x53).to_hex()),
            ("audience_ref".to_owned(), "audience".to_owned()),
            ("compiled_at_secs".to_owned(), "10".to_owned()),
            ("stale_after_secs".to_owned(), "20".to_owned()),
            ("included_rows".to_owned(), "1".to_owned()),
            ("struck_rows".to_owned(), "1".to_owned()),
            ("takes_included".to_owned(), "false".to_owned()),
            ("artifact_fingerprint".to_owned(), "cd".repeat(32)),
        ]),
    };
    for expected in [&expected_federation, &expected_snapshot] {
        let actual = before
            .iter()
            .find(|row| row.receipt_id == expected.receipt_id)
            .expect("legacy receipt");
        assert_eq!(
            rmp_serde::to_vec_named(actual).expect("receipt bytes"),
            rmp_serde::to_vec_named(expected).expect("pinned legacy bytes")
        );
    }
    vault.create_share(&brief_id, &issuer, &share)?;
    vault.revoke_share(&brief_id, &issuer, 60)?;
    let after = vault.receipts(query)?;
    assert_eq!(after.len(), 4);
    for legacy in &before {
        let actual = after
            .iter()
            .find(|row| row.receipt_id == legacy.receipt_id)
            .expect("retained legacy receipt");
        assert_eq!(
            rmp_serde::to_vec_named(actual).expect("receipt bytes"),
            rmp_serde::to_vec_named(legacy).expect("legacy bytes")
        );
    }
    let ids: BTreeSet<_> = after.iter().map(|row| &row.receipt_id).collect();
    assert_eq!(ids.len(), after.len());
    // Even equal hex suffixes across kinds cannot collide.
    let suffix = brief_id.to_hex();
    assert_eq!(
        BTreeSet::from([
            format!("share:{suffix}"),
            format!("share:persona_snapshot:{suffix}"),
            format!("share:brief:{suffix}"),
            format!("share:brief:{suffix}:revoked"),
        ])
        .len(),
        4
    );
    Ok(())
}
