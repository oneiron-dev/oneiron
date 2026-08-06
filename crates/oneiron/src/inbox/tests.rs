use rmpv::Value;

use super::*;
use crate::attempt_queue::{AttemptId, EnqueueAttempt, EnqueueOutcome};
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::edge::EdgeActorClass;
use crate::receipt::ReceiptQuery;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::{GateDecisionId, PendingGateConsentRecord};
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;

const REASON_CEILING: &str = "gate.pending.actor_ceiling";
const REASON_CRITICAL: &str = "gate.pending.criticality_floor";
const REASON_CHECKER: &str = "gate.pending.checker_low_confidence";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}

use crate::test_util::entity;

fn time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn synthetic_pending_id(prefix: u8, value: u64) -> [u8; 16] {
    let mut bytes = [prefix; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn synthetic_gate_decision_id(prefix: u8, value: u64) -> GateDecisionId {
    GateDecisionId::from_bytes(synthetic_pending_id(prefix, value))
}

fn dreamer_envelope(actor: EntityId, run_id: &str) -> WriteEnvelope {
    WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("runner"),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (Value::from("run_id"), Value::from(run_id)),
        ]))
        .expect("provenance"),
        ClaimApprovalStatus::Proposed,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "fixture keeps each proposal's identity explicit at call sites"
)]
fn write_dreamer_proposal(
    vault: &Vault,
    claim_id: EntityId,
    actor: EntityId,
    subject: EntityId,
    predicate: &str,
    value: &str,
    run_id: &str,
    created_at: u64,
    reasons: &[&str],
) -> Result<()> {
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, time(1), 1, b"dreamer actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;
    let envelope = dreamer_envelope(actor, run_id);
    let candidate = crate::write_envelope::ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            time(created_at),
            created_at,
        )
        .commit()?;
    add_pending_row(vault, claim_id, actor, created_at, reasons, run_id)
}

fn add_pending_row(
    vault: &Vault,
    claim_id: EntityId,
    actor: EntityId,
    created_at: u64,
    reasons: &[&str],
    run_id: &str,
) -> Result<()> {
    let body = vault.get_claim(&claim_id)?.expect("proposal stored");
    let (diff_handle, read_frontier_hash) = {
        let rtxn = vault.store.env.read_txn()?;
        crate::gate::claim_consent_binding_parts(&vault.store, &rtxn, &body)?
    };
    let reason_codes: Vec<String> = reasons.iter().map(|code| (*code).to_owned()).collect();
    let decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at,
        outcome: "pending".to_owned(),
        reason_codes: reason_codes.clone(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "agent".to_owned(),
        actor_ref: Some(actor.to_hex()),
        content_kind: "claim".to_owned(),
        policy_manifest_version: "v0".to_owned(),
        claim_id: Some(*claim_id.as_bytes()),
        grant_ref: None,
        diff_handle: diff_handle.clone(),
        read_frontier_hash,
        redacted_at: None,
    };
    let pending = PendingGateConsentRecord {
        version: 0,
        claim_id: *claim_id.as_bytes(),
        decision_id: decision.decision_id,
        created_at,
        diff_handle,
        read_frontier_hash,
        reason_codes,
        dreamer_run_id: Some(run_id.to_owned()),
    };
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
    })
}

fn enqueue_dreamer_attempt(
    vault: &Vault,
    attempt_type: &str,
    parent_attempt: Option<AttemptId>,
    input: Value,
    run_id: &str,
    now: u64,
) -> Result<AttemptId> {
    let runner = DreamerRunnerStore::new(vault);
    match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: attempt_type.to_owned(),
        input,
        parent_attempt,
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status.attempt.id),
    }
}

#[test]
fn review_dial_defaults_to_exceptions_only_and_round_trips() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    assert_eq!(vault.inbox_review_dial()?, InboxReviewDial::ExceptionsOnly);

    vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
    assert_eq!(vault.inbox_review_dial()?, InboxReviewDial::ApproveAll);

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    assert_eq!(
        vault.inbox_review_dial()?,
        InboxReviewDial::ReviewEverything
    );

    assert!(matches!(
        vault.reopen_inbox_group("claim:not-a-run"),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn inbox_group_key_is_the_run_tree_root_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-antevon-week";
    let root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(
            Value::from("intent"),
            Value::from("Your Antevon week"),
        )]),
        run_id,
        10,
    )?;
    let branch = enqueue_dreamer_attempt(
        &vault,
        "entity-sweep",
        Some(root),
        Value::from("branch input"),
        run_id,
        20,
    )?;

    write_dreamer_proposal(
        &vault,
        entity(0x61),
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        30,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        entity(0x62),
        entity(0xB2),
        entity(0xC2),
        "profile.hobby",
        "chess",
        run_id,
        40,
        &[REASON_CEILING],
    )?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.group_key, bytes_to_hex_lower(root.as_bytes()));
    assert_ne!(group.group_key, bytes_to_hex_lower(branch.as_bytes()));
    assert_eq!(group.run_id, run_id);
    assert_eq!(group.headline, "Your Antevon week: 2 new claims");
    assert_eq!(group.created_at, 30);
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.members[0].claim_id, entity(0x61).to_hex());
    assert_eq!(group.members[0].age_secs, 70);
    assert_eq!(group.members[0].verb_class, "new_claim");
    assert_eq!(group.held_member_count, 0);
    assert!(group.sub_clusters.is_empty());
    Ok(())
}

#[test]
fn bundle_receipt_reopens_group_after_accept_all() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-b";
    let first = entity(0x61);
    let second = entity(0x62);
    write_dreamer_proposal(
        &vault,
        first,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        10,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        second,
        entity(0xB2),
        entity(0xC2),
        "profile.hobby",
        "chess",
        run_id,
        20,
        &[REASON_CEILING],
    )?;

    assert!(matches!(
        vault.resolve_inbox_group_at("run-missing", InboxBulkVerb::AcceptAll, None, 30),
        Err(Error::EntityNotFound)
    ));

    let review = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::ReviewEach, None, 40)?;
    assert_eq!(review.bundle_receipt.outcome, "bundle_review_each");
    assert_eq!(review.review_items.len(), 2);
    assert!(review.item_receipts.is_empty());
    assert_eq!(vault.store.pending_gate_consents(10)?.len(), 2);

    let resolution = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::AcceptAll, None, 50)?;
    assert_eq!(resolution.group_key, run_id);
    assert_eq!(resolution.bundle_ref, "bundle:dreamer_run:run-b");
    assert_eq!(resolution.bundle_receipt.outcome, "bundle_accepted");
    assert_eq!(
        resolution.bundle_receipt.trigger_ref.as_deref(),
        Some("dreamer_run:run-b")
    );
    assert_eq!(
        resolution
            .bundle_receipt
            .fields
            .get("bundle_ref")
            .map(String::as_str),
        Some("bundle:dreamer_run:run-b")
    );
    assert_eq!(resolution.item_receipts.len(), 2);
    for receipt in &resolution.item_receipts {
        assert_eq!(receipt.outcome, "approved");
        assert!(
            receipt
                .policy_trace
                .contains(&"gate.consent.bundle_accept".to_owned())
        );
    }

    assert_eq!(
        vault.get_claim(&first)?.expect("accepted claim").approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault.get_claim(&second)?.expect("accepted claim").approval,
        ClaimApprovalStatus::Approved
    );
    assert!(vault.store.pending_gate_consents(10)?.is_empty());
    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    assert!(vault.inbox_groups(InboxQuery::at(60, 10))?.is_empty());

    let approved = vault.receipts(ReceiptQuery::new(10).with_outcome("approved"))?;
    assert_eq!(approved.len(), 2);

    let reopened = vault.reopen_inbox_group_at("bundle:dreamer_run:run-b", 70)?;
    assert_eq!(reopened.group_key, run_id);
    assert!(reopened.open_group.is_none());
    let outcomes: Vec<&str> = reopened
        .resolution_receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "approved")
            .count(),
        2
    );
    assert!(outcomes.contains(&"bundle_accepted"));
    assert!(outcomes.contains(&"bundle_review_each"));
    Ok(())
}

#[test]
fn stale_semantic_hash_sidecar_keeps_current_member_visible_and_clearable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = entity(0x91);
    let actor = entity(0x92);
    let subject = entity(0x93);
    let run_id = "run-stale-semantic-hash";
    write_dreamer_proposal(
        &vault,
        claim_id,
        actor,
        subject,
        "profile.hobby",
        "chess",
        run_id,
        20,
        &[REASON_CEILING],
    )?;

    vault
        .batch()
        .claim_candidate(
            &claim_id,
            crate::write_envelope::ClaimCandidate::new(
                "profile.hobby",
                ClaimSubject::Entity(subject),
                Value::from("go"),
                0.9,
            ),
            &dreamer_envelope(actor, run_id),
            time(21),
            21,
        )
        .commit()?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    assert_eq!(vault.inbox_groups(InboxQuery::at(50, 10))?.len(), 1);
    assert!(
        vault
            .reopen_inbox_group_at(&format!("{INBOX_GROUP_DOOR_PREFIX}{run_id}"), 50)?
            .open_group
            .is_some()
    );
    assert!(matches!(
        vault.resolve_inbox_group_at(run_id, InboxBulkVerb::AcceptAll, None, 50),
        Err(Error::GateConsentStale { claim_id: stale }) if stale == claim_id
    ));
    let rejected = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, None, 51)?;
    assert_eq!(rejected.item_receipts.len(), 1);
    assert!(vault.store.pending_gate_consents(10)?.is_empty());
    Ok(())
}

#[test]
fn reject_all_emits_per_item_receipts_and_keeps_proposal_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-reject";
    let first = entity(0x61);
    let second = entity(0x62);
    write_dreamer_proposal(
        &vault,
        first,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        10,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        second,
        entity(0xB2),
        entity(0xC2),
        "profile.hobby",
        "chess",
        run_id,
        20,
        &[REASON_CEILING],
    )?;

    let resolution = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, None, 50)?;
    assert_eq!(resolution.bundle_receipt.outcome, "bundle_rejected");
    assert_eq!(resolution.item_receipts.len(), 2);
    for receipt in &resolution.item_receipts {
        assert_eq!(receipt.outcome, "rejected");
        assert!(
            receipt
                .policy_trace
                .contains(&"gate.consent.bundle_reject".to_owned())
        );
    }

    // Rejection resolves consent but never silently deletes the proposal.
    assert_eq!(
        vault
            .get_claim(&first)?
            .expect("rejected proposal")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(vault.store.pending_gate_consents(10)?.is_empty());
    Ok(())
}

#[test]
fn cross_run_same_claim_hash_dups_collapse_into_earliest_open_group() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = entity(0xC1);
    let original = entity(0x61);
    let duplicate = entity(0x62);
    let distinct = entity(0x63);
    write_dreamer_proposal(
        &vault,
        original,
        entity(0xB1),
        subject,
        "profile.diet",
        "vegan",
        "run-early",
        10,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        duplicate,
        entity(0xB2),
        subject,
        "profile.diet",
        "vegan",
        "run-late",
        20,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        distinct,
        entity(0xB3),
        entity(0xC2),
        "profile.hobby",
        "chess",
        "run-late",
        30,
        &[REASON_CEILING],
    )?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 2);

    let early = &groups[0];
    assert_eq!(early.run_id, "run-early");
    assert_eq!(early.members.len(), 1);
    assert_eq!(early.members[0].claim_id, original.to_hex());
    assert_eq!(
        early.members[0].duplicate_claim_ids,
        vec![duplicate.to_hex()]
    );
    assert!(early.pointer_rows.is_empty());

    let late = &groups[1];
    assert_eq!(late.run_id, "run-late");
    assert_eq!(late.members.len(), 1);
    assert_eq!(late.members[0].claim_id, distinct.to_hex());
    assert_eq!(late.pointer_rows.len(), 1);
    assert_eq!(late.pointer_rows[0].claim_id, duplicate.to_hex());
    assert_eq!(
        late.pointer_rows[0].duplicate_of_claim_id,
        original.to_hex()
    );
    assert_eq!(late.pointer_rows[0].duplicate_of_group_key, early.group_key);

    // Accepting the earliest group covers the collapsed duplicate's
    // pending row too — each row redeems against its own binding.
    let resolution =
        vault.resolve_inbox_group_at("run-early", InboxBulkVerb::AcceptAll, None, 50)?;
    assert_eq!(resolution.item_receipts.len(), 2);
    assert_eq!(
        vault
            .get_claim(&duplicate)?
            .expect("duplicate claim")
            .approval,
        ClaimApprovalStatus::Approved
    );

    let groups = vault.inbox_groups(InboxQuery::at(60, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].run_id, "run-late");
    assert_eq!(groups[0].members.len(), 1);
    assert!(groups[0].pointer_rows.is_empty());
    Ok(())
}

#[test]
fn indexed_explicit_group_matches_scan_for_raw_and_branch_root_aliases() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(
            Value::from("intent"),
            Value::from("Indexed branch root"),
        )]),
        "run-parent",
        10,
    )?;
    let branch = enqueue_dreamer_attempt(
        &vault,
        "entity-sweep",
        Some(root),
        Value::from("branch input"),
        "run-branch",
        20,
    )?;
    let subject = entity(0xC1);
    let original = entity(0x61);
    let duplicate = entity(0x62);
    write_dreamer_proposal(
        &vault,
        original,
        entity(0xB1),
        subject,
        "profile.diet",
        "vegan",
        "run-parent",
        30,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        duplicate,
        entity(0xB2),
        subject,
        "profile.diet",
        "vegan",
        "run-branch",
        40,
        &[REASON_CEILING],
    )?;

    let root_key = bytes_to_hex_lower(root.as_bytes());
    let scan_groups = inbox_groups_projection(
        &vault,
        InboxQuery::at(100, 10),
        InboxReviewDial::ReviewEverything,
        10,
    )?;
    let expected_parent = scan_groups
        .iter()
        .find(|group| group.run_id == "run-parent")
        .expect("scan parent group")
        .clone();
    let expected_branch = scan_groups
        .iter()
        .find(|group| group.run_id == "run-branch")
        .expect("scan branch group")
        .clone();
    assert_eq!(expected_parent.group_key, root_key);
    assert_ne!(
        expected_branch.group_key,
        bytes_to_hex_lower(branch.as_bytes())
    );
    assert_eq!(
        explicit_inbox_group(&vault, "run-parent", 100)?,
        Some(expected_parent.clone())
    );
    assert_eq!(
        explicit_inbox_group(&vault, "run-branch", 100)?,
        Some(expected_branch)
    );
    // A canonical root door follows the former projection's first matching
    // raw run, so it picks the parent row and carries the duplicate.
    assert_eq!(
        explicit_inbox_group(&vault, &root_key, 100)?,
        Some(expected_parent.clone())
    );
    assert_eq!(
        expected_parent.members[0].duplicate_claim_ids,
        vec![duplicate.to_hex()]
    );

    let semantic_hash = inbox_claim_hash(&vault.get_claim(&original)?.expect("original"))?;
    let resolution =
        vault.resolve_inbox_group_at(&root_key, InboxBulkVerb::AcceptAll, None, 110)?;
    assert_eq!(resolution.item_receipts.len(), 2);
    assert_eq!(
        vault
            .get_claim(&original)?
            .expect("original claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .get_claim(&duplicate)?
            .expect("duplicate claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    // The deletion state removes every lookup alias that powered this
    // resolution, including the branch root and semantic duplicate rows.
    assert!(
        vault
            .store
            .pending_gate_consents_for_run("run-parent")?
            .is_empty()
    );
    assert!(
        vault
            .store
            .pending_gate_consents_for_run("run-branch")?
            .is_empty()
    );
    assert!(
        vault
            .store
            .pending_gate_consents_for_group_key(&root_key)?
            .is_empty()
    );
    assert!(
        vault
            .store
            .pending_gate_consents_for_semantic_claim_hash(&semantic_hash)?
            .is_empty()
    );
    assert!(explicit_inbox_group(&vault, &root_key, 120)?.is_none());
    assert!(
        inbox_groups_projection(
            &vault,
            InboxQuery::at(120, 10),
            InboxReviewDial::ReviewEverything,
            10,
        )?
        .is_empty()
    );

    let reopened =
        vault.reopen_inbox_group_at(&format!("{INBOX_GROUP_DOOR_PREFIX}{root_key}"), 120)?;
    assert!(reopened.open_group.is_none());
    let outcomes: Vec<&str> = reopened
        .resolution_receipts
        .iter()
        .map(|receipt| receipt.outcome.as_str())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "approved")
            .count(),
        2
    );
    assert!(outcomes.contains(&"bundle_accepted"));
    Ok(())
}

#[test]
fn late_root_insertion_rekeys_pending_group_aliases() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-late-root";
    let claim_id = entity(0x61);

    // A generated proposal can be durable before its run root. The group
    // sidecar must follow the root once that attempt is subsequently persisted.
    write_dreamer_proposal(
        &vault,
        claim_id,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        10,
        &[REASON_CEILING],
    )?;
    let root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Late root"))]),
        run_id,
        20,
    )?;
    let root_key = bytes_to_hex_lower(root.as_bytes());

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let expected = vault
        .inbox_groups(InboxQuery::at(100, 10))?
        .into_iter()
        .next()
        .expect("browse surfaces the late-root group");
    assert_eq!(expected.group_key, root_key);

    assert_eq!(
        explicit_inbox_group(&vault, &root_key, 100)?,
        Some(expected.clone())
    );
    let reopened =
        vault.reopen_inbox_group_at(&format!("{INBOX_GROUP_DOOR_PREFIX}{root_key}"), 100)?;
    assert_eq!(reopened.open_group, Some(expected));

    let resolution =
        vault.resolve_inbox_group_at(&root_key, InboxBulkVerb::AcceptAll, None, 110)?;
    assert_eq!(resolution.group_key, root_key);
    assert_eq!(resolution.item_receipts.len(), 1);
    assert_eq!(
        vault
            .get_claim(&claim_id)?
            .expect("resolved claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn explicit_resolution_reaches_a_run_beyond_the_legacy_pending_scan_budget() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Generic, non-Dreamer pending asks remain in the primary tray but have
    // no run sidecar.  They model the old global scan being saturated without
    // changing the target group's semantics.
    vault.with_write_txn(|wtxn| {
        for offset in 0..=crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            let pending = PendingGateConsentRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                claim_id: synthetic_pending_id(0xE1, offset as u64),
                decision_id: synthetic_gate_decision_id(0xE2, offset as u64),
                created_at: offset as u64,
                diff_handle: vec![0xE3],
                read_frontier_hash: [0xE4; 32],
                reason_codes: vec!["gate.pending.synthetic".to_owned()],
                dreamer_run_id: None,
            };
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &pending)?;
        }
        Ok(())
    })?;

    let run_id = "run-after-legacy-pending-scan";
    let target = entity(0x61);
    write_dreamer_proposal(
        &vault,
        target,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        crate::receipt::MAX_RECEIPT_QUERY_SCAN as u64 + 10,
        &[REASON_CEILING],
    )?;

    let legacy_scan = vault
        .store
        .pending_gate_consents(crate::receipt::MAX_RECEIPT_QUERY_SCAN)?;
    assert_eq!(legacy_scan.len(), crate::receipt::MAX_RECEIPT_QUERY_SCAN);
    assert!(
        legacy_scan
            .iter()
            .all(|record| record.claim_id != *target.as_bytes())
    );
    assert_eq!(vault.store.pending_gate_consents_for_run(run_id)?.len(), 1);

    let resolution =
        vault.resolve_inbox_group_at(run_id, InboxBulkVerb::AcceptAll, None, 200_000)?;
    assert_eq!(resolution.item_receipts.len(), 1);
    assert_eq!(
        vault.get_claim(&target)?.expect("target claim").approval,
        ClaimApprovalStatus::Approved
    );
    assert!(
        vault
            .store
            .pending_gate_consents_for_run(run_id)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn approve_all_dial_still_surfaces_manifest_critical() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-dial";
    let critical = entity(0x61);
    let plain = entity(0x62);
    let hedged = entity(0x63);
    write_dreamer_proposal(
        &vault,
        critical,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        10,
        &[REASON_CRITICAL],
    )?;
    write_dreamer_proposal(
        &vault,
        plain,
        entity(0xB2),
        entity(0xC2),
        "profile.hobby",
        "chess",
        run_id,
        20,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        hedged,
        entity(0xB3),
        entity(0xC3),
        "profile.city",
        "osaka",
        run_id,
        30,
        &[REASON_CHECKER],
    )?;

    // Default dial: exceptions-only surfaces critical + checker hedge.
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    let surfaced: Vec<&str> = groups[0]
        .members
        .iter()
        .map(|member| member.claim_id.as_str())
        .collect();
    assert_eq!(
        surfaced,
        vec![critical.to_hex().as_str(), hedged.to_hex().as_str()]
    );
    assert_eq!(groups[0].held_member_count, 1);
    assert!(
        groups[0].members[0]
            .exception_classes
            .contains(&InboxExceptionClass::ManifestCritical)
    );
    assert!(
        groups[0].members[1]
            .exception_classes
            .contains(&InboxExceptionClass::CheckerHedge)
    );

    // approve-all cannot waive manifest-critical rows.
    vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 1);
    assert_eq!(groups[0].members[0].claim_id, critical.to_hex());
    assert_eq!(groups[0].held_member_count, 2);

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    assert_eq!(
        vault.inbox_groups(InboxQuery::at(100, 10))?[0]
            .members
            .len(),
        3
    );
    Ok(())
}

#[test]
fn per_item_lapse_never_drops_siblings() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-lapse";
    let lapsing = entity(0x61);
    let sibling = entity(0x62);
    write_dreamer_proposal(
        &vault,
        lapsing,
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        10,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        sibling,
        entity(0xB2),
        entity(0xC2),
        "profile.hobby",
        "chess",
        run_id,
        20,
        &[REASON_CEILING],
    )?;
    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;

    let lapse = vault
        .let_go_pending_ask_at(&lapsing, 99)?
        .expect("lapse emits a receipt");
    assert_eq!(lapse.outcome, "let_go");

    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 1);
    assert_eq!(groups[0].members[0].claim_id, sibling.to_hex());
    assert_eq!(groups[0].held_member_count, 0);

    // The group closes only once every member is resolved.
    vault
        .let_go_pending_ask_at(&sibling, 120)?
        .expect("second lapse emits a receipt");
    assert!(vault.inbox_groups(InboxQuery::at(130, 10))?.is_empty());
    Ok(())
}

#[test]
fn supersede_of_user_stated_and_conflict_rows_surface_as_exceptions() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-d";
    let subject = entity(0xC1);
    let owner = entity(0xB0);
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, time(1), 1, b"owner")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;

    // Existing user_stated truth on the same subject + predicate.
    let truth = entity(0xA0);
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("user said so")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    let candidate = crate::write_envelope::ClaimCandidate::new(
        "profile.diet",
        ClaimSubject::Entity(subject),
        Value::from("vegan"),
        1.0,
    );
    vault
        .batch()
        .claim_candidate(&truth, candidate, &envelope, time(5), 5)
        .commit()?;

    let update = entity(0x61);
    write_dreamer_proposal(
        &vault,
        update,
        entity(0xB1),
        subject,
        "profile.diet",
        "keto",
        run_id,
        10,
        &[REASON_CEILING],
    )?;
    let conflict = entity(0x62);
    write_dreamer_proposal(
        &vault,
        conflict,
        entity(0xB2),
        subject,
        PREDICATE_CONFLICT_OPEN,
        "diet conflict",
        run_id,
        20,
        &[REASON_CEILING],
    )?;
    let plain = entity(0x63);
    write_dreamer_proposal(
        &vault,
        plain,
        entity(0xB3),
        entity(0xC3),
        "profile.hobby",
        "chess",
        run_id,
        30,
        &[REASON_CEILING],
    )?;

    // Default exceptions-only dial: the supersede-of-user_stated row and
    // the conflict row surface; the plain new claim rides auto.
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.held_member_count, 1);
    assert_eq!(group.new_claim_count, 1);
    assert_eq!(group.update_count, 1);
    assert_eq!(group.conflict_count, 1);
    assert_eq!(
        group.headline,
        "Dreamer run: 1 new claim, 1 update, 1 conflict"
    );

    let update_row = &group.members[0];
    assert_eq!(update_row.claim_id, update.to_hex());
    assert_eq!(update_row.verb_class, "update");
    assert!(
        update_row
            .exception_classes
            .contains(&InboxExceptionClass::SupersedesUserStated)
    );
    let conflict_row = &group.members[1];
    assert_eq!(conflict_row.claim_id, conflict.to_hex());
    assert_eq!(conflict_row.verb_class, "conflict");
    assert!(
        conflict_row
            .exception_classes
            .contains(&InboxExceptionClass::Conflict)
    );

    // Bundle consent scopes to run x verb-class.
    let resolution =
        vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, Some("conflict"), 99)?;
    assert_eq!(resolution.item_receipts.len(), 1);
    assert_eq!(
        resolution.item_receipts[0].trigger_ref.as_deref(),
        Some(format!("claim:{}", conflict.to_hex()).as_str())
    );
    assert!(
        resolution
            .bundle_receipt
            .policy_trace
            .contains(&"gate.consent.bundle.verb_class.conflict".to_owned())
    );
    assert_eq!(vault.store.pending_gate_consents(10)?.len(), 2);
    Ok(())
}

#[test]
fn many_item_runs_sub_cluster_by_entity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-many";
    let first_subject = entity(0xC1);
    let second_subject = entity(0xC2);
    let values = ["a", "b", "c"];
    for (index, value) in values.iter().enumerate() {
        let offset = u8::try_from(index).expect("small index");
        write_dreamer_proposal(
            &vault,
            entity(0x61 + offset),
            entity(0xB1 + offset),
            first_subject,
            "profile.note",
            value,
            run_id,
            10 + u64::from(offset),
            &[REASON_CEILING],
        )?;
        write_dreamer_proposal(
            &vault,
            entity(0xD1 + offset),
            entity(0x5E + offset),
            second_subject,
            "profile.note",
            value,
            run_id,
            20 + u64::from(offset),
            &[REASON_CEILING],
        )?;
    }

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 6);
    assert_eq!(groups[0].sub_clusters.len(), 2);
    let first_cluster = &groups[0].sub_clusters[0];
    assert_eq!(
        first_cluster.key,
        format!("entity:{}", first_subject.to_hex())
    );
    assert_eq!(first_cluster.member_claim_ids.len(), 3);
    let second_cluster = &groups[0].sub_clusters[1];
    assert_eq!(
        second_cluster.key,
        format!("entity:{}", second_subject.to_hex())
    );
    assert_eq!(second_cluster.member_claim_ids.len(), 3);
    Ok(())
}

#[test]
fn run_root_ignores_non_dreamer_attempts_sharing_the_run_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-mixed";
    // A non-Dreamer attempt with the same run id, created BEFORE the dreamer
    // root, must never be picked as the run-tree root.
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(webhook) = queue.enqueue(EnqueueAttempt {
        kind: "webhook".to_owned(),
        payload: b"webhook payload".to_vec(),
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now: 5,
    })?
    else {
        panic!("expected fresh enqueue");
    };
    let root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Mixed run"))]),
        run_id,
        10,
    )?;

    write_dreamer_proposal(
        &vault,
        entity(0x61),
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        30,
        &[REASON_CEILING],
    )?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_key, bytes_to_hex_lower(root.as_bytes()));
    assert_ne!(
        groups[0].group_key,
        bytes_to_hex_lower(webhook.id.as_bytes())
    );
    assert_eq!(groups[0].headline, "Mixed run: 1 new claim");
    Ok(())
}

#[test]
fn run_root_preserves_creation_order_when_a_run_has_multiple_roots() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-multiple-roots";
    // The attempt IDs follow enqueue order, but `list_run` has always selected
    // roots in the persisted creation-time order.  Keep that distinction
    // visible so the run-id sidecar cannot accidentally choose by key order.
    let later_root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Later root"))]),
        run_id,
        20,
    )?;
    let earlier_root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Earlier root"))]),
        run_id,
        10,
    )?;
    write_dreamer_proposal(
        &vault,
        entity(0x61),
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        run_id,
        30,
        &[REASON_CEILING],
    )?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].group_key,
        bytes_to_hex_lower(earlier_root.as_bytes())
    );
    assert_ne!(
        groups[0].group_key,
        bytes_to_hex_lower(later_root.as_bytes())
    );
    assert_eq!(groups[0].headline, "Earlier root: 1 new claim");
    Ok(())
}

#[test]
fn run_root_climbs_parent_links_for_branch_run_ids() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let root = enqueue_dreamer_attempt(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Branch climb"))]),
        "run-parent",
        10,
    )?;
    let branch = enqueue_dreamer_attempt(
        &vault,
        "entity-sweep",
        Some(root),
        Value::from("branch input"),
        "run-branch",
        20,
    )?;

    // The proposal is stamped with the BRANCH run id; the group key must
    // still be the OF-193 root reached through parent links.
    write_dreamer_proposal(
        &vault,
        entity(0x61),
        entity(0xB1),
        entity(0xC1),
        "profile.diet",
        "vegan",
        "run-branch",
        30,
        &[REASON_CEILING],
    )?;

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_key, bytes_to_hex_lower(root.as_bytes()));
    assert_ne!(groups[0].group_key, bytes_to_hex_lower(branch.as_bytes()));
    assert_eq!(groups[0].run_id, "run-branch");
    assert_eq!(groups[0].headline, "Branch climb: 1 new claim");
    Ok(())
}

#[test]
fn stale_truth_does_not_classify_updates() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = entity(0xC1);
    let owner = entity(0xB0);
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, time(1), 1, b"owner")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;

    // The only same subject+predicate truth is STALE: it is excluded
    // from read-path truth, so the proposal is a new claim, not an
    // update over user_stated truth.
    let stale_truth = entity(0xA0);
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("user said so")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    let candidate = crate::write_envelope::ClaimCandidate::new(
        "profile.diet",
        ClaimSubject::Entity(subject),
        Value::from("vegan"),
        1.0,
    )
    .with_stale(true);
    vault
        .batch()
        .claim_candidate(&stale_truth, candidate, &envelope, time(5), 5)
        .commit()?;

    write_dreamer_proposal(
        &vault,
        entity(0x61),
        entity(0xB1),
        subject,
        "profile.diet",
        "keto",
        "run-stale",
        10,
        &[REASON_CEILING],
    )?;

    // Default exceptions-only dial: no exception classes, nothing
    // surfaces, so the group stays out of the queue entirely.
    assert!(vault.inbox_groups(InboxQuery::at(100, 10))?.is_empty());

    vault.set_inbox_review_dial(InboxReviewDial::ReviewEverything)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 1);
    assert_eq!(groups[0].members[0].verb_class, "new_claim");
    assert!(groups[0].members[0].exception_classes.is_empty());
    assert_eq!(groups[0].new_claim_count, 1);
    assert_eq!(groups[0].update_count, 0);
    Ok(())
}

#[test]
fn duplicate_rows_keep_exception_surfacing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = entity(0xC1);
    let original = entity(0x61);
    let duplicate = entity(0x62);
    // The owner row is a plain non-exception ask; the later duplicate is
    // manifest-critical. The collapse must not hide the exception.
    write_dreamer_proposal(
        &vault,
        original,
        entity(0xB1),
        subject,
        "profile.diet",
        "vegan",
        "run-early",
        10,
        &[REASON_CEILING],
    )?;
    write_dreamer_proposal(
        &vault,
        duplicate,
        entity(0xB2),
        subject,
        "profile.diet",
        "vegan",
        "run-late",
        20,
        &[REASON_CRITICAL],
    )?;

    // Default exceptions-only dial: the owner row surfaces because the
    // collapsed duplicate carries a manifest-critical hold.
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 2);
    let early = &groups[0];
    assert_eq!(early.run_id, "run-early");
    assert_eq!(early.members.len(), 1);
    assert_eq!(early.members[0].claim_id, original.to_hex());
    assert_eq!(
        early.members[0].duplicate_claim_ids,
        vec![duplicate.to_hex()]
    );
    assert!(
        early.members[0]
            .exception_classes
            .contains(&InboxExceptionClass::ManifestCritical)
    );
    let late = &groups[1];
    assert_eq!(late.pointer_rows.len(), 1);
    assert!(late.members.is_empty());

    // The dial can never waive a manifest-critical row, duplicate or not.
    vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups[0].members.len(), 1);
    assert_eq!(groups[0].members[0].claim_id, original.to_hex());
    Ok(())
}

// ===== ONE-1757 (ED-01) — approve-with-edit =====

/// Builds the decider's edited body from the stored proposal.
fn edited_body(vault: &Vault, claim_id: EntityId, value: &str) -> Result<Vec<u8>> {
    let mut body = vault.get_claim(&claim_id)?.expect("proposal stored");
    body.value = Value::from(value);
    body.confidence = 0.5;
    crate::claim::encode_claim_body(&body)
}

fn amended_proposal(vault: &Vault) -> Result<EntityId> {
    let claim_id = entity(0xB4);
    write_dreamer_proposal(
        vault,
        claim_id,
        entity(0xB5),
        entity(0xB6),
        "core.role",
        "draft",
        "run-amend",
        10,
        &[REASON_CHECKER],
    )?;
    Ok(claim_id)
}

/// The CRITICAL fix: before this door the bulk verbs re-encoded the EXISTING
/// body, so a decider's edit was silently discarded. The amended body is what
/// lands, and the receipt says so — `approved_amended` plus a Δ carrying all
/// six ARCH-0056 §2 fields.
#[test]
fn approve_with_edit_persists_the_amended_body_and_receipts_the_delta() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;
    let amended = edited_body(&vault, claim_id, "revised by the owner")?;

    let approval = vault.approve_inbox_member_with_edit_at(&claim_id, &amended, 20)?;

    // Read-back differs from what was proposed and matches the amendment.
    let stored = vault.get_claim(&claim_id)?.expect("approved claim");
    assert_eq!(stored.value, Value::from("revised by the owner"));
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
    assert_eq!(stored.predicate, "core.role");

    assert_eq!(approval.receipt.outcome, OUTCOME_APPROVED_AMENDED);
    assert!(
        approval
            .receipt
            .policy_trace
            .contains(&INBOX_REASON_AMEND_ACCEPT.to_owned())
    );
    // No capture-failure marker: the Δ was measured.
    assert!(
        !approval
            .receipt
            .policy_trace
            .contains(&INBOX_REASON_AMEND_DELTA_UNCAPTURED.to_owned())
    );

    let delta = approval.delta.expect("amended approval carries a delta");
    assert_eq!(
        delta.source,
        crate::edit_distance::delta::DeltaSource::FieldDiff
    );
    assert!((0.0..=1.0).contains(&delta.d_norm) && delta.d_norm > 0.0);
    assert!(delta.ops_summary.ins > 0 && delta.ops_summary.del > 0);
    assert!(delta.ops_summary.kept > 0, "an edit is not a replacement");
    assert_eq!(delta.engine_ver, env!("CARGO_PKG_VERSION"));
    assert_ne!(delta.proposed_ref, delta.final_ref);

    // The Δ rides the receipt's reserved slot, byte-identical to the door's.
    let carried = crate::receipt::proposal_outcome_delta(&approval.receipt)
        .expect("receipt carries the reserved delta slot");
    assert_eq!(
        crate::edit_distance::delta::AmendmentDelta::decode(&carried)?,
        delta
    );

    // The member is resolved: no open row survives the approval.
    assert!(vault.inbox_groups(InboxQuery::at(30, 10))?.is_empty());
    Ok(())
}

/// The Δ is not a courtesy of the door's own return value: a later receipt
/// query projects it too, from the same side-ledger.
#[test]
fn a_receipt_query_projects_the_delta_the_door_recorded() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;
    let amended = edited_body(&vault, claim_id, "revised")?;
    let approval = vault.approve_inbox_member_with_edit_at(&claim_id, &amended, 20)?;

    let queried = vault
        .receipts(ReceiptQuery::new(50))?
        .into_iter()
        .find(|receipt| receipt.receipt_id == approval.receipt.receipt_id)
        .expect("resolution receipt is queryable");
    assert_eq!(queried.fields, approval.receipt.fields);
    assert!(queried.fields.contains_key("amendment_delta"));
    Ok(())
}

/// The untouched path is unchanged: an unamended approval has no Δ, because
/// nothing was edited to measure.
#[test]
fn an_untouched_approval_carries_no_delta() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;

    let resolution =
        vault.resolve_inbox_group_at("run-amend", InboxBulkVerb::AcceptAll, None, 20)?;
    let receipt = resolution
        .item_receipts
        .first()
        .expect("per-item receipt")
        .clone();
    assert_eq!(receipt.outcome, "approved");
    assert!(!receipt.fields.contains_key("amendment_delta"));
    assert_eq!(
        vault
            .get_claim(&claim_id)?
            .expect("approved claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

/// An amendment NARROWS the review it belongs to. Moving the predicate or the
/// subject would land a claim under exception classes and a consent binding
/// that were derived from the ORIGINAL pair — a substitution wearing an
/// edit's clothes. Both are refused with the proposal left open.
#[test]
fn an_amendment_may_not_move_the_reviewed_predicate_or_subject() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;

    let mut swapped_predicate = vault.get_claim(&claim_id)?.expect("proposal");
    swapped_predicate.predicate = "core.alias".to_owned();
    let swapped_predicate = crate::claim::encode_claim_body(&swapped_predicate)?;
    assert!(matches!(
        vault.approve_inbox_member_with_edit_at(&claim_id, &swapped_predicate, 20),
        Err(Error::InvalidClaimBody(_))
    ));

    let mut swapped_subject = vault.get_claim(&claim_id)?.expect("proposal");
    swapped_subject.subject = ClaimSubject::Entity(entity(0xB7));
    let swapped_subject = crate::claim::encode_claim_body(&swapped_subject)?;
    assert!(matches!(
        vault.approve_inbox_member_with_edit_at(&claim_id, &swapped_subject, 20),
        Err(Error::InvalidClaimBody(_))
    ));

    // Fail-closed: nothing landed and the row is still open for review.
    let stored = vault.get_claim(&claim_id)?.expect("proposal");
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.value, Value::from("draft"));
    assert_eq!(vault.inbox_groups(InboxQuery::at(30, 10))?.len(), 1);
    Ok(())
}

/// A body that does not decode as a claim is refused by the SAME strict
/// decode the original rode — the amendment door is not a second, looser way
/// into the claim store.
#[test]
fn an_undecodable_amendment_is_refused_by_the_claim_body_decode() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;
    assert!(
        vault
            .approve_inbox_member_with_edit_at(&claim_id, b"\x91", 20)
            .is_err()
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

/// The door redeems CONSENT, so a claim with no open pending row has nothing
/// to redeem — an edit is not its own authority to write.
#[test]
fn approve_with_edit_needs_an_open_pending_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;
    let amended = edited_body(&vault, claim_id, "revised")?;
    vault.approve_inbox_member_with_edit_at(&claim_id, &amended, 20)?;

    assert!(matches!(
        vault.approve_inbox_member_with_edit_at(&claim_id, &amended, 21),
        Err(Error::EntityNotFound)
    ));
    Ok(())
}

/// The door's receipt enrichment rides INSIDE the write txn it commits, so
/// no failure can land the approval and report it as refused.
///
/// The failure this pins is ordinary, not exotic: the enrichment used to open
/// its own read txn AFTER the commit, and LMDB refuses a second reader on a
/// thread that already holds one (`BadRslot`). A caller iterating the tray
/// under a read txn — the obvious way to review and approve in one pass —
/// therefore got `Err` on a consent decision that had ALREADY landed: the
/// claim was Approved with the amendment, the pending row was gone, and the
/// retry hit [`Error::EntityNotFound`].
#[test]
fn a_read_failure_cannot_refuse_an_amendment_that_already_landed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim_id = amended_proposal(&vault)?;
    let amended = edited_body(&vault, claim_id, "revised under an open reader")?;

    let held = vault.store.env.read_txn()?;
    let approval = vault.approve_inbox_member_with_edit_at(&claim_id, &amended, 20)?;
    drop(held);

    assert_eq!(approval.receipt.outcome, OUTCOME_APPROVED_AMENDED);
    assert!(
        crate::receipt::proposal_outcome_delta(&approval.receipt).is_some(),
        "the reserved slot is filled from inside the txn, not by a later read"
    );
    let stored = vault.get_claim(&claim_id)?.expect("approved claim");
    assert_eq!(stored.value, Value::from("revised under an open reader"));
    Ok(())
}

/// The non-fatal contract at its chokepoint: an unmeasurable pair yields no Δ
/// and a receipt reason saying so — never an error that would refuse the
/// approval it hangs off.
#[test]
fn an_unmeasurable_pair_records_the_gap_instead_of_raising() {
    let (delta, reasons) = captured_amendment_delta(b"\x91", b"\x91");
    assert!(delta.is_none());
    assert_eq!(
        reasons,
        vec![INBOX_REASON_AMEND_DELTA_UNCAPTURED.to_owned()]
    );

    let good = crate::claim::encode_claim_body(&ClaimBody::new(
        "core.role",
        ClaimSubject::Entity(entity(0xB8)),
        Value::from("v"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    ))
    .expect("encode body");
    let (delta, reasons) = captured_amendment_delta(&good, &good);
    assert!(delta.is_some());
    assert!(reasons.is_empty());
}
