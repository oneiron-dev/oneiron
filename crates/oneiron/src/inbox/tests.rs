use rmpv::Value;

use super::*;
use crate::attempt_queue::AttemptId;
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
const REASON_CHECKER: &str = "gate.pending.checker_low_confidence";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}

use crate::error::GateError;
use crate::test_util::entity;

fn time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
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
    let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![subject],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    );
    let candidate = crate::write_envelope::ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
    )
    .with_evidence(evidence);
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

    let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![subject],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            crate::write_envelope::ClaimCandidate::new(
                "profile.hobby",
                ClaimSubject::Entity(subject),
                Value::from("go"),
                0.9,
            )
            .with_evidence(evidence),
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
        Err(Error::Gate(GateError::GateConsentStale { claim_id: stale })) if stale == claim_id
    ));
    let rejected = vault.resolve_inbox_group_at(run_id, InboxBulkVerb::RejectAll, None, 51)?;
    assert_eq!(rejected.item_receipts.len(), 1);
    assert!(vault.store.pending_gate_consents(10)?.is_empty());
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
    let group = vault
        .inbox_groups(InboxQuery::at(100, 10))?
        .into_iter()
        .next()
        .expect("browse surfaces the late-root group");
    assert_eq!(group.group_key, root_key);
    assert_eq!(group.run_id, run_id);
    assert!(
        group
            .members
            .iter()
            .any(|member| member.claim_id == claim_id.to_hex())
    );

    let reopened =
        vault.reopen_inbox_group_at(&format!("{INBOX_GROUP_DOOR_PREFIX}{root_key}"), 100)?;
    assert_eq!(reopened.group_key, root_key);
    let group = reopened.open_group.expect("late-root group is open");
    assert_eq!(group.group_key, root_key);
    assert_eq!(group.run_id, run_id);
    assert!(
        group
            .members
            .iter()
            .any(|member| member.claim_id == claim_id.to_hex())
    );

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

    let update_row = group
        .members
        .iter()
        .find(|member| member.claim_id == update.to_hex())
        .expect("supersession surfaces");
    assert_eq!(update_row.verb_class, "update");
    assert!(
        update_row
            .exception_classes
            .contains(&InboxExceptionClass::SupersedesUserStated)
    );
    let conflict_row = group
        .members
        .iter()
        .find(|member| member.claim_id == conflict.to_hex())
        .expect("conflict surfaces");
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
    let reopened =
        vault.reopen_inbox_group_at(&format!("{INBOX_GROUP_DOOR_PREFIX}{run_id}"), 100)?;
    let remainder = reopened.open_group.expect("siblings remain open");
    assert_eq!(remainder.members.len(), 2);
    for claim_id in [update, plain] {
        assert!(
            remainder
                .members
                .iter()
                .any(|member| member.claim_id == claim_id.to_hex())
        );
    }
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

/// An approval never removes the author, and the approver's write is not
/// judged against the agent author's own Proposed ceiling. An amended body is
/// the approver's text, so it keeps no single author.
#[test]
fn an_untouched_approval_keeps_the_agent_author_and_an_amended_one_does_not() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let author = |claim_id: EntityId| -> Result<Option<EntityId>> {
        let body = vault.get_claim(&claim_id)?.expect("claim");
        let txn = vault.store.env.read_txn()?;
        Ok(
            crate::batch::authenticated_claim_author_in_txn(&vault.store, &txn, &claim_id, &body)?
                .map(WriteActor::entity_ref),
        )
    };
    let untouched = amended_proposal(&vault)?;
    assert_eq!(author(untouched)?, Some(entity(0xB5)));
    vault.resolve_inbox_group_at("run-amend", InboxBulkVerb::AcceptAll, None, 20)?;
    assert_eq!(
        vault.get_claim(&untouched)?.expect("approved").approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(author(untouched)?, Some(entity(0xB5)));
    {
        use crate::ports::{ChangeLogStore, ChangeOp};
        let txn = vault.store.env.read_txn()?;
        let updates = |records: Vec<crate::ports::ChangeLogRecord>| {
            records
                .into_iter()
                .filter(|record| record.entity == untouched && record.op == ChangeOp::Update)
                .count()
        };
        assert_eq!(
            updates(vault.port_changelog_list_by_entity(&txn, &untouched, 100)?),
            1
        );
        assert_eq!(
            updates(vault.port_changelog_list_by_actor(&txn, &entity(0xB5), 100)?),
            0,
            "the approval is the approver's write, never the author's"
        );
    }

    let edited = entity(0xB7);
    write_dreamer_proposal(
        &vault,
        edited,
        entity(0xB5),
        entity(0xB8),
        "core.role",
        "draft",
        "run-edit",
        30,
        &[REASON_CHECKER],
    )?;
    let amended = edited_body(&vault, edited, "revised by the owner")?;
    vault.approve_inbox_member_with_edit_at(&edited, &amended, 40)?;
    assert_eq!(
        vault.get_claim(&edited)?.expect("approved").approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(author(edited)?, None);
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

#[cfg(test)]
mod vad_vetting_tests {
    use super::*;
    use crate::affect::{CLAIM_VAD_REAPPRAISAL_PREDICATE, Vad, VadAnnotation, VadAnnotationSource};
    use crate::edge::EdgeKind;
    use crate::registry::ENTITY_TYPE_TURN;

    const RUN: &str = "vad-vetting";
    const FULL_VAD: Vad = Vad {
        valence: -0.5,
        arousal: 0.75,
        dominance: 0.25,
    };

    fn proposal(vault: &Vault, predicate: &str) -> Result<(EntityId, EntityId)> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        let turn = EntityId::now();
        let claim = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, time(1), 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, time(1), 1, b"subject")?;
        let turn_body =
            rmp_serde::to_vec_named(&serde_json::json!({"txt": "evidence"})).expect("turn body");
        vault.put_entity(&turn, ENTITY_TYPE_TURN, time(2), 2, &turn_body)?;
        vault.annotate_turn_vad(
            &turn,
            VadAnnotation::new(FULL_VAD, VadAnnotationSource::ModelInference, 3)?,
        )?;
        let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![turn],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        );
        let candidate = crate::write_envelope::ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from("draft"),
            0.9,
        )
        .with_evidence(evidence);
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &dreamer_envelope(actor, RUN),
                time(10),
                10,
            )
            .commit()?;
        add_pending_row(vault, claim, actor, 10, &[REASON_CHECKER], RUN)?;
        vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;
        vault.put_edge(&subject, EdgeKind::Supports, &claim, 1.0)?;
        vault.put_edge(&claim, EdgeKind::BelongsTo, &subject, 1.0)?;
        Ok((claim, turn))
    }

    fn assert_populated_before_retry(vault: &Vault, claim: EntityId) -> Result<()> {
        assert_eq!(
            vault.get_claim(&claim)?.expect("approved").approval,
            ClaimApprovalStatus::Approved
        );
        let mut semantic = 0;
        let mut structural = 0;
        for edge in vault
            .edges_out(&claim)?
            .into_iter()
            .chain(vault.edges_in(&claim)?)
        {
            match edge.kind {
                EdgeKind::Mentions | EdgeKind::Supports => {
                    semantic += 1;
                    assert_eq!(edge.vad, Some(FULL_VAD));
                }
                EdgeKind::BelongsTo => {
                    structural += 1;
                    assert_eq!(edge.vad, None);
                }
                _ => {}
            }
        }
        let mut states = Vec::new();
        for edge in vault.edges_in(&claim)? {
            if edge.kind == EdgeKind::ClaimOf
                && let Some(body) = vault.get_claim(&edge.target)?
                && body.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                states.push(edge.target);
            }
        }
        assert_eq!(
            semantic, 2,
            "both incident directions populated by production hook"
        );
        assert_eq!(structural, 1);
        assert_eq!(states.len(), 1, "hook created exactly one audit state");
        let retry = vault.consolidate_claim_vad_now(&claim, 30)?;
        assert_eq!(retry.vad, Some(FULL_VAD));
        assert_eq!(retry.reappraisal.active_claim_id, Some(states[0]));
        assert_eq!(retry.reappraisal.created_claim_id, None);
        Ok(())
    }

    #[test]
    fn inbox_vad_error_keeps_approval_and_canonical_retry_recovers_idempotently() -> Result<()> {
        for edit in [false, true] {
            let (_tmp, vault) = temp_vault();
            let (claim, turn) = proposal(&vault, "profile.name")?;
            let annotation = crate::affect::vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
            let original = {
                let rtxn = vault.store.env.read_txn()?;
                vault
                    .store
                    .entities
                    .get(&rtxn, annotation.as_bytes())?
                    .expect("annotation claim")
                    .to_vec()
            };
            // A valid envelope with the wrong entity type is a deterministic
            // canonical VAD error, not an approval or evidence-binding failure.
            vault.with_write_txn(|wtxn| {
                let corrupt = crate::test_util::entity_record(
                    ENTITY_TYPE_PERSON,
                    time(3),
                    3,
                    b"corrupt annotation",
                );
                vault
                    .store
                    .entities
                    .put(wtxn, annotation.as_bytes(), &corrupt)?;
                Ok(())
            })?;
            let amended = edited_body(&vault, claim, "reviewed")?;
            let approve = || {
                if edit {
                    vault
                        .approve_inbox_member_with_edit_at(&claim, &amended, 20)
                        .map(|_| ())
                } else {
                    vault
                        .resolve_inbox_group_at(RUN, InboxBulkVerb::AcceptAll, None, 20)
                        .map(|_| ())
                }
            };
            assert!(matches!(
                approve(),
                Err(Error::CorruptedIndex("VAD annotation claim"))
            ));
            let stored = vault
                .get_claim(&claim)?
                .expect("approved survives VAD failure");
            assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
            if edit {
                assert_eq!(stored.value, Value::from("reviewed"));
            }
            assert!(vault.pending_gate_consents(10)?.is_empty());
            assert!(matches!(approve(), Err(Error::EntityNotFound)));
            vault.with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .put(wtxn, annotation.as_bytes(), &original)?;
                Ok(())
            })?;
            let recovered = vault.consolidate_claim_vad_now(&claim, 30)?;
            assert_eq!(recovered.vad, Some(FULL_VAD));
            assert!(recovered.reappraisal.created_claim_id.is_some());
            assert_populated_before_retry(&vault, claim)?;
        }
        Ok(())
    }
}

#[test]
fn erasing_one_inbox_bundle_member_shreds_all_constituent_refs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let first = entity(0x91);
    let second = entity(0x92);
    let independent = entity(0x93);
    for (id, run, predicate, actor, subject) in [
        (first, "erase-bundle", "profile.diet", 0xB1, 0xC1),
        (second, "erase-bundle", "profile.hobby", 0xB1, 0xC1),
        (independent, "keep-bundle", "profile.diet", 0xB2, 0xC2),
    ] {
        write_dreamer_proposal(
            &vault,
            id,
            entity(actor),
            entity(subject),
            predicate,
            "value",
            run,
            10,
            &[REASON_CEILING],
        )?;
    }
    let target =
        vault.resolve_inbox_group_at("erase-bundle", InboxBulkVerb::AcceptAll, None, 50)?;
    let survivor =
        vault.resolve_inbox_group_at("keep-bundle", InboxBulkVerb::AcceptAll, None, 51)?;
    let target_id = crate::store::GateDecisionId::from_bytes(
        *uuid::Uuid::parse_str(target.bundle_receipt.receipt_id.trim_start_matches("gate:"))
            .expect("bundle receipt id")
            .as_bytes(),
    );
    let rtxn = vault.store.env.read_txn()?;
    for id in [first, second] {
        assert!(
            vault
                .store
                .bundle_gate_decisions_for_claim_in_txn(&rtxn, id.as_bytes())?
                .iter()
                .any(|row| row.decision_id == target_id)
        );
        assert!(
            vault
                .store
                .gate_decisions_for_claim_in_txn(&rtxn, id.as_bytes())?
                .iter()
                .all(|row| row.claim_id == Some(*id.as_bytes())),
            "ordinary claim verdict reads exclude multi-claim bundle rows"
        );
    }
    drop(rtxn);

    assert!(vault.delete_entity(&first)?);
    let rtxn = vault.store.env.read_txn()?;
    let redacted = vault
        .store
        .gate_decision_in_txn(&rtxn, target_id)?
        .expect("bundle accountability skeleton");
    assert!(redacted.redacted_at.is_some());
    assert!(redacted.diff_handle.is_empty());
    assert!(redacted.grant_ref.is_none());
    for id in [first, second] {
        assert!(
            !vault
                .store
                .bundle_gate_decisions_for_claim_in_txn(&rtxn, id.as_bytes())?
                .iter()
                .any(|row| row.decision_id == target_id)
        );
    }
    assert!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, first.as_bytes())?
            .is_empty()
    );
    drop(rtxn);
    assert!(
        vault
            .store
            .gate_decisions_for_grant_ref(&survivor.bundle_ref)?
            .iter()
            .any(|row| row.redacted_at.is_none())
    );
    Ok(())
}

#[test]
fn deleting_unresolved_proposal_shreds_tray_and_prevents_let_go_resurrection() -> Result<()> {
    for batch_delete in [false, true] {
        let (_tmp, vault) = temp_vault();
        let claim_id = entity(0x71);
        let run_id = "erase-unresolved";
        write_dreamer_proposal(
            &vault,
            claim_id,
            entity(0xB1),
            entity(0xC1),
            "profile.diet",
            "sensitive",
            run_id,
            10,
            &[REASON_CEILING],
        )?;
        assert_eq!(vault.pending_gate_consents(10)?.len(), 1);
        if batch_delete {
            vault.batch().delete(&claim_id).commit()?;
        } else {
            vault
                .delete_entity_with_reason(&claim_id, crate::deletion::DeleteReason::UserDelete)?;
        }
        assert!(vault.pending_gate_consents(10)?.is_empty());
        assert!(
            vault
                .store
                .pending_gate_consents_for_run(run_id)?
                .is_empty()
        );
        assert!(vault.let_go_pending_ask_at(&claim_id, 99)?.is_none());
        let rtxn = vault.store.env.read_txn()?;
        let rows = vault
            .store
            .gate_decisions_for_claim_in_txn(&rtxn, claim_id.as_bytes())?;
        assert!(!rows.is_empty());
        assert!(
            rows.iter()
                .all(|row| row.redacted_at.is_some() && row.diff_handle.is_empty())
        );
        assert!(
            vault
                .store
                .verify_claim_erasure_by_scan_in_txn(&rtxn, claim_id.as_bytes())?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn batch_delete_of_approved_member_redacts_singular_and_bundle_decisions() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let first = entity(0x72);
    let second = entity(0x73);
    for (id, predicate) in [(first, "profile.diet"), (second, "profile.hobby")] {
        write_dreamer_proposal(
            &vault,
            id,
            entity(0xB1),
            entity(0xC1),
            predicate,
            "sensitive",
            "erase-batch-bundle",
            10,
            &[REASON_CEILING],
        )?;
    }
    let receipt =
        vault.resolve_inbox_group_at("erase-batch-bundle", InboxBulkVerb::AcceptAll, None, 50)?;
    let bundle_id = GateDecisionId::from_bytes(
        *uuid::Uuid::parse_str(
            receipt
                .bundle_receipt
                .receipt_id
                .trim_start_matches("gate:"),
        )
        .expect("bundle id")
        .as_bytes(),
    );
    vault.batch().delete(&first).commit()?;
    let rtxn = vault.store.env.read_txn()?;
    let singular = vault
        .store
        .gate_decisions_for_claim_in_txn(&rtxn, first.as_bytes())?;
    assert!(!singular.is_empty());
    assert!(
        singular
            .iter()
            .all(|row| row.redacted_at.is_some() && row.diff_handle.is_empty())
    );
    let bundle = vault
        .store
        .gate_decision_in_txn(&rtxn, bundle_id)?
        .expect("bundle skeleton remains");
    assert!(bundle.redacted_at.is_some());
    assert!(bundle.diff_handle.is_empty());
    assert!(
        vault
            .store
            .bundle_gate_decisions_for_claim_in_txn(&rtxn, second.as_bytes())?
            .is_empty()
    );
    assert!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, first.as_bytes())?
            .is_empty()
    );
    Ok(())
}
