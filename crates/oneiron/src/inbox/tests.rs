use rmpv::Value;

use super::*;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerJob, EnqueueDreamerJobOutcome};
use crate::edge::EdgeActorClass;
use crate::job_queue::{EnqueueJob, EnqueueOutcome, JobId};
use crate::receipt::ReceiptQuery;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;
use crate::types::{VaultConfig, WriteActor, WriteEnvelope, WriteProvenance};

const REASON_CEILING: &str = "gate.pending.actor_ceiling";
const REASON_CRITICAL: &str = "gate.pending.criticality_floor";
const REASON_CHECKER: &str = "gate.pending.checker_low_confidence";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("entity id")
}

fn time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn dreamer_envelope(actor: EntityId, run_id: &str) -> WriteEnvelope {
    WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from(DREAMER_RUNNER_JOB_KIND)),
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
    let candidate = crate::types::ClaimCandidate::new(
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

fn enqueue_dreamer_job(
    vault: &Vault,
    job_type: &str,
    parent_job: Option<JobId>,
    input: Value,
    run_id: &str,
    now: u64,
) -> Result<JobId> {
    let runner = DreamerRunnerStore::new(vault);
    match runner.enqueue(EnqueueDreamerJob {
        job_type: job_type.to_owned(),
        input,
        parent_job,
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now,
    })? {
        EnqueueDreamerJobOutcome::Enqueued(status) | EnqueueDreamerJobOutcome::Existing(status) => {
            Ok(status.job.id)
        }
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
    let root = enqueue_dreamer_job(
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
    let branch = enqueue_dreamer_job(
        &vault,
        "entity-sweep",
        Some(root),
        Value::from("branch input"),
        run_id,
        20,
    )?;

    write_dreamer_proposal(
        &vault,
        entity(0xA1),
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
        entity(0xA2),
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
    assert_eq!(group.members[0].claim_id, entity(0xA1).to_hex());
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
    let first = entity(0xA1);
    let second = entity(0xA2);
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
fn reject_all_emits_per_item_receipts_and_keeps_proposal_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-reject";
    let first = entity(0xA1);
    let second = entity(0xA2);
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
    let original = entity(0xA1);
    let duplicate = entity(0xA2);
    let distinct = entity(0xA3);
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
fn approve_all_dial_still_surfaces_manifest_critical() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-dial";
    let critical = entity(0xA1);
    let plain = entity(0xA2);
    let hedged = entity(0xA3);
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
    let lapsing = entity(0xA1);
    let sibling = entity(0xA2);
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
    let candidate = crate::types::ClaimCandidate::new(
        "profile.diet",
        ClaimSubject::Entity(subject),
        Value::from("vegan"),
        1.0,
    );
    vault
        .batch()
        .claim_candidate(&truth, candidate, &envelope, time(5), 5)
        .commit()?;

    let update = entity(0xA1);
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
    let conflict = entity(0xA2);
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
    let plain = entity(0xA3);
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
            entity(0xA1 + offset),
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
            entity(0xE1 + offset),
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
fn run_root_ignores_non_dreamer_jobs_sharing_the_run_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let run_id = "run-mixed";
    // A non-Dreamer job with the same run id, created BEFORE the dreamer
    // root, must never be picked as the run-tree root.
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(webhook) = queue.enqueue(EnqueueJob {
        kind: "webhook".to_owned(),
        payload: b"webhook payload".to_vec(),
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now: 5,
    })?
    else {
        panic!("expected fresh enqueue");
    };
    let root = enqueue_dreamer_job(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Mixed run"))]),
        run_id,
        10,
    )?;

    write_dreamer_proposal(
        &vault,
        entity(0xA1),
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
fn run_root_climbs_parent_links_for_branch_run_ids() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let root = enqueue_dreamer_job(
        &vault,
        "orchestrator",
        None,
        Value::Map(vec![(Value::from("intent"), Value::from("Branch climb"))]),
        "run-parent",
        10,
    )?;
    let branch = enqueue_dreamer_job(
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
        entity(0xA1),
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
    let candidate = crate::types::ClaimCandidate::new(
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
        entity(0xA1),
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
    let original = entity(0xA1);
    let duplicate = entity(0xA2);
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
