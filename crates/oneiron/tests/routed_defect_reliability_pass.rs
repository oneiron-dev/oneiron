//! [ROUTED-DEFECT-UNSTAMPED-RECEIPT-FAILS-RELIABILITY-PASS]: the reliability
//! pass (`skill_reliability::project_skill_reliability`) skips a routed
//! `skill_defect` judgment whose cited pack receipt can train no named cell,
//! as it skips every other ungrounded row, so the judgments after it in the
//! same pass still land. A receipt with no executor stamp stays in the legacy
//! bucket, and a receipt with no task typeRef has no cell: the outcome ledger
//! refuses both. Before the fix the first such row ended the whole pass with
//! that refusal, and every later skill kept no loss.
//!
//! Public paths only, so the stem builds with or without
//! `--cfg oneiron_test_support`.

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::receipt::attempt_pack_receipt_id;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_attribution::{
    AttemptOutcome, AttributionJudgment, AttributionVerdict, OutcomeEvidence,
    read_attribution_cursor, record_attribution_evidence, run_attribution_projector,
};
use oneiron::skill_reliability::{effective_skill_outcome, project_skill_reliability};
use oneiron::{ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, VaultConfig};

/// The skill whose attempt cites the receipt that can train no cell.
const FIRST_SKILL_ID: &str = "routed-defect.first";
/// The skill whose attempt cites a typed, stamped receipt.
const SECOND_SKILL_ID: &str = "routed-defect.second";
const SKILL_VERSION: &str = "1.0.0";
/// The executor revision an attempt fixture stamps.
const MODEL: &str = "fixture/model@1";
/// The lease owner of an attempt fixture.
const LEASE: &str = "fixture";
/// The kind of the plain queue row an untyped attempt fixture runs as.
const UNTYPED_KIND: &str = "test.routed_defect.untyped";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A fresh vault and the PERSON every attempt fixture is bound to.
struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
}

fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let actor = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "person" })).expect("body");
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, &body)
        .expect("FIXTURE: the actor");
    Seeded {
        _dir: dir,
        vault,
        actor,
    }
}

/// An Active skill named `skill_id` at [`SKILL_VERSION`].
fn active_skill(vault: &Vault, skill_id: &str) -> EntityId {
    let id = EntityId::now();
    let tree =
        canonical_skill_tree_hash([("SKILL.md", format!("# {skill_id} fixture\n").as_bytes())])
            .expect("FIXTURE: the skill tree hash");
    let candidate = SkillRecord::new(
        skill_id,
        "a skill whose content was wrong",
        SKILL_VERSION,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("routed-defect-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault
        .put_skill_record(&id, &candidate, at(10), 11)
        .expect("FIXTURE: the skill");
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &active, at(12), 13)
        .expect("FIXTURE: the skill goes Active");
    id
}

/// A completed attempt the actor ran with `skill_id`'s pack loaded,
/// returning its pack receipt. `typed`: an agent dispatch, whose receipt
/// carries the task typeRef; otherwise a plain queue row, whose receipt
/// carries none. `stamped`: its executor revision is stamped.
fn completed_attempt(seeded: &Seeded, skill_id: &str, typed: bool, stamped: bool) -> String {
    let vault = &seeded.vault;
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let (row, kind) = if typed {
        let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(vault)
            .dispatch_default_base(None, None, None, now)
            .expect("FIXTURE: the agent dispatch")
        else {
            panic!("FIXTURE: a fresh agent dispatch");
        };
        (dispatched.attempt, DREAMER_RUNNER_ATTEMPT_KIND)
    } else {
        let EnqueueOutcome::Enqueued(row) = queue
            .enqueue(EnqueueAttempt {
                kind: UNTYPED_KIND.to_owned(),
                payload: b"untyped".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("FIXTURE: the queue row")
        else {
            panic!("FIXTURE: a fresh queue row");
        };
        (row, UNTYPED_KIND)
    };
    vault
        .bind_actor_attempt(row.id, &seeded.actor)
        .expect("FIXTURE: the actor runs the attempt");
    queue
        .append_manifest_entry(
            row.id,
            ManifestEntry::new(ManifestKind::Skill, skill_id, SKILL_VERSION, now),
        )
        .expect("FIXTURE: the pack loads the skill");
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            kind,
            ClaimAttempt {
                lease_owner: LEASE.to_owned(),
                now: vault.now_recorded_at(),
            },
        )
        .expect("FIXTURE: the claim")
    else {
        panic!("FIXTURE: the attempt leases");
    };
    assert_eq!(leased.id, row.id, "FIXTURE: the claim leases this attempt");
    if stamped {
        queue
            .set_executor_model(row.id, LEASE, leased.attempt_count, MODEL)
            .expect("FIXTURE: the executor stamp");
    }
    let completed = queue
        .complete(CompleteAttempt {
            id: row.id,
            lease_owner: LEASE.to_owned(),
            attempt_count: leased.attempt_count,
            now: vault.now_recorded_at(),
        })
        .expect("FIXTURE: the completion");
    assert!(
        matches!(completed, CompleteOutcome::Completed(_)),
        "FIXTURE: the attempt completes"
    );
    attempt_pack_receipt_id(&row.id)
}

/// Records that the attempt under `receipt` failed while the actor followed
/// `skill` and the skill covered the step: the rule tier routes it as a
/// `skill_defect` of `skill`.
fn record_defect_evidence(seeded: &Seeded, skill: EntityId, receipt: &str, time: u64) {
    record_attribution_evidence(
        &seeded.vault,
        &OutcomeEvidence::new(receipt, seeded.actor, AttemptOutcome::Failed, time)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )
    .expect("FIXTURE: the defect evidence");
}

/// The attempt's outcome as the skill's attributed ledger reads it.
fn attempt_outcome(seeded: &Seeded, skill: &EntityId, receipt: &str) -> Option<bool> {
    effective_skill_outcome(&seeded.vault, skill, receipt).expect("attributed outcome read")
}

/// Two defects routed in one attribution pass: the first on an attempt of
/// the first skill, typed and stamped as given; the second on a typed,
/// stamped attempt of the second skill.
struct TwoDefects {
    first: EntityId,
    first_receipt: String,
    second: EntityId,
    second_receipt: String,
    judgments: Vec<AttributionJudgment>,
}

fn two_routed_defects(seeded: &Seeded, first_typed: bool, first_stamped: bool) -> TwoDefects {
    let vault = &seeded.vault;
    let first = active_skill(vault, FIRST_SKILL_ID);
    let second = active_skill(vault, SECOND_SKILL_ID);
    let first_receipt = completed_attempt(seeded, FIRST_SKILL_ID, first_typed, first_stamped);
    let second_receipt = completed_attempt(seeded, SECOND_SKILL_ID, true, true);
    record_defect_evidence(seeded, first, &first_receipt, 30);
    record_defect_evidence(seeded, second, &second_receipt, 31);
    let cursor = read_attribution_cursor(vault).expect("FIXTURE: the attribution cursor");
    let judgments =
        run_attribution_projector(vault, cursor).expect("FIXTURE: the attribution pass");
    assert_eq!(
        judgments
            .iter()
            .map(|judgment| (judgment.verdict, judgment.subject))
            .collect::<Vec<_>>(),
        vec![
            (AttributionVerdict::SkillDefect, Some(first)),
            (AttributionVerdict::SkillDefect, Some(second)),
        ],
        "FIXTURE: both outcomes route as skill defects, the first skill's first"
    );
    TwoDefects {
        first,
        first_receipt,
        second,
        second_receipt,
        judgments,
    }
}

/// Runs the reliability pass over both judgments and checks that the first
/// is skipped and the second lands; `why` names the first receipt's gap.
fn assert_pass_skips_first_and_lands_second(seeded: &Seeded, defects: &TwoDefects, why: &str) {
    let projected = project_skill_reliability(&seeded.vault, &defects.judgments);
    assert_eq!(
        projected.as_ref().ok(),
        Some(&vec![defects.second]),
        "the pass skips the defect whose receipt has {why} and projects the second skill: \
         {projected:?}"
    );
    assert_eq!(
        attempt_outcome(seeded, &defects.second, &defects.second_receipt),
        Some(false),
        "the second skill's defect lands as its attempt's loss"
    );
    assert_eq!(
        attempt_outcome(seeded, &defects.first, &defects.first_receipt),
        None,
        "the defect whose receipt has {why} trains no cell"
    );
}

#[test]
fn a_routed_defect_on_an_unstamped_receipt_leaves_the_later_defects_projected() {
    let seeded = seed();
    let defects = two_routed_defects(&seeded, true, false);
    assert_pass_skips_first_and_lands_second(&seeded, &defects, "no executor stamp");
}

#[test]
fn a_routed_defect_on_an_untyped_receipt_leaves_the_later_defects_projected() {
    let seeded = seed();
    let defects = two_routed_defects(&seeded, false, true);
    assert_pass_skips_first_and_lands_second(&seeded, &defects, "no task typeRef");
}
