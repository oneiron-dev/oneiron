use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_TASK;
use crate::session_lifecycle::{SessionClosePredicate, SessionEndWake, SessionMintOutcome};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::skill_attribution::{
    AttemptOutcome, OutcomeEvidence, read_attribution_cursor, record_attribution_evidence,
    run_attribution_projector,
};

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn put_actor(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"sk06 actor fixture")?;
    Ok(id)
}

fn put_skill(vault: &Vault, skill_id: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let tree_hash = canonical_skill_tree_hash([("SKILL.md", b"# sk06 fixture\n".as_slice())])
        .expect("fixture tree hashes");
    let candidate = SkillRecord::new(
        skill_id,
        "sk06 fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("sk06-fixture"))]),
    )
    .with_content_hash(tree_hash);
    vault.put_skill_record(&id, &candidate, t(10), 11)?;
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, t(12), 13)?;
    Ok(id)
}

fn task_evidence(at: u64) -> ActorClaimEvidence {
    ActorClaimEvidence::task(vec!["receipt:sk06".to_owned()], at).expect("task evidence")
}

fn chat_evidence(at: u64) -> ActorClaimEvidence {
    ActorClaimEvidence::chat(EntityId::now(), vec![EntityId::now()], at).expect("chat evidence")
}

fn rows(
    vault: &Vault,
    actor: &EntityId,
    predicate: &str,
) -> Result<(Vec<ClaimBody>, Vec<ClaimBody>)> {
    let mut active = Vec::new();
    let mut superseded = Vec::new();
    for id in vault.claims_for_subject(actor)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate != predicate {
            continue;
        }
        match body.lifecycle {
            ClaimLifecycleStatus::Active => active.push(body),
            ClaimLifecycleStatus::Superseded => superseded.push(body),
            ClaimLifecycleStatus::Retracted => {}
        }
    }
    Ok((active, superseded))
}

/// Runs one attempt whose pack loaded `skill_id` to its terminal door and
/// returns the receipt id close STAMPED.
fn stamped_pack_receipt(vault: &Vault, skill_id: &str) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "sk06.attempt".to_owned(),
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
        ManifestEntry::new(ManifestKind::Skill, skill_id, "1.0.0", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "sk06-worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("the enqueued attempt is claimable");
    };
    queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "sk06-worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;
    Ok(attempt_pack_receipt_id(&attempt.id))
}

/// A distiller that returns exactly the notes it was handed.
struct FixedDistiller(Vec<ActorNote>);

impl SessionActorDistiller for FixedDistiller {
    fn distill(&self, _brief: &SessionDistillBrief) -> Result<Vec<ActorNote>> {
        Ok(self.0.clone())
    }
}

// ─── cardinality ────────────────────────────────────────────────────────

#[test]
fn set_rows_dedupe_on_the_normalized_note() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    let first = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "cite the receipt".to_owned(),
        },
        &task_evidence(30),
    )?;
    // Same meaning, different spacing: one standing fact, not two.
    let repeat = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "  cite   the receipt  ".to_owned(),
        },
        &task_evidence(31),
    )?;
    assert_eq!(
        first, repeat,
        "a duplicate note re-returns the standing row"
    );

    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "read the diff".to_owned(),
        },
        &task_evidence(32),
    )?;

    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(
        active.len(),
        2,
        "two distinct lessons, one duplicate folded"
    );
    assert!(
        superseded.is_empty(),
        "SET rows dedupe; they never supersede"
    );
    Ok(())
}

#[test]
fn skill_fit_supersedes_per_pair_not_per_actor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill_a = put_skill(&vault, "sk06.fit.a")?;
    let skill_b = put_skill(&vault, "sk06.fit.b")?;

    for (skill, fit, at) in [
        (skill_a, 0.25_f32, 40_u64),
        (skill_a, 0.75, 41),
        (skill_b, 0.5, 42),
    ] {
        write_actor_claim(
            &vault,
            ActorClaimRow::SkillFit { actor, skill, fit },
            &task_evidence(at),
        )?;
    }

    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_SKILL_FIT)?;
    assert_eq!(active.len(), 2, "one live row per (actor, skill)");
    assert_eq!(superseded.len(), 1, "only skill_a's first estimate closed");
    assert_eq!(superseded[0].value, Value::F32(0.25));
    assert_eq!(skill_fit_for(&vault, &actor, &skill_a)?, Some(0.75));
    assert_eq!(skill_fit_for(&vault, &actor, &skill_b)?, Some(0.5));
    Ok(())
}

#[test]
fn fit_outside_the_unit_interval_or_non_finite_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "sk06.fit.range")?;

    for fit in [1.5_f32, -0.1, f32::NAN, f32::INFINITY] {
        let error = write_actor_claim(
            &vault,
            ActorClaimRow::SkillFit { actor, skill, fit },
            &task_evidence(50),
        )
        .expect_err("an out-of-range or non-finite fit is refused");
        assert!(
            matches!(error, Error::InvalidClaimBody(_)),
            "typed rejection, got {error:?}"
        );
    }
    assert_eq!(skill_fit_for(&vault, &actor, &skill)?, None);
    Ok(())
}

#[test]
fn an_empty_note_and_an_unknown_actor_are_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    let blank = write_actor_claim(
        &vault,
        ActorClaimRow::ScopeNote {
            actor,
            text: "   ".to_owned(),
        },
        &task_evidence(60),
    )
    .expect_err("a blank note is refused");
    assert!(matches!(blank, Error::InvalidClaimBody(_)));

    let missing = write_actor_claim(
        &vault,
        ActorClaimRow::FailureMode {
            actor: EntityId::now(),
            text: "skips verification".to_owned(),
        },
        &task_evidence(61),
    )
    .expect_err("an unresolvable actor is refused");
    assert!(matches!(missing, Error::EntityNotFound));
    Ok(())
}

#[test]
fn evidence_free_rows_are_unconstructible() {
    assert!(ActorClaimEvidence::task(Vec::new(), 70).is_err());
    assert!(ActorClaimEvidence::chat(EntityId::now(), Vec::new(), 70).is_err());
}

// ─── write gating ───────────────────────────────────────────────────────

#[test]
fn public_writes_of_the_four_predicates_are_reserved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    for predicate in [
        PREDICATE_ACTOR_LESSON,
        PREDICATE_ACTOR_FAILURE_MODE,
        PREDICATE_ACTOR_SCOPE_NOTE,
        PREDICATE_ACTOR_SKILL_FIT,
    ] {
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(actor),
            Value::from("hand written"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(Value::from("forged"));
        body.source = Some(ClaimSource::Generated);
        let error = vault
            .put_claim(&EntityId::now(), &body, t(80), 80)
            .expect_err("the generic claim API must refuse a reserved predicate");
        assert!(
            matches!(error, Error::ReservedPredicate { .. }),
            "typed reserved-namespace rejection, got {error:?}"
        );
    }
    Ok(())
}

#[test]
fn the_provider_confidence_prior_path_still_writes_and_supersedes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    crate::provider_confidence::write_provider_prior(&vault, "provider_sk06", 0.4, "evidence:a")?;
    crate::provider_confidence::write_provider_prior(&vault, "provider_sk06", 0.8, "evidence:b")?;

    assert_eq!(
        crate::provider_confidence::count_active_prior_claims(&vault, "provider_sk06")?,
        1,
        "the reserved door still supersedes the old head"
    );
    assert_eq!(
        crate::provider_confidence::count_superseded_prior_claims(&vault, "provider_sk06")?,
        1
    );
    Ok(())
}

#[test]
fn stored_rows_are_auto_evidence_carrying_and_lineage_stamped() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "from the task lane".to_owned(),
        },
        &task_evidence(90),
    )?;
    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "from the chat lane".to_owned(),
        },
        &chat_evidence(91),
    )?;

    let (active, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(active.len(), 2, "one ledger, two inlets");
    let mut lineages: Vec<Option<ClaimSource>> = active.iter().map(actor_claim_lineage).collect();
    lineages.sort_by_key(|source| source.map(ClaimSource::as_str));
    assert_eq!(
        lineages,
        vec![Some(ClaimSource::Generated), Some(ClaimSource::ToolOutput)],
        "the evidence meet is derived per lane, never a blanket restamp"
    );
    for body in &active {
        assert_eq!(body.approval, ClaimApprovalStatus::Auto);
        assert_eq!(body.confidence, 1.0);
        assert_eq!(
            body.source,
            Some(ClaimSource::Observed),
            "the projector observed the trace; the meet rides the evidence"
        );
        assert!(body.evidence.is_some(), "gate-written rows carry evidence");
    }
    Ok(())
}

#[test]
fn the_structural_validator_refuses_bare_or_mis_sourced_rows() {
    let actor = EntityId::now();
    let bare = ClaimBody::new(
        PREDICATE_ACTOR_LESSON,
        ClaimSubject::Entity(actor),
        Value::from("no evidence"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    assert!(validate_actor_claim_structure(&bare).is_err());

    let lineaged = |meet: ClaimSource| {
        Value::Map(vec![(
            Value::from(ACTOR_CLAIM_LINEAGE_KEY),
            Value::from(meet.as_str()),
        )])
    };

    let mut no_lineage = bare.clone();
    no_lineage.evidence = Some(Value::from("a bare string is not a meet"));
    no_lineage.source = Some(ClaimSource::Observed);
    assert!(
        validate_actor_claim_structure(&no_lineage).is_err(),
        "a row with no legible lineage cannot launder its trail"
    );

    let mut imported = bare.clone();
    imported.evidence = Some(lineaged(ClaimSource::ToolOutput));
    imported.source = Some(ClaimSource::Imported);
    assert!(
        validate_actor_claim_structure(&imported).is_err(),
        "a federation-restamped foreign row never enters this routing signal"
    );

    let mut proposed = bare.clone();
    proposed.evidence = Some(lineaged(ClaimSource::Generated));
    proposed.source = Some(ClaimSource::Observed);
    proposed.approval = ClaimApprovalStatus::Proposed;
    assert!(validate_actor_claim_structure(&proposed).is_err());

    let mut unnormalized = bare;
    unnormalized.evidence = Some(lineaged(ClaimSource::Generated));
    unnormalized.source = Some(ClaimSource::Observed);
    unnormalized.value = Value::from("  padded  ");
    assert!(validate_actor_claim_structure(&unnormalized).is_err());
}

// ─── TASK lane ──────────────────────────────────────────────────────────

#[test]
fn lapse_judgments_project_lesson_and_failure_mode_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "sk06.lapse")?;
    let receipt = stamped_pack_receipt(&vault, "sk06.lapse")?;

    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 100)
            .with_skill(skill)
            .with_routing_facts(false, false),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    assert_eq!(judgments.len(), 1);
    assert_eq!(judgments[0].verdict, AttributionVerdict::ExecutionLapse);

    let written = project_actor_claims_from_judgments(&vault, &judgments)?;
    assert_eq!(written.len(), 2, "one failure mode, one lesson");

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    let (failure_modes, _) = rows(&vault, &actor, PREDICATE_ACTOR_FAILURE_MODE)?;
    assert_eq!(lessons.len(), 1);
    assert_eq!(failure_modes.len(), 1);
    assert_eq!(failure_modes[0].value, Value::from(LAPSE_FAILURE_MODE));
    assert_eq!(
        actor_claim_lineage(&lessons[0]),
        Some(ClaimSource::ToolOutput),
        "a receipt-derived row says so; it is not a blanket Generated restamp"
    );
    assert_eq!(
        lessons[0].evidence.as_ref().and_then(|value| value
            .as_map()?
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_RECEIPTS))
            .map(|(_, receipts)| receipts.clone())),
        Some(Value::Array(vec![Value::from(receipt.as_str())])),
        "the row cites the attempt receipt it rests on"
    );

    // A second pass over the same judgments folds into the same two rows.
    let replay = project_actor_claims_from_judgments(&vault, &judgments)?;
    assert_eq!(
        replay, written,
        "re-projection is idempotent by cardinality"
    );
    Ok(())
}

#[test]
fn an_unpersisted_or_uncited_judgment_is_skipped() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    let forged = AttributionJudgment {
        sequence: 99,
        verdict: AttributionVerdict::ExecutionLapse,
        subject: actor,
        evidence_receipts: vec!["receipt:never-stamped".to_owned()],
        at: 100,
    };
    assert!(project_actor_claims_from_judgments(&vault, &[forged])?.is_empty());

    let uncited = AttributionJudgment {
        sequence: 1,
        verdict: AttributionVerdict::ExecutionLapse,
        subject: actor,
        evidence_receipts: Vec::new(),
        at: 100,
    };
    assert!(project_actor_claims_from_judgments(&vault, &[uncited])?.is_empty());

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert!(lessons.is_empty(), "ungrounded rows write nothing");
    Ok(())
}

// ─── CHAT lane ──────────────────────────────────────────────────────────

/// Mints a sitting with `turn_count` turns, ends it through the wake, and
/// returns the session id.
fn ended_chat_session(vault: &Vault, turn_count: usize, now: u64) -> Result<EntityId> {
    let SessionMintOutcome::Minted(session) = vault.mint_session(now)? else {
        panic!("a fresh vault mints");
    };
    for index in 0..turn_count {
        let turn = EntityId::now();
        let body = Value::Map(vec![
            (Value::from("spkr"), Value::from("user")),
            (Value::from("txt"), Value::from(format!("turn {index}"))),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &body)
            .map_err(|_| Error::InvariantViolation("fixture turn encode"))?;
        vault.put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            t(now + index as u64),
            now + index as u64,
            &bytes,
        )?;
        vault.put_edge(&turn, EdgeKind::ChildOf, &session, 1.0)?;
    }
    vault.end_session_with_wake(
        &session,
        SessionClosePredicate::Explicit,
        now + 100,
        &SessionEndWake::none(0),
    )?;
    Ok(session)
}

#[test]
fn session_end_registers_a_distill_job_the_run_consumes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let session = ended_chat_session(&vault, 2, 200)?;
    assert_eq!(pending_session_actor_distills(&vault)?, vec![session]);

    let distilled = run_session_end_actor_distill(
        &vault,
        &session,
        &FixedDistiller(vec![ActorNote {
            actor,
            kind: ActorNoteKind::Lesson,
            text: "ask before assuming the file layout".to_owned(),
        }]),
    )?;
    assert_eq!(distilled.len(), 1);
    assert!(
        pending_session_actor_distills(&vault)?.is_empty(),
        "the job is consumed, so a re-run cannot serve the same notes twice"
    );

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(lessons.len(), 1, "chat still teaches");
    assert_eq!(
        actor_claim_lineage(&lessons[0]),
        Some(ClaimSource::Generated)
    );
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_TASK)?,
        0,
        "plain chatting mints no TASK (08b r13)"
    );

    let rerun = run_session_end_actor_distill(&vault, &session, &FixedDistiller(Vec::new()))
        .expect_err("a consumed job is not servable twice");
    assert!(matches!(rerun, Error::InvalidClaimBody(_)));
    Ok(())
}

#[test]
fn the_brief_carries_the_sittings_turns_in_scan_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = ended_chat_session(&vault, 3, 300)?;
    let turns = session_turns(&vault, &session)?;
    assert_eq!(turns.len(), 3);
    assert_eq!(turns[0].speaker.as_deref(), Some("user"));
    assert_eq!(turns[0].text.as_deref(), Some("turn 0"));
    assert_eq!(turns[2].text.as_deref(), Some("turn 2"));
    Ok(())
}

#[test]
fn a_sitting_with_no_turns_distills_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let session = ended_chat_session(&vault, 0, 400)?;

    let distilled = run_session_end_actor_distill(
        &vault,
        &session,
        &FixedDistiller(vec![ActorNote {
            actor,
            kind: ActorNoteKind::ScopeNote,
            text: "invented from nothing".to_owned(),
        }]),
    )?;
    assert!(
        distilled.is_empty(),
        "no turns is no evidence, whatever a distiller offers"
    );
    Ok(())
}
