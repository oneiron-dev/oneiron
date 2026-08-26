use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
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

/// TASK-lane evidence citing a receipt an attempt actually STAMPED — the door
/// resolves every citation, so a hand-written receipt string lands nothing.
fn task_evidence(vault: &Vault, at: u64) -> ActorClaimEvidence {
    let receipt = stamped_pack_receipt(vault, "sk06.evidence").expect("stamped receipt");
    ActorClaimEvidence::task(vec![receipt], at).expect("task evidence")
}

/// CHAT-lane evidence citing a sitting and a turn this vault actually holds.
fn chat_evidence(vault: &Vault, at: u64) -> ActorClaimEvidence {
    let session = witnessed_chat_session(vault, 1, at).expect("witnessed sitting");
    let turns = session_turns(
        vault,
        SittingWindow {
            started_at: at,
            ended_at: at + 100,
        },
    )
    .expect("the sitting's turns");
    ActorClaimEvidence::chat(session, turns.iter().map(|turn| turn.turn).collect(), at)
        .expect("chat evidence")
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
///
/// Claimed BY KIND, like every production worker: a fresh row's ready key is
/// `(0, attempt_id)`, so an untyped claim takes the oldest row in the whole
/// vault — including the ones a fixture's session close registers.
fn stamped_pack_receipt(vault: &Vault, skill_id: &str) -> Result<String> {
    const KIND: &str = "sk06.attempt";
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: KIND.to_owned(),
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
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        KIND,
        ClaimAttempt {
            lease_owner: "sk06-worker".to_owned(),
            now: 12,
        },
    )?
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

/// A distiller tier that is having a bad day — the host-supplied seam is the
/// one step in this pass that fails for reasons that pass.
struct FailingDistiller;

impl SessionActorDistiller for FailingDistiller {
    fn distill(&self, _brief: &SessionDistillBrief) -> Result<Vec<ActorNote>> {
        Err(Error::InvariantViolation("distiller tier unavailable"))
    }
}

/// Plants a SECOND Active head with `head`'s exact shape under a fresh id —
/// the state two replicas reach when each observed the same fact locally and
/// then synced (`EntityId::now()` is per-replica unique).
fn plant_replica_head(vault: &Vault, head: &ClaimBody, at: u64) -> Result<EntityId> {
    let id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        vault.put_reserved_claim_in_txn(wtxn, &id, head, t(at), at)?;
        Ok(id)
    })
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
        &task_evidence(&vault, 30),
    )?;
    // Same meaning, different spacing: one standing fact, not two.
    let repeat = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "  cite   the receipt  ".to_owned(),
        },
        &task_evidence(&vault, 31),
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
        &task_evidence(&vault, 32),
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

/// A SET write is a convergence point, not just a dedupe: two Active heads
/// carrying the same note is a post-sync FORK, and returning the first one
/// found leaves the other standing forever.
#[test]
fn a_duplicate_head_fork_collapses_on_the_next_write() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let note = "name the file you changed";

    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: note.to_owned(),
        },
        &task_evidence(&vault, 30),
    )?;
    let (active, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    let [head] = active.as_slice() else {
        panic!("one head after the first write");
    };
    plant_replica_head(&vault, head, 31)?;
    let (forked, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(forked.len(), 2, "the fixture reproduces the post-sync fork");

    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: note.to_owned(),
        },
        &task_evidence(&vault, 32),
    )?;
    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(active.len(), 1, "the fork collapses to ONE standing note");
    assert_eq!(superseded.len(), 2, "EVERY duplicate head is closed");
    Ok(())
}

/// Cross-inlet reconciliation: the same standing note observed from both lanes
/// rests, in part, on model-written prose. The row must say so — a dedupe that
/// re-returns the receipt-grounded head keeps the flattering half of a lineage
/// the ledger no longer has.
#[test]
fn a_note_reobserved_from_the_other_lane_folds_the_meet_down() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let note = "restate the ask before answering";

    let receipt_grounded = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: note.to_owned(),
        },
        &task_evidence(&vault, 40),
    )?;
    let distilled = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: note.to_owned(),
        },
        &chat_evidence(&vault, 41),
    )?;
    assert_ne!(
        receipt_grounded, distilled,
        "a lineage the row no longer earns is a new row, not a no-op"
    );

    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(active.len(), 1, "still ONE standing note (SET)");
    assert_eq!(superseded.len(), 1, "the tool-output head is closed");
    assert_eq!(
        actor_claim_lineage(&active[0]),
        Some(ClaimSource::Generated),
        "the meet folds DOWN: partly prose-derived is prose-derived"
    );

    // …and the other direction is the laundering one: re-observing a distilled
    // note from the TASK lane must not restamp it `tool_output`, which would
    // walk a model-written note UP the lattice on the strength of a receipt
    // that says nothing about its words. The head already carries the meet, so
    // this is a no-op — a re-observation that cannot improve the lineage does
    // not rewrite the row.
    let standing = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: note.to_owned(),
        },
        &task_evidence(&vault, 42),
    )?;
    assert_eq!(standing, distilled, "the standing prose-derived row stands");
    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(active.len(), 1);
    assert_eq!(superseded.len(), 1, "no second supersession");
    assert_eq!(
        actor_claim_lineage(&active[0]),
        Some(ClaimSource::Generated),
        "a receipt beside the prose does not launder the prose"
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
            &task_evidence(&vault, at),
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

/// A supersession closes a head with an EARLIER event time, never a later one:
/// a backfill landing at 50 must not retire the estimate the ledger already
/// holds at 100 and leave the stale fit sole-active.
#[test]
fn a_backfilled_fit_never_closes_a_later_head() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "sk06.fit.backfill")?;

    write_actor_claim(
        &vault,
        ActorClaimRow::SkillFit {
            actor,
            skill,
            fit: 0.75,
        },
        &task_evidence(&vault, 100),
    )?;
    write_actor_claim(
        &vault,
        ActorClaimRow::SkillFit {
            actor,
            skill,
            fit: 0.25,
        },
        &task_evidence(&vault, 50),
    )?;

    let (active, superseded) = rows(&vault, &actor, PREDICATE_ACTOR_SKILL_FIT)?;
    assert!(
        superseded.is_empty(),
        "the later head is not the backfill's to close"
    );
    assert_eq!(
        active.len(),
        2,
        "both observations stand on their own times"
    );
    assert_eq!(
        skill_fit_for(&vault, &actor, &skill)?,
        Some(0.75),
        "the read still resolves to the NEWEST estimate, not the backfill"
    );
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
            &task_evidence(&vault, 50),
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
        &task_evidence(&vault, 60),
    )
    .expect_err("a blank note is refused");
    assert!(matches!(blank, Error::InvalidClaimBody(_)));

    let missing = write_actor_claim(
        &vault,
        ActorClaimRow::FailureMode {
            actor: EntityId::now(),
            text: "skips verification".to_owned(),
        },
        &task_evidence(&vault, 61),
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

/// Constructible is not grounded: `ActorClaimEvidence` is built from
/// caller-owned strings and ids, so the door RESOLVES every citation before it
/// authors reserved truth (the ONE-1738 loss-door posture).
#[test]
fn a_row_citing_evidence_that_resolves_to_nothing_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let lesson = |text: &str| ActorClaimRow::Lesson {
        actor,
        text: text.to_owned(),
    };

    let unstamped = write_actor_claim(
        &vault,
        lesson("rests on a receipt nobody stamped"),
        &ActorClaimEvidence::task(vec!["receipt:sk06".to_owned()], 70)?,
    )
    .expect_err("a hand-written receipt id is a trace only in shape");
    assert!(matches!(unstamped, Error::InvalidClaimBody(_)));

    // One real receipt does not launder the fabricated one beside it.
    let real = stamped_pack_receipt(&vault, "sk06.grounding")?;
    let mixed = write_actor_claim(
        &vault,
        lesson("cites one real receipt and one invented"),
        &ActorClaimEvidence::task(vec![real, "receipt:sk06".to_owned()], 71)?,
    )
    .expect_err("EVERY citation resolves, not the first");
    assert!(matches!(mixed, Error::InvalidClaimBody(_)));

    let session = witnessed_chat_session(&vault, 1, 72)?;
    let phantom_turn = write_actor_claim(
        &vault,
        lesson("cites a turn this vault never held"),
        &ActorClaimEvidence::chat(session, vec![EntityId::now()], 73)?,
    )
    .expect_err("a citation naming no stored turn is refused");
    assert!(matches!(phantom_turn, Error::InvalidClaimBody(_)));

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert!(lessons.is_empty(), "ungrounded rows write nothing");
    Ok(())
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
        &task_evidence(&vault, 90),
    )?;
    write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "from the chat lane".to_owned(),
        },
        &chat_evidence(&vault, 91),
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

    // A well-formed row: evidence present, lineage stamped where the trust
    // lattice reads it. Each case below breaks exactly one thing about it.
    let stamped = |meet: ClaimSource| {
        let mut body = bare.clone();
        body.evidence = Some(Value::Map(vec![(Value::from(KEY_AT), Value::from(1_u64))]));
        body.source = Some(ClaimSource::Observed);
        body.scope = Some(scope_with_lineage(None, meet));
        body
    };
    assert!(validate_actor_claim_structure(&stamped(ClaimSource::Generated)).is_ok());

    let mut no_evidence = stamped(ClaimSource::Generated);
    no_evidence.evidence = None;
    assert!(
        validate_actor_claim_structure(&no_evidence).is_err(),
        "a lineage stamp is not a trace: the row must still cite one"
    );

    let mut no_lineage = stamped(ClaimSource::Generated);
    no_lineage.scope = None;
    assert!(
        validate_actor_claim_structure(&no_lineage).is_err(),
        "a row with no legible lineage cannot launder its trail"
    );

    let mut foreign_lineage = stamped(ClaimSource::Generated);
    foreign_lineage.scope = Some(Value::Map(vec![(
        Value::from(ACTOR_CLAIM_LINEAGE_KEY),
        Value::from(ClaimSource::Imported.as_str()),
    )]));
    assert!(
        validate_actor_claim_structure(&foreign_lineage).is_err(),
        "only the two lanes' meets are legible; this ledger mints no other"
    );

    let mut extra_scope = stamped(ClaimSource::Generated);
    extra_scope.scope = Some(Value::Map(vec![
        (
            Value::from(ACTOR_CLAIM_LINEAGE_KEY),
            Value::from(ClaimSource::Generated.as_str()),
        ),
        (Value::from("sensitivity"), Value::from(0_u64)),
    ]));
    assert!(
        validate_actor_claim_structure(&extra_scope).is_err(),
        "the scope map is the writer's, key for key"
    );

    let mut imported = stamped(ClaimSource::ToolOutput);
    imported.source = Some(ClaimSource::Imported);
    assert!(
        validate_actor_claim_structure(&imported).is_err(),
        "a federation-restamped foreign row never enters this routing signal"
    );

    let mut proposed = stamped(ClaimSource::Generated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    assert!(validate_actor_claim_structure(&proposed).is_err());

    let mut unnormalized = stamped(ClaimSource::Generated);
    unnormalized.value = Value::from("  padded  ");
    assert!(validate_actor_claim_structure(&unnormalized).is_err());
}

/// The lineage is only worth stamping if the TRUST CODE can read it: the
/// evidence-taint reader is what blocks a receipt-derived row from
/// consolidating without a human re-stamp, and a bespoke evidence-map key —
/// which is where this lineage used to ride — is a label nothing enforces.
#[test]
fn the_lineage_meet_is_the_taint_the_trust_lattice_reads() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    write_actor_claim(
        &vault,
        ActorClaimRow::FailureMode {
            actor,
            text: "departs from the loaded pack".to_owned(),
        },
        &task_evidence(&vault, 92),
    )?;
    let (active, _) = rows(&vault, &actor, PREDICATE_ACTOR_FAILURE_MODE)?;
    let [row] = active.as_slice() else {
        panic!("one failure-mode row");
    };
    assert_eq!(
        crate::claim::claim_evidence_taint(row),
        Some(ClaimSource::ToolOutput),
        "the meet rides the channel `claim_evidence_taint` reads"
    );
    assert!(
        !crate::claim::claim_consolidatable(row),
        "a tool-output-derived row does not consolidate on its own say-so"
    );
    Ok(())
}

// ─── TASK lane ──────────────────────────────────────────────────────────

#[test]
fn a_lapse_judgment_projects_one_failure_mode_row_and_no_lesson() -> Result<()> {
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
    assert_eq!(written.len(), 1, "one lapse is one failure-mode row");

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    let (failure_modes, _) = rows(&vault, &actor, PREDICATE_ACTOR_FAILURE_MODE)?;
    assert!(
        lessons.is_empty(),
        "a routing boolean cannot source a craft note; the lesson is the distiller's"
    );
    assert_eq!(failure_modes.len(), 1);
    assert_eq!(failure_modes[0].value, Value::from(LAPSE_FAILURE_MODE));
    assert_eq!(
        actor_claim_lineage(&failure_modes[0]),
        Some(ClaimSource::ToolOutput),
        "a receipt-derived row says so; it is not a blanket Generated restamp"
    );
    assert_eq!(
        failure_modes[0].evidence.as_ref().and_then(|value| value
            .as_map()?
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_RECEIPTS))
            .map(|(_, receipts)| receipts.clone())),
        Some(Value::Array(vec![Value::from(receipt.as_str())])),
        "the row cites the attempt receipt it rests on"
    );

    // A second pass over the same judgments folds into the same row.
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

    let (failure_modes, _) = rows(&vault, &actor, PREDICATE_ACTOR_FAILURE_MODE)?;
    assert!(failure_modes.is_empty(), "ungrounded rows write nothing");
    Ok(())
}

// ─── CHAT lane ──────────────────────────────────────────────────────────

/// Opens a sitting, witnesses `turn_count` turns THROUGH THE PRODUCTION WITNESS
/// DOOR, ends it through the wake, and returns the session id.
///
/// The witness door is the point: it writes an empty TURN container plus MESSAGE
/// children, and no SESSION edge at all. A fixture that hand-put turns carrying
/// `spkr`/`txt` under a `ChildOf` edge into the session would be proving the
/// chat lane works on a shape nothing in production writes.
fn witnessed_chat_session(vault: &Vault, turn_count: usize, now: u64) -> Result<EntityId> {
    let speaker = put_actor(vault)?;
    let facade = vault.memory(speaker, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();
    let SessionMintOutcome::Minted(session) = vault.mint_session(now)? else {
        panic!("a fresh vault mints");
    };
    for index in 0..turn_count {
        let index = u64::try_from(index).expect("fixture turn counts are small");
        facade
            .witness(&WitnessTurn {
                conversation_ref: conversation.clone(),
                turn_ref: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "text".to_owned(),
                    content: format!("turn {index}"),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: now + index,
            })
            .expect("the witness door lands the turn");
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
    let session = witnessed_chat_session(&vault, 2, 200)?;
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

/// The job is the sitting's ONLY record that it is over and unlearned-from, so
/// a distiller tier having a bad minute must not spend it. Consume-after-success
/// or the transient failure is permanent.
#[test]
fn a_failing_distiller_leaves_the_job_standing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let session = witnessed_chat_session(&vault, 2, 500)?;

    let failed = run_session_end_actor_distill(&vault, &session, &FailingDistiller)
        .expect_err("the distiller's failure surfaces");
    assert!(matches!(failed, Error::InvariantViolation(_)));
    assert_eq!(
        pending_session_actor_distills(&vault)?,
        vec![session],
        "the sitting is still owed a distillation"
    );

    // …and the retry, on a tier that is up again, still lands.
    let distilled = run_session_end_actor_distill(
        &vault,
        &session,
        &FixedDistiller(vec![ActorNote {
            actor,
            kind: ActorNoteKind::Lesson,
            text: "the retry still learns".to_owned(),
        }]),
    )?;
    assert_eq!(distilled.len(), 1);
    assert!(pending_session_actor_distills(&vault)?.is_empty());
    Ok(())
}

/// One sitting's notes are ONE landing: a pass that dies partway leaves no
/// half-distillation behind, and the job it did not finish is still pending.
#[test]
fn a_pass_that_fails_midway_commits_no_partial_notes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let session = witnessed_chat_session(&vault, 2, 600)?;

    let landed = ActorNote {
        actor,
        kind: ActorNoteKind::Lesson,
        text: "this one is fine".to_owned(),
    };
    // Refused by the door itself, after the note before it has been staged.
    let refused = ActorNote {
        actor,
        kind: ActorNoteKind::ScopeNote,
        text: "x".repeat(ACTOR_NOTE_MAX_BYTES + 1),
    };
    let error =
        run_session_end_actor_distill(&vault, &session, &FixedDistiller(vec![landed, refused]))
            .expect_err("a note the door refuses fails the pass");
    assert!(matches!(error, Error::InvalidClaimBody(_)));

    let (lessons, _) = rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert!(lessons.is_empty(), "the staged note rolled back with it");
    assert_eq!(
        pending_session_actor_distills(&vault)?,
        vec![session],
        "an unfinished pass never spends the job"
    );
    Ok(())
}

/// The brief must be built from what the WITNESS DOOR wrote — an empty TURN
/// container whose words live in its MESSAGE children — because that is the
/// only shape the companion surface produces. Reading the turn body alone
/// yields three empty turns, which is what the chat lane used to do.
#[test]
fn the_brief_carries_the_witnessed_words_in_scan_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = witnessed_chat_session(&vault, 3, 300)?;
    // The premise, pinned: production links a turn to a sitting by TIME, and by
    // nothing else. A derivation that walked `ChildOf` edges into the SESSION
    // would find an empty sitting here — and in every real one.
    assert!(
        vault
            .edges_in(&session)?
            .iter()
            .all(|edge| edge.kind != EdgeKind::ChildOf),
        "the witness door writes no SESSION child edge"
    );
    let turns = session_turns(
        &vault,
        SittingWindow {
            started_at: 300,
            ended_at: 400,
        },
    )?;
    assert_eq!(turns.len(), 3);
    assert_eq!(turns[0].said.len(), 1, "one message, one utterance");
    assert_eq!(turns[0].said[0].speaker.as_deref(), Some("user"));
    assert_eq!(turns[0].said[0].text.as_deref(), Some("turn 0"));
    assert_eq!(turns[2].said[0].text.as_deref(), Some("turn 2"));
    Ok(())
}

#[test]
fn a_sitting_with_no_turns_distills_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let session = witnessed_chat_session(&vault, 0, 400)?;

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
