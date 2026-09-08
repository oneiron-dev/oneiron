//! Persona-core isolation: isolated classes, session floor, and replay and source rules.

use super::*;
use crate::claim::PREDICATE_COMPANION_EXPRESSION;
use crate::inbox::{InboxExceptionClass, InboxGroupMember, InboxQuery, InboxReviewDial};

const ISOLATION_RUN_ID: &str = "gate13-isolation-run";

/// A vault whose manifest grants BOTH the Dreamer's `agent` actor and the
/// human candidate actor `auto`, so a write that stops short of Auto stopped
/// for a reason of its own rather than for want of a ceiling.
fn isolation_vault() -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
    );
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x90), &data)?;
    Ok((tmp, vault))
}

fn seed_isolation_session(vault: &crate::Vault, session: &EntityId) -> Result<()> {
    vault.put_entity(
        session,
        crate::registry::ENTITY_TYPE_SESSION,
        test_time(1),
        1,
        b"isolation sitting",
    )
}

/// Seeds one TURN plus, when `session` is present, the engine-owned
/// membership fact binding it to that sitting — the same `vault_meta` row the
/// witness door records beside a turn. A turn seeded with `None` is the
/// witnessed-outside-any-sitting case, which must not count.
fn seed_isolation_turn(
    vault: &crate::Vault,
    turn: &EntityId,
    session: Option<EntityId>,
) -> Result<()> {
    vault.put_entity(
        turn,
        crate::registry::ENTITY_TYPE_TURN,
        test_time(1),
        1,
        b"isolation turn",
    )?;
    if session.is_some() {
        let mut wtxn = vault.store.env.write_txn()?;
        crate::session_lifecycle::record_turn_session_membership_in_txn(
            &vault.store,
            &mut wtxn,
            turn,
            session,
        )?;
        wtxn.commit()?;
    }
    Ok(())
}

/// One turn witnessed into its own fresh sitting: a whole cycle.
fn seed_isolation_cycle(vault: &crate::Vault, turn: &EntityId, session: &EntityId) -> Result<()> {
    seed_isolation_session(vault, session)?;
    seed_isolation_turn(vault, turn, Some(*session))
}

/// A Dreamer-authored candidate body on `predicate`, citing `refs` as its
/// candidate evidence.
fn isolation_body(predicate: &str, value: Value, refs: Vec<EntityId>) -> ClaimBody {
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.predicate = predicate.to_owned();
    body.value = value;
    body.evidence = Some(precommit_evidence(refs));
    body
}

/// The mirroring-prone witness, built through the affect module's own value
/// codec so the claim's structural validator is satisfied by construction.
fn isolation_affect_body(person: EntityId, trigger_turn: EntityId) -> Result<ClaimBody> {
    let value = crate::affect::AffectTriggerValue::new(
        person,
        trigger_turn,
        crate::affect::VadDelta::new(-0.2, 0.4, -0.3)?,
        0.75,
        2,
        9,
    )?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.predicate = crate::affect::AFFECT_TRIGGER_PREDICATE.to_owned();
    body.subject = ClaimSubject::Entity(person);
    body.confidence = value.confidence();
    body.value = crate::affect::affect_trigger_value(&value);
    body.evidence = Some(precommit_evidence(vec![trigger_turn]));
    Ok(body)
}

fn attempt_isolation_write(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        vault,
        body,
        first_party_eiri_connector_actor_id(),
        ISOLATION_RUN_ID,
    )?;
    vault
        .batch()
        .claim_candidate(claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
}

/// Asserts the raw rejection shape.
///
/// The isolation codes are gate-internal today: the public `GateDenialReason`
/// table does not carry them, so `Error::gate_denial()` declines to type this
/// rejection and the assertion reads the exact stable strings off the error.
fn assert_isolation_rejected(err: Error, outcome: &'static str, reason_codes: &[&'static str]) {
    match err {
        Error::GateWriteRejected {
            outcome: got_outcome,
            reason_codes: got_reason_codes,
        } => {
            assert_eq!(got_outcome, outcome);
            assert_eq!(got_reason_codes, reason_codes);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

fn isolation_pending_row(
    vault: &crate::Vault,
    claim_id: &EntityId,
) -> Result<PendingGateConsentRecord> {
    Ok(vault
        .pending_gate_consents(10)?
        .into_iter()
        .find(|record| record.claim_id == *claim_id.as_bytes())
        .expect("an isolated row mints a pending consent"))
}

/// The reason-code pair one isolation class stamps, spelled through the enum
/// so the row a dial reads carries the SAME criticality marker string
/// `classify_member` compares against rather than a re-literalized copy.
fn isolation_reason_codes(isolation: GateReasonCode) -> Vec<String> {
    vec![
        isolation.as_str().to_owned(),
        GateReasonCode::PendingCriticalityFloor.as_str().to_owned(),
    ]
}

fn surfaced_inbox_member(vault: &crate::Vault, claim_id: &EntityId) -> Result<InboxGroupMember> {
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    let hex = claim_id.to_hex();
    Ok(groups
        .iter()
        .flat_map(|group| group.members.iter())
        .find(|member| member.claim_id == hex)
        .expect("an isolated row surfaces as an inbox member")
        .clone())
}

fn assert_exception_class(member: &InboxGroupMember, class: InboxExceptionClass) {
    assert!(
        member.exception_classes.contains(&class),
        "{class:?} missing from {:?}",
        member.exception_classes
    );
}

/// Persona-core writes are NEVER Auto, whatever the manifest grants, and two
/// distinct sittings buy an owner-review row rather than the head itself.
#[test]
fn persona_core_isolated() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let first_turn = test_id(0xD1);
    let second_turn = test_id(0xD2);
    seed_isolation_cycle(&vault, &first_turn, &test_id(0xE2))?;
    seed_isolation_cycle(&vault, &second_turn, &test_id(0xE3))?;

    let body = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("warm"),
        vec![first_turn, second_turn],
    );

    // This actor holds an `auto` ceiling and the candidate clears every other
    // axis, so the isolation ceiling is the only thing that can refuse the
    // Auto ask — and it refuses rather than letting Auto land.
    let auto_claim = test_id(0x91);
    let err = attempt_isolation_write(&vault, &auto_claim, &body)
        .expect_err("persona-core is never Auto");
    assert_isolation_rejected(
        err,
        "pending",
        &[
            "gate.pending.persona_isolation",
            "gate.pending.criticality_floor",
        ],
    );
    assert!(vault.get_raw(&auto_claim)?.is_none());
    assert!(!has_pending_gate_consent(&vault, &auto_claim)?);

    // The same candidate asked as Proposed lands as an owner-review row.
    let proposed_claim = test_id(0x92);
    let mut proposed = body;
    proposed.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &proposed_claim, &proposed)?;

    let stored = stored_claim_body(&vault, &proposed_claim)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_ne!(
        stored.approval,
        ClaimApprovalStatus::Auto,
        "an isolated persona-core row is never Auto"
    );

    let pending = isolation_pending_row(&vault, &proposed_claim)?;
    assert_eq!(
        pending.reason_codes,
        isolation_reason_codes(GateReasonCode::PendingPersonaIsolation)
    );
    assert_eq!(pending.dreamer_run_id.as_deref(), Some(ISOLATION_RUN_ID));
    Ok(())
}

/// One cycle is not a transformation. A persona-core write whose evidence
/// reaches a single sitting is DENIED rather than parked; a mirroring-prone
/// write, which carries no multi-cycle floor, parks on the same evidence.
#[test]
fn casual_edit_to_isolated_class_escalated() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let turn = test_id(0xD1);
    seed_isolation_cycle(&vault, &turn, &test_id(0xE2))?;

    let single_cycle = test_id(0x93);
    let mut body = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("unrestricted"),
        vec![turn],
    );
    body.approval = ClaimApprovalStatus::Proposed;
    let err = attempt_isolation_write(&vault, &single_cycle, &body)
        .expect_err("one sitting cannot move a persona head");
    assert_isolation_rejected(
        err,
        "deny",
        &["gate.deny.dreamer_precommit.persona_single_cycle"],
    );
    assert!(vault.get_raw(&single_cycle)?.is_none());
    assert!(
        !has_pending_gate_consent(&vault, &single_cycle)?,
        "a deny mints no owner-review row"
    );

    let mirroring_claim = test_id(0x94);
    let mut mirroring = isolation_affect_body(test_id(0xBA), turn)?;
    mirroring.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &mirroring_claim, &mirroring)?;

    assert_eq!(
        stored_claim_body(&vault, &mirroring_claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        isolation_pending_row(&vault, &mirroring_claim)?.reason_codes,
        isolation_reason_codes(GateReasonCode::PendingMirroringIsolation)
    );
    Ok(())
}

/// Isolation is scoped to the agent path. The owner writing the same
/// persona-core predicate, with no multi-sitting evidence at all, keeps the
/// pre-existing gate behaviour.
#[test]
fn owner_writes_unrestricted() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let claim_id = test_id(0x95);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = PREDICATE_COMPANION_EXPRESSION.to_owned();
    body.value = Value::from("professional");
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::UserStated));
    assert!(
        !has_pending_gate_consent(&vault, &claim_id)?,
        "an owner write is not parked for owner review"
    );
    Ok(())
}

/// Both classes ride the EXISTING criticality marker, so the inbox
/// projection — untouched by this change — classifies them manifest-critical
/// and no dial position can waive them.
#[test]
fn isolated_rows_surface_as_manifest_critical() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let first_turn = test_id(0xD1);
    let second_turn = test_id(0xD2);
    seed_isolation_cycle(&vault, &first_turn, &test_id(0xE2))?;
    seed_isolation_cycle(&vault, &second_turn, &test_id(0xE3))?;

    let persona_claim = test_id(0x96);
    let mut persona = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("warm"),
        vec![first_turn, second_turn],
    );
    persona.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &persona_claim, &persona)?;

    let mirroring_claim = test_id(0x97);
    let mut mirroring = isolation_affect_body(test_id(0xBA), first_turn)?;
    mirroring.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &mirroring_claim, &mirroring)?;

    for dial in [
        InboxReviewDial::ApproveAll,
        InboxReviewDial::ExceptionsOnly,
        InboxReviewDial::ReviewEverything,
    ] {
        vault.set_inbox_review_dial(dial)?;
        let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
        let held: usize = groups.iter().map(|group| group.held_member_count).sum();
        assert_eq!(held, 0, "{dial:?} must hold back no isolated row");

        for claim_id in [persona_claim, mirroring_claim] {
            let member = surfaced_inbox_member(&vault, &claim_id)?;
            assert_exception_class(&member, InboxExceptionClass::ManifestCritical);
        }
    }
    Ok(())
}

/// The floor counts SITTINGS, and only the ones the engine can prove. Every
/// case here cites two refs of which at most one resolves to a distinct
/// sitting; the control at the end lands the same shape once the second
/// sitting is real.
#[test]
fn persona_core_session_floor_counts_only_provable_sittings() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let good_turn = test_id(0xD1);
    seed_isolation_cycle(&vault, &good_turn, &test_id(0xE2))?;

    // Never seeded at all.
    let absent_ref = test_id(0xD3);
    // Resolves, but not to a TURN.
    let not_a_turn = test_id(0xD4);
    vault.put_entity(
        &not_a_turn,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"not a turn",
    )?;
    // A TURN carrying no recorded sitting at all.
    let unbound_turn = test_id(0xD5);
    seed_isolation_turn(&vault, &unbound_turn, None)?;
    // A TURN whose recorded sitting is not a SESSION entity.
    let mistyped_turn = test_id(0xD6);
    let mistyped_session = test_id(0xE4);
    vault.put_entity(
        &mistyped_session,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"not a sitting",
    )?;
    seed_isolation_turn(&vault, &mistyped_turn, Some(mistyped_session))?;
    // A TURN bound to a sitting that was never written.
    let dangling_turn = test_id(0xD8);
    seed_isolation_turn(&vault, &dangling_turn, Some(test_id(0xE5)))?;
    // A second turn inside the SAME sitting: one cycle, cited twice.
    let same_sitting_turn = test_id(0xD9);
    seed_isolation_turn(&vault, &same_sitting_turn, Some(test_id(0xE2)))?;

    for (seed, refs) in [
        (0x98_u8, vec![good_turn, absent_ref]),
        (0x99, vec![good_turn, not_a_turn]),
        (0x9A, vec![good_turn, unbound_turn]),
        (0x9B, vec![good_turn, mistyped_turn]),
        (0x9C, vec![good_turn, dangling_turn]),
        (0x9D, vec![good_turn, same_sitting_turn]),
    ] {
        let claim_id = test_id(seed);
        let mut body = isolation_body(PREDICATE_COMPANION_EXPRESSION, Value::from("warm"), refs);
        body.approval = ClaimApprovalStatus::Proposed;
        let err = attempt_isolation_write(&vault, &claim_id, &body)
            .expect_err("unprovable evidence cannot buy a second sitting");
        assert_isolation_rejected(
            err,
            "deny",
            &["gate.deny.dreamer_precommit.persona_single_cycle"],
        );
        assert!(vault.get_raw(&claim_id)?.is_none(), "{seed:#04x}");
    }

    // A malformed ref inside an otherwise well-formed envelope is refused by
    // the GATE-12 validity floor FIRST: isolation never replaces a stricter
    // denial with one of its own.
    let mut malformed = precommit_evidence(vec![good_turn]);
    if let Value::Map(entries) = &mut malformed {
        for (key, value) in entries {
            if key.as_str() == Some(PRECOMMIT_EVIDENCE_REFS_KEY) {
                *value = Value::Array(vec![Value::Binary(vec![0x01, 0x02, 0x03, 0x04])]);
            }
        }
    }
    let malformed_claim = test_id(0x9E);
    let mut malformed_body = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("warm"),
        Vec::new(),
    );
    malformed_body.evidence = Some(malformed);
    malformed_body.approval = ClaimApprovalStatus::Proposed;
    let err = attempt_isolation_write(&vault, &malformed_claim, &malformed_body)
        .expect_err("a malformed evidence envelope is no evidence at all");
    assert_isolation_rejected(err, "deny", &["gate.deny.dreamer_precommit.no_evidence"]);

    // The control: a real second sitting, and the same write parks instead.
    let second_turn = test_id(0xDA);
    seed_isolation_cycle(&vault, &second_turn, &test_id(0xE6))?;
    let landed = test_id(0x9F);
    let mut body = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("warm"),
        vec![good_turn, second_turn],
    );
    body.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &landed, &body)?;
    assert_eq!(
        stored_claim_body(&vault, &landed)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        isolation_pending_row(&vault, &landed)?.reason_codes,
        isolation_reason_codes(GateReasonCode::PendingPersonaIsolation)
    );
    Ok(())
}

/// Replicated replay stays trust-blind: an isolated predicate arriving over
/// replication rematerializes exactly as sent, without an isolation verdict,
/// a demotion or an owner-review row.
#[test]
fn replay_untouched() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let claim_id = test_id(0x91);
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.predicate = PREDICATE_COMPANION_EXPRESSION.to_owned();
    body.value = Value::from("warm");
    let data = crate::claim::encode_claim_body(&body)?;

    vault
        .batch()
        .put_replicated(
            &claim_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(
        stored.approval,
        ClaimApprovalStatus::Auto,
        "replay is not re-gated"
    );
    assert!(!has_pending_gate_consent(&vault, &claim_id)?);
    Ok(())
}

/// An isolated row is a PROPOSAL. It leaves the owner's own head on the same
/// predicate exactly as it was, and surfaces as superseding user-stated truth
/// so the dial cannot approve it away unseen either.
#[test]
fn generated_cannot_retire_user_stated() -> Result<()> {
    let (_tmp, vault) = isolation_vault()?;
    let owner_claim = test_id(0x95);
    let mut owner = source_trust_claim(ClaimSource::UserStated);
    owner.predicate = PREDICATE_COMPANION_EXPRESSION.to_owned();
    owner.value = Value::from("professional");
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &owner)?;
    vault
        .batch()
        .claim_candidate(&owner_claim, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let first_turn = test_id(0xD1);
    let second_turn = test_id(0xD2);
    seed_isolation_cycle(&vault, &first_turn, &test_id(0xE2))?;
    seed_isolation_cycle(&vault, &second_turn, &test_id(0xE3))?;

    let dreamer_claim = test_id(0x96);
    let mut dreamer = isolation_body(
        PREDICATE_COMPANION_EXPRESSION,
        Value::from("warm"),
        vec![first_turn, second_turn],
    );
    dreamer.approval = ClaimApprovalStatus::Proposed;
    attempt_isolation_write(&vault, &dreamer_claim, &dreamer)?;

    let head = stored_claim_body(&vault, &owner_claim)?;
    assert_eq!(head.approval, ClaimApprovalStatus::Auto);
    assert_eq!(head.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(head.source, Some(ClaimSource::UserStated));
    assert_eq!(
        head.value,
        Value::from("professional"),
        "a proposal cannot retire user-stated truth"
    );

    vault.set_inbox_review_dial(InboxReviewDial::ApproveAll)?;
    let member = surfaced_inbox_member(&vault, &dreamer_claim)?;
    assert_exception_class(&member, InboxExceptionClass::SupersedesUserStated);
    assert_exception_class(&member, InboxExceptionClass::ManifestCritical);
    Ok(())
}
