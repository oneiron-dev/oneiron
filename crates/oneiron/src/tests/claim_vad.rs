//! Claim-VAD consolidation/reappraisal, coping-outcome claims, claim_vad_now (flattens inline mod).

use super::*;
use crate::error::ClaimError;

#[test]
fn claim_vad_reappraisal_preserves_provenance_and_supersession() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        },
    )?;
    let body = claim_vad_fixture_body(subject, &[turn]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;

    let first = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    let old_state_id = first
        .reappraisal
        .created_claim_id
        .expect("initial state claim");
    let old_before = vault
        .get_claim(&old_state_id)?
        .expect("initial state remains readable");

    vault.annotate_turn_vad(
        &turn,
        VadAnnotation::new(
            Vad {
                valence: 0.7,
                arousal: 0.6,
                dominance: 0.5,
            },
            VadAnnotationSource::UserSelfReport,
            150,
        )?,
    )?;
    let second = block_on_ready(vault.consolidate_claim_vad(&claim, 200))?;
    let new_state_id = second
        .reappraisal
        .created_claim_id
        .expect("changed evidence creates a reappraisal");
    assert_eq!(second.reappraisal.superseded_claim_ids, vec![old_state_id]);
    assert_ne!(new_state_id, old_state_id);

    let old_after = vault
        .get_claim(&old_state_id)?
        .expect("superseded state stays readable");
    assert_eq!(old_after.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_after.valid_to, Some(200));
    assert_eq!(entity_header(&vault, &old_state_id)?.occurred_end, 200);
    assert_eq!(old_after.source, old_before.source);
    assert_eq!(old_after.evidence, old_before.evidence);

    let new_state = vault
        .get_claim(&new_state_id)?
        .expect("new state claim readable");
    assert_eq!(new_state.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(new_state.source, Some(ClaimSource::Inferred));
    assert!(new_state.evidence.is_some());
    assert_eq!(entity_header(&vault, &new_state_id)?.occurred_end, u64::MAX);

    let supersedes = EdgeRef::new(new_state_id, EdgeKind::Supersedes, old_state_id);
    let (out, inn) = raw_edge_values(&vault, &supersedes)?;
    let out = out.expect("supersedes edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        decode_edge_value_for_kind(EdgeKind::Supersedes, &out)?.vad,
        None
    );

    let expected = Vad {
        valence: 0.7,
        arousal: 0.6,
        dominance: 0.5,
    };
    let mentions = vault
        .edges_out(&claim)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic edge survives");
    assert_vad_close(mentions.vad.expect("updated VAD"), expected);
    Ok(())
}

#[test]
fn claim_vad_consolidation_rejects_stale_active_claim_with_specific_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.2,
            arousal: 0.4,
            dominance: 0.6,
        },
    )?;

    let mut body = claim_vad_fixture_body(subject, &[turn]);
    body.stale = true;
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;

    let err = block_on_ready(vault.consolidate_claim_vad(&claim, 100))
        .expect_err("stale Active claims are not consolidatable");
    assert_matches!(err, Error::InvalidClaimBody(_));
    Ok(())
}

#[test]
fn claim_vad_consolidation_rejects_missing_and_closed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let missing = EntityId::now();
    let err = block_on_ready(vault.consolidate_claim_vad(&missing, 10))
        .expect_err("missing claim must fail");
    assert_matches!(err, Error::EntityNotFound);

    let subject = EntityId::now();
    let claim = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let body = claim_vad_fixture_body(subject, &[]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.retract_claim(&claim, 40)?;

    let err = block_on_ready(vault.consolidate_claim_vad(&claim, 50))
        .expect_err("closed claim must fail");
    assert_matches!(
        err,
        Error::Claim(ClaimError::ClaimAlreadyClosed {
            status: ClaimLifecycleStatus::Retracted
        })
    );
    Ok(())
}

#[test]
fn claim_vad_reappraisal_clears_state_when_turn_evidence_disappears() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.6,
            arousal: 0.4,
            dominance: 0.8,
        },
    )?;
    let body = claim_vad_fixture_body(subject, &[turn]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;

    let first = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    assert!(first.vad.is_some());
    let old_state_id = first
        .reappraisal
        .created_claim_id
        .expect("initial state claim");
    let old_before = vault
        .get_claim(&old_state_id)?
        .expect("initial state remains readable");

    vault.batch().delete(&turn).commit()?;
    assert_eq!(vault.get_turn_vad_annotation(&turn)?, None);

    let second = block_on_ready(vault.consolidate_claim_vad(&claim, 200))?;
    assert_eq!(second.vad, None);
    assert!(second.evidence_turns.is_empty());
    assert_eq!(second.semantic_edges_updated, 1);
    assert_eq!(second.reappraisal.active_claim_id, None);
    assert_eq!(second.reappraisal.created_claim_id, None);
    assert_eq!(second.reappraisal.superseded_claim_ids, vec![old_state_id]);

    let old_after = vault
        .get_claim(&old_state_id)?
        .expect("superseded state stays readable");
    assert_eq!(old_after.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_after.valid_to, Some(200));
    assert_eq!(old_after.source, old_before.source);
    assert_eq!(old_after.evidence, old_before.evidence);

    let mentions = vault
        .edges_out(&claim)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic edge survives");
    assert_vad_close(mentions.vad.expect("cleared VAD"), Vad::NEUTRAL);

    let mut active_claim_vad_states = Vec::new();
    for state_id in vault.claims_for_subject(&claim)? {
        let Some(state) = vault.get_claim(&state_id)? else {
            continue;
        };
        if state.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
            && state.lifecycle == ClaimLifecycleStatus::Active
        {
            active_claim_vad_states.push(state_id);
        }
    }
    assert!(
        active_claim_vad_states.is_empty(),
        "removed evidence must not leave an active claim-VAD state"
    );
    Ok(())
}

#[test]
fn coping_outcome_claim_validation_requires_bitemporal_confidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let strategy_ref = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;

    let value = CopingOutcomeValue::new(
        person,
        strategy_ref,
        CopingStrategy::SitSel,
        VadDelta::new(0.2, -0.1, 0.1)?,
        0.7,
        1,
    )?;
    let missing_valid_time = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(person),
        coping_outcome_value(&value),
        value.confidence(),
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    let err = vault
        .put_claim(
            &outcome,
            &missing_valid_time,
            test_time_range(10, u64::MAX),
            10,
        )
        .expect_err("coping outcomes must carry valid_from");
    assert_matches!(err, Error::InvalidClaimBody(_));

    let mut mismatched_confidence = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(person),
        coping_outcome_value(&value),
        0.6,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    mismatched_confidence.valid_from = Some(10);
    let err = vault
        .put_claim(
            &outcome,
            &mismatched_confidence,
            test_time_range(10, u64::MAX),
            10,
        )
        .expect_err("wrapper confidence must mirror the value");
    assert_matches!(err, Error::InvalidClaimBody(_));
    Ok(())
}

#[test]
fn coping_outcome_update_from_later_turn_vad_delta_supersedes_previous_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let baseline_turn = EntityId::now();
    let later_turn = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    put_claim_vad_turn(
        &vault,
        &baseline_turn,
        10,
        Vad {
            valence: -0.5,
            arousal: 0.9,
            dominance: 0.2,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &later_turn,
        20,
        Vad {
            valence: 0.3,
            arousal: 0.4,
            dominance: 0.7,
        },
    )?;

    let body = coping_outcome_fixture_body(
        person,
        baseline_turn,
        CopingStrategy::CogChg,
        VadDelta::new(-0.2, 0.2, -0.1)?,
        0.4,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let update = vault.update_coping_outcome_from_turn_vad(
        &outcome,
        &baseline_turn,
        &later_turn,
        0.8,
        200,
    )?;

    assert_eq!(update.prior_claim_id, outcome);
    assert_eq!(update.superseded_claim_ids, vec![outcome]);
    assert_ne!(update.active_claim_id, outcome);
    assert_eq!(update.value.strategy(), CopingStrategy::CogChg);
    assert!(update.value.successful());
    assert_eq!(update.value.observed_n(), 2);
    assert_f32_close(update.value.vad_delta().valence(), 0.3);
    assert_f32_close(update.value.vad_delta().arousal(), -0.15);
    assert_f32_close(update.value.vad_delta().dominance(), 0.2);
    assert_f32_close(update.value.confidence(), 0.6);

    let old = vault
        .get_claim(&outcome)?
        .expect("superseded outcome remains readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old.valid_to, Some(200));
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, 200);

    let active = vault
        .get_claim(&update.active_claim_id)?
        .expect("updated outcome claim");
    assert_eq!(active.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(active.valid_from, Some(200));
    assert_eq!(
        active.confidence.to_bits(),
        update.value.confidence().to_bits()
    );
    assert!(active.evidence.is_some());
    assert_eq!(
        decode_coping_outcome_claim(&active)?.expect("typed outcome"),
        update.value
    );
    assert!(vault.edge_exists(&update.active_claim_id, EdgeKind::ClaimOf, &person)?);
    assert!(vault.edge_exists(&update.active_claim_id, EdgeKind::Supersedes, &outcome)?);
    Ok(())
}

#[test]
fn coping_outcome_update_rejects_auto_generated_prior_claim_until_vetted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let strategy_ref = EntityId::now();
    let later_turn = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(&person, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, b"p")?;
    let mut body = public_stamped(coping_outcome_fixture_body(
        person,
        strategy_ref,
        CopingStrategy::SitSel,
        VadDelta::new(0.1, 0.1, 0.1)?,
        0.6,
        ClaimLifecycleStatus::Active,
        50,
    )?);
    body.source = Some(ClaimSource::Generated);
    seed_generated_auto_source_trust_manifest(&vault)?;
    vault.put_claim(&outcome, &body, test_time_range(50, 50), 50)?;

    let err = vault
        .update_coping_outcome_from_turn_vad_delta(
            &outcome,
            later_turn,
            VadDelta::new(0.3, 0.2, 0.1)?,
            0.8,
            100,
        )
        .expect_err("Auto/Generated coping outcome must not consolidate until vetted");
    assert_matches!(err, Error::InvalidClaimBody(_));

    let prior = vault
        .get_claim(&outcome)?
        .expect("rejected update must leave prior claim readable");
    assert_eq!(prior.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(vault.claims_for_subject(&person)?.len(), 1);
    Ok(())
}

#[test]
fn coping_outcome_update_rejects_backfilled_supersession_timestamp() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let strategy_ref = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    let body = coping_outcome_fixture_body(
        person,
        strategy_ref,
        CopingStrategy::CogChg,
        VadDelta::new(0.2, -0.1, 0.1)?,
        0.7,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let err = vault
        .update_coping_outcome_from_turn_vad_delta(
            &outcome,
            strategy_ref,
            VadDelta::new(0.1, -0.1, 0.1)?,
            0.8,
            40,
        )
        .expect_err("backfilled supersession must not invert the active interval");
    assert_matches!(err, Error::InvalidClaimBody(_));

    let old = vault
        .get_claim(&outcome)?
        .expect("rejected update leaves prior outcome readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(old.valid_to, None);
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, u64::MAX);
    let claims = vault.claims_for_subject(&person)?;
    assert_eq!(claims, vec![outcome]);
    Ok(())
}

#[test]
fn coping_outcome_update_rejects_unrelated_baseline_turn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let baseline_turn = EntityId::now();
    let wrong_baseline_turn = EntityId::now();
    let later_turn = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    put_claim_vad_turn(
        &vault,
        &baseline_turn,
        10,
        Vad {
            valence: -0.5,
            arousal: 0.8,
            dominance: 0.1,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &wrong_baseline_turn,
        11,
        Vad {
            valence: 0.5,
            arousal: 0.1,
            dominance: 0.9,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &later_turn,
        20,
        Vad {
            valence: 0.3,
            arousal: 0.4,
            dominance: 0.7,
        },
    )?;

    let body = coping_outcome_fixture_body(
        person,
        baseline_turn,
        CopingStrategy::CogChg,
        VadDelta::new(-0.2, 0.2, -0.1)?,
        0.4,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let err = vault
        .update_coping_outcome_from_turn_vad(&outcome, &wrong_baseline_turn, &later_turn, 0.8, 200)
        .expect_err("unrelated baseline turn must not update the outcome ledger");
    assert_matches!(err, Error::InvalidClaimBody(_));

    let old = vault
        .get_claim(&outcome)?
        .expect("rejected update leaves prior outcome readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(old.valid_to, None);
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, u64::MAX);
    let claims = vault.claims_for_subject(&person)?;
    assert_eq!(claims, vec![outcome]);
    Ok(())
}

#[cfg(test)]
mod claim_vad_now_tests {
    use super::*;

    fn approved_fixture(vault: &Vault) -> Result<(EntityId, EntityId, Vad)> {
        let subject = EntityId::now();
        let claim = EntityId::now();
        let turns = [EntityId::now(), EntityId::now()];
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"subject",
        )?;
        for (turn, vad) in turns.iter().zip([
            Vad {
                valence: -0.5,
                arousal: 0.25,
                dominance: 0.5,
            },
            Vad {
                valence: 0.0,
                arousal: 0.75,
                dominance: 1.0,
            },
        ]) {
            put_claim_vad_turn(vault, turn, 10, vad)?;
        }
        let mut body = public_stamped(claim_vad_fixture_body(subject, &turns));
        body.approval = ClaimApprovalStatus::Approved;
        body.source = Some(ClaimSource::Generated);
        vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
        vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;
        vault.put_edge(&subject, EdgeKind::Supports, &claim, 1.0)?;
        vault.put_edge(&claim, EdgeKind::BelongsTo, &subject, 1.0)?;
        Ok((
            claim,
            subject,
            Vad {
                valence: -0.25,
                arousal: 0.5,
                dominance: 0.75,
            },
        ))
    }

    #[test]
    fn claim_vad_now_approved_full_mean_structural_skip_and_canonical_retry() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let (claim, subject, expected) = approved_fixture(&vault)?;
        let structural = EdgeRef::new(claim, EdgeKind::BelongsTo, subject);
        let before = raw_edge_values(&vault, &structural)?;
        let first = vault.consolidate_claim_vad_now(&claim, 100)?;
        assert_eq!(first.vad, Some(expected));
        assert_eq!(first.evidence_turns.len(), 2);
        assert_eq!(first.semantic_edges_updated, 2);
        assert!(first.structural_edges_skipped >= 2);
        assert_eq!(raw_edge_values(&vault, &structural)?, before);
        for edge in vault
            .edges_out(&claim)?
            .into_iter()
            .chain(vault.edges_in(&claim)?)
        {
            if matches!(edge.kind, EdgeKind::Mentions | EdgeKind::Supports) {
                assert_eq!(edge.vad, Some(expected));
            }
        }
        let state = first.reappraisal.created_claim_id.expect("created state");
        let body = vault.get_claim(&state)?.expect("audit state");
        assert_eq!(body.source, Some(ClaimSource::Inferred));
        assert_eq!(body.predicate, CLAIM_VAD_REAPPRAISAL_PREDICATE);
        assert!(body.evidence.is_some());
        let sync_retry = vault.consolidate_claim_vad_now(&claim, 110)?;
        let async_retry = block_on_ready(vault.consolidate_claim_vad(&claim, 110))?;
        assert_eq!(sync_retry, async_retry);
        assert_eq!(sync_retry.reappraisal.active_claim_id, Some(state));
        assert_eq!(sync_retry.reappraisal.created_claim_id, None);
        Ok(())
    }

    #[test]
    fn claim_vad_now_auto_generated_matches_async_error_and_clear_bytes() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let (claim, subject, _) = approved_fixture(&vault)?;
        seed_generated_auto_source_trust_manifest(&vault)?;
        let approved = vault.get_claim(&claim)?.expect("approved");
        let semantic = EdgeRef::new(claim, EdgeKind::Mentions, subject);
        let mut cleared = None;
        for synchronous in [true, false] {
            vault.put_claim(&claim, &approved, test_time_range(30, 30), 30)?;
            let first = vault.consolidate_claim_vad_now(&claim, 100)?;
            let state = first.reappraisal.active_claim_id.expect("active state");
            let mut unvetted = approved.clone();
            unvetted.approval = ClaimApprovalStatus::Auto;
            vault.put_claim(&claim, &unvetted, test_time_range(30, 30), 30)?;
            let result = if synchronous {
                vault.consolidate_claim_vad_now(&claim, 200)
            } else {
                block_on_ready(vault.consolidate_claim_vad(&claim, 200))
            };
            assert_matches!(result, Err(Error::InvalidClaimBody(_)));
            assert_eq!(
                vault.get_claim(&state)?.expect("closed state").lifecycle,
                ClaimLifecycleStatus::Superseded
            );
            let bytes = raw_edge_values(&vault, &semantic)?;
            if let Some(previous) = &cleared {
                assert_eq!(&bytes, previous, "both entries clear identical edge bytes");
            }
            cleared = Some(bytes);
            let edge = vault
                .edges_out(&claim)?
                .into_iter()
                .find(|edge| edge.kind == EdgeKind::Mentions)
                .expect("semantic edge");
            assert_eq!(edge.vad, Some(Vad::NEUTRAL));
        }
        Ok(())
    }

    #[test]
    fn claim_vad_now_propagates_reappraisal_and_annotation_rejection() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let (claim, _, _) = approved_fixture(&vault)?;
        let result = vault.consolidate_claim_vad_now(&claim, 100)?;
        let state = result.reappraisal.active_claim_id.expect("active state");
        assert_matches!(
            vault.consolidate_claim_vad_now(&state, 110),
            Err(Error::InvalidClaimBody(_))
        );
        let turn = result.evidence_turns[0].turn_id;
        let annotation = vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
        assert_matches!(
            vault.consolidate_claim_vad_now(&annotation, 110),
            Err(Error::InvalidClaimBody(_))
        );
        Ok(())
    }
}
