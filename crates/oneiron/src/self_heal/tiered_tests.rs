//! Observable propose-only outputs and reviewed distillation.
use super::distillation::ClosedFormPredicate;
use super::tiered::{DetectorPolicy, ProposedTier, TelemetryJudge};
use super::*;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::{RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalSignal};

struct Grade(bool);
impl TelemetryJudge for Grade {
    fn assess(
        &self,
        _: &str,
        _: &str,
        _: &[RetrievalRunRecord],
        _: &[(Vec<RetrievalRunRecord>, bool)],
    ) -> Result<bool> {
        Ok(self.0)
    }
}
struct LabeledGrade;
impl TelemetryJudge for LabeledGrade {
    fn assess(
        &self,
        _: &str,
        _: &str,
        _: &[RetrievalRunRecord],
        examples: &[(Vec<RetrievalRunRecord>, bool)],
    ) -> Result<bool> {
        Ok(examples.len() == 3
            && examples
                .iter()
                .filter(|(rows, positive)| rows.len() == 1 && *positive)
                .count()
                == 2
            && examples
                .iter()
                .filter(|(rows, positive)| rows.len() == 1 && !*positive)
                .count()
                == 1)
    }
}
fn policy(n: usize) -> DetectorPolicy {
    DetectorPolicy {
        family: "retrieval_quality".into(),
        class: DiagnosticEventClass::RetrievalMiss,
        prompt: "caller-supplied prompt".into(),
        rubric: "caller-supplied rubric".into(),
        consecutive: n,
    }
}
fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::VaultConfig::device();
    config.embedding_model = Some("test/tiered@v1".into());
    config.dimensions = 4;
    let vault = Vault::open_owned(dir.path(), config).unwrap();
    (dir, vault)
}
fn run(v: &Vault, at: u64, miss: bool) -> RetrievalRunRecord {
    let row = RetrievalRunRecord::new(
        RetrievalRunId::now(),
        RetrievalAction::Pipeline,
        at,
        1,
        vec![RetrievalSignal::Text],
        vec![],
        if miss { 3 } else { 0 },
        0,
        if miss { Some("no_result".into()) } else { None },
    );
    v.store.record_retrieval_run(&row).unwrap();
    row
}
fn owner(v: &Vault) -> crate::consent::AuthenticatedOwner {
    let id = EntityId::now();
    v.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )
    .unwrap();
    v.authenticate_owner(id, "owner", true, crate::store::GateDecisionId::now())
        .unwrap()
}

#[test]
fn t2b_and_t3_persist_proposals_but_never_sign_t1() -> Result<()> {
    let (_d, v) = vault();
    let rows = vec![run(&v, 10, true), run(&v, 11, true)];
    assert!(
        v.classify_prompt(&policy(2), &Grade(false), &rows)?
            .is_none()
    );
    assert!(v.classify_prompt(&policy(3), &Grade(true), &rows).is_err());
    let t2 = v.classify_prompt(&policy(2), &Grade(true), &rows)?.unwrap();
    assert_eq!(t2.tier, ProposedTier::PromptClassifier);
    assert_eq!(
        decode_diagnostic_event_body(&v.get(&t2.event_id)?.unwrap())?,
        t2.event
    );
    let t3 = v
        .judge_retrieval_trace(&policy(1), &Grade(true), &rows)?
        .unwrap();
    assert_eq!(t3.tier, ProposedTier::Judge);
    assert_ne!(t3.event_id, t2.event_id);
    assert_eq!(t2.event.criticality, DiagnosticCriticality::Normal);
    assert!(t2.event.detector_id.starts_with("t2b."));
    assert!(t3.event.detector_id.starts_with("t3."));
    // The signed-run validation door only accepts T1 instances registered by the host.
    assert!(v.get(&t3.event_id)?.is_some());
    let mut forged = rows;
    forged[1].empty_reason = Some("forged".into());
    assert!(
        v.judge_retrieval_trace(&policy(1), &Grade(true), &forged)
            .is_err()
    );
    Ok(())
}

#[test]
fn session_judge_requires_one_telemetry_episode() -> Result<()> {
    let (_d, v) = vault();
    let mut a = run(&v, 20, true);
    let mut b = run(&v, 21, true);
    assert!(
        v.judge_session_quality(&policy(1), &Grade(true), &[a.clone()])
            .is_err()
    );
    let turn = crate::store::RetrievalTurn {
        turn_id: [1; 16],
        episode_id: [3; 16],
        turn_idx: 1,
    };
    a.turn = Some(turn);
    b.turn = Some(crate::store::RetrievalTurn {
        turn_idx: 2,
        ..turn
    });
    v.store.delete_retrieval_run(a.run_id)?;
    v.store.record_retrieval_run(&a)?;
    v.store.delete_retrieval_run(b.run_id)?;
    v.store.record_retrieval_run(&b)?;
    assert!(
        v.judge_session_quality(&policy(1), &Grade(false), &[a.clone(), b.clone()])?
            .is_none()
    );
    let judged = v
        .judge_session_quality(&policy(1), &Grade(true), &[a.clone(), b.clone()])?
        .unwrap();
    assert_eq!(judged.tier, ProposedTier::SessionJudge);
    b.turn = Some(crate::store::RetrievalTurn {
        episode_id: [4; 16],
        ..turn
    });
    v.store.delete_retrieval_run(b.run_id)?;
    v.store.record_retrieval_run(&b)?;
    assert!(
        v.judge_session_quality(&policy(1), &Grade(true), &[a, b])
            .is_err()
    );
    Ok(())
}

#[test]
fn reviewed_recurrence_mints_t2_and_closed_form_t1() -> Result<()> {
    let (_d, v) = vault();
    let o = owner(&v);
    let p = policy(2);
    let yes1 = run(&v, 31, true);
    let yes2 = run(&v, 32, true);
    let no = run(&v, 33, false);
    let a = v
        .judge_retrieval_trace(&policy(1), &Grade(true), &[yes1])?
        .unwrap();
    let b = v
        .judge_retrieval_trace(&policy(1), &Grade(true), &[yes2])?
        .unwrap();
    let c = v
        .judge_retrieval_trace(&policy(1), &Grade(true), &[no])?
        .unwrap();
    // A model opinion by itself cannot mint or arm anything.
    assert!(v.mint_t2(p.clone())?.is_none());
    assert!(v.review_t3_finding(&o, &p.family, a.event_id, true).is_ok());
    assert!(v.mint_t2(p.clone())?.is_none());
    v.review_t3_finding(&o, &p.family, b.event_id, true)?;
    assert!(v.mint_t2(p.clone())?.is_none()); // negatives are required too
    v.review_t3_finding(&o, &p.family, c.event_id, false)?;
    assert!(
        v.review_t3_finding(&o, &p.family, c.event_id, true)
            .is_err()
    );
    let t2 = v.mint_t2(p)?.unwrap();
    assert_eq!(t2.positive_events.len(), 2);
    let new_runs = [run(&v, 34, false), run(&v, 35, false)];
    assert_eq!(
        v.classify_minted_t2(&t2, &LabeledGrade, &new_runs)?
            .unwrap()
            .tier,
        ProposedTier::PromptClassifier
    );
    let t1 = v
        .graduate_t1(&t2, ClosedFormPredicate::RetrievalMiss)?
        .unwrap();
    assert_eq!(t1.detector_id, "retrieval.miss.v1");
    assert_eq!(t1.negative_events, vec![c.event_id]);
    Ok(())
}

#[test]
fn mismatched_labels_and_forged_centroid_input_fail_closed() -> Result<()> {
    let (_d, v) = vault();
    let o = owner(&v);
    let p = policy(1);
    let row = run(&v, 42, false);
    let t3 = v
        .judge_retrieval_trace(&p, &Grade(true), std::slice::from_ref(&row))?
        .unwrap();
    assert!(v.review_t3_finding(&o, "other", t3.event_id, true).is_err());
    v.review_t3_finding(&o, &p.family, t3.event_id, true)?;
    let another = run(&v, 43, false);
    let negative = v
        .judge_retrieval_trace(&p, &Grade(true), &[another])?
        .unwrap();
    v.review_t3_finding(&o, &p.family, negative.event_id, false)?;
    let minted = v.mint_t2(p.clone())?.unwrap();
    assert!(
        v.graduate_t1(&minted, ClosedFormPredicate::RetrievalMiss)?
            .is_none()
    );
    let candidate = EntityId::now();
    assert!(
        v.classify_centroid(&p, &[candidate], candidate, &row, 0.6)
            .is_err()
    );
    Ok(())
}

#[test]
fn centroid_uses_existing_vectors_and_emits_only_a_proposal() -> Result<()> {
    use crate::store::RetrievalScoreBreakdown;
    let (_d, v) = vault();
    let center = EntityId::now();
    let candidate = EntityId::now();
    for id in [center, candidate] {
        v.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )?;
    }
    v.put_vector(&center, &[1.0, 0.0, 0.0, 0.0])?;
    v.put_vector(&candidate, &[0.98, 0.02, 0.0, 0.0])?;
    let row = RetrievalRunRecord::new(
        RetrievalRunId::now(),
        RetrievalAction::Pipeline,
        44,
        1,
        vec![RetrievalSignal::Vector],
        vec![RetrievalScoreBreakdown {
            result_id: *candidate.as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![],
            access_factor: None,
        }],
        1,
        0,
        None,
    );
    v.store.record_retrieval_run(&row)?;
    let classified = v
        .classify_centroid(&policy(1), &[center], candidate, &row, 0.9)?
        .unwrap();
    assert_eq!(classified.tier, ProposedTier::Centroid);
    assert!(classified.event.detector_id.starts_with("t2a."));
    assert_eq!(
        decode_diagnostic_event_body(&v.get(&classified.event_id)?.unwrap())?,
        classified.event
    );
    let original = v.replay_centroid_finding(&classified.event_id)?;
    assert_eq!(original.candidate, candidate);
    assert_eq!(original.labeled, vec![(center, vec![1.0, 0.0, 0.0, 0.0])]);
    assert_eq!(original.min_similarity, 0.9);
    assert!(original.matched);
    // Mutable current vectors can no longer produce this verdict. Historical
    // replay must still reconstruct the exact centroid and threshold.
    v.put_vector(&center, &[0.0, 1.0, 0.0, 0.0])?;
    assert!(
        v.classify_centroid(&policy(1), &[center], candidate, &row, 0.9)?
            .is_none()
    );
    let replayed = v.replay_centroid_finding(&classified.event_id)?;
    assert_eq!(replayed.labeled, original.labeled);
    assert_eq!(replayed.similarity.to_bits(), original.similarity.to_bits());
    assert_eq!(replayed.run, row);
    // The threshold is a verdict input: same telemetry with a changed
    // threshold must not reuse the previous event address.
    v.put_vector(&center, &[1.0, 0.0, 0.0, 0.0])?;
    let other = v
        .classify_centroid(&policy(1), &[center], candidate, &row, 0.8)?
        .unwrap();
    assert_ne!(other.event_id, classified.event_id);
    assert_eq!(
        v.replay_centroid_finding(&other.event_id)?.min_similarity,
        0.8
    );
    assert!(
        v.classify_centroid(&policy(1), &[center], candidate, &row, 1.0)?
            .is_none()
    );
    Ok(())
}

#[test]
fn copied_t3_bodies_under_other_entity_kinds_cannot_mint_evidence() -> Result<()> {
    let (_d, vault) = vault();
    let owner = owner(&vault);
    let positive = vault
        .judge_retrieval_trace(&policy(1), &Grade(true), &[run(&vault, 51, true)])?
        .unwrap();
    let negative = vault
        .judge_retrieval_trace(&policy(1), &Grade(true), &[run(&vault, 52, false)])?
        .unwrap();
    let body = vault.get(&positive.event_id)?.unwrap();
    for _ in 0..2 {
        let forged = EntityId::now();
        vault.put_entity(
            &forged,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 51,
                end: u64::MAX,
            },
            51,
            &body,
        )?;
        assert!(
            vault
                .review_t3_finding(&owner, &policy(2).family, forged, true)
                .is_err()
        );
    }
    vault.review_t3_finding(&owner, &policy(2).family, positive.event_id, true)?;
    vault.review_t3_finding(&owner, &policy(2).family, negative.event_id, false)?;
    assert!(vault.mint_t2(policy(2))?.is_none());
    Ok(())
}
