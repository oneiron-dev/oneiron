use super::*;
use crate::{ClaimCandidate, ClaimSource, ClaimSubject, TimeRange};
fn candidate(subject: EntityId, predicate: &str, value: Value) -> PromotionCandidate {
    PromotionCandidate {
        claim_id: EntityId::now(),
        candidate: ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 0.8),
        evidence_turn_refs: vec![EntityId::now()],
        provenance_chain: vec![],
        supersedes: None,
        evidence_meet: ClaimSource::Generated,
        occurred: TimeRange { start: 0, end: 0 },
        learned_at: 0,
    }
}
#[test]
fn exact_value_keys_attach_evidence_without_judgment() -> Result<()> {
    let subject = EntityId::now();
    let a = candidate(subject, "profile.name", Value::from("Ada"));
    let b = candidate(subject, "profile.name", Value::from(" ada  "));
    let rules = serde_json::from_str(include_str!("../key_defaults.json")).unwrap();
    let refs = BTreeSet::from([a.evidence_turn_refs[0], b.evidence_turn_refs[0]]);
    let kept = attach_duplicate_evidence(vec![a, b], &rules)?;
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0]
            .evidence_turn_refs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        refs
    );
    assert!(judge_queue(&kept, &BTreeMap::new(), &rules, 0.9)?.is_empty());
    Ok(())
}
#[test]
fn question_keys_route_changed_answers_and_cosine_only_nominates() -> Result<()> {
    let subject = EntityId::now();
    let make = |topic, answer| {
        Value::Map(vec![
            (Value::from("topic"), Value::from(topic)),
            (Value::from("answer"), Value::from(answer)),
        ])
    };
    let a = candidate(subject, "boundary.topic", make("work", "yes"));
    let b = candidate(subject, "boundary.topic", make("work", "no"));
    let c = candidate(subject, "boundary.topic", make("home", "yes"));
    let rules = serde_json::from_str(include_str!("../key_defaults.json")).unwrap();
    let pairs = judge_queue(&[a.clone(), b, c.clone()], &BTreeMap::new(), &rules, 0.9)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].candidate_indexes, vec![0, 1]);
    let embeddings = BTreeMap::from([(a.claim_id, vec![1.0, 0.0]), (c.claim_id, vec![1.0, 0.01])]);
    let original = vec![a, c];
    let pairs = judge_queue(&original, &embeddings, &rules, 0.9)?;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].candidate_indexes, vec![0, 1]);
    // Nomination returns only questions. Both beliefs and their evidence remain intact.
    assert_eq!(original.len(), 2);
    let mut other_scope = original[1].clone();
    other_scope.candidate = other_scope.candidate.with_relationship(EntityId::now());
    assert!(
        judge_queue(
            &[original[0].clone(), other_scope],
            &embeddings,
            &rules,
            0.9
        )?
        .is_empty()
    );
    Ok(())
}
