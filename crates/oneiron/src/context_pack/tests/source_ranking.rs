//! Source ranking is PACK data and cannot widen visibility or scope.
use super::super::source_ranking::SourceRankingPolicy;
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

#[test]
fn observed_preference_stays_below_stated_until_pack_explicitly_overrides() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let stated = EntityId::now();
    let observed = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    for (id, source, confidence, text) in [
        (
            stated,
            ClaimSource::UserStated,
            0.1,
            "needle less relevant long supporting text",
        ),
        (observed, ClaimSource::Observed, 0.99, "needle"),
    ] {
        let envelope = WriteEnvelope::new(
            WriteActor::new(person, crate::edge::EdgeActorClass::Human),
            source,
            WriteProvenance::new(rmpv::Value::from("test"))?,
            ClaimApprovalStatus::Approved,
        );
        vault
            .batch()
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    "preference.food",
                    ClaimSubject::Entity(person),
                    rmpv::Value::from(text),
                    confidence,
                ),
                &envelope,
                TimeRange { start: 1, end: 1 },
                1,
            )
            .text(&id, &[("body", text)])
            .commit()?;
    }
    let default = vault
        .context_pack()
        .search_text("needle", 20)
        .boost_confidence()
        .with_temporal_now(2)
        .run()?;
    assert_eq!(
        default.results.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![stated, observed]
    );
    let mut policy = SourceRankingPolicy::default();
    policy.multipliers.insert("observed".into(), 5.0);
    let overridden = vault
        .context_pack()
        .search_text("needle", 20)
        .boost_confidence()
        .with_temporal_now(2)
        .source_ranking(policy)
        .run()?;
    assert_eq!(
        overridden.results.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![observed, stated]
    );
    let mut invalid = SourceRankingPolicy::default();
    invalid.multipliers.insert("observed".into(), f32::NAN);
    assert!(
        vault
            .context_pack()
            .search_text("needle", 20)
            .source_ranking(invalid)
            .run()
            .is_err()
    );
    Ok(())
}
