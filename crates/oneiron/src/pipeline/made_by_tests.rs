//! Provenance slices are membership filters, never score multipliers.
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::provenance::made_by::{MadeByClass, MadeByPredicate};
use crate::test_util::{entity, open_test_vault_with};
use crate::{Result, TimeRange};

#[test]
fn made_by_filters_before_limit_and_keeps_scores() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(crate::VaultConfig::device());
    let subject = entity(40);
    let at = TimeRange {
        start: 100,
        end: 100,
    };
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        100,
        b"person",
    )?;
    let mut ids = Vec::new();
    for (i, source) in [
        ClaimSource::Inferred,
        ClaimSource::UserStated,
        ClaimSource::Observed,
    ]
    .into_iter()
    .enumerate()
    {
        let id = entity(41 + i as u8);
        let mut body = ClaimBody::new(
            "test.provenance",
            ClaimSubject::Entity(subject),
            "needle".into(),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(source);
        vault.put_claim(&id, &body, at, 100)?;
        vault.batch().text(&id, &[("body", "needle")]).commit()?;
        ids.push(id);
    }
    let query = || {
        vault
            .query()
            .search_text("needle", 20)
            .with_temporal_now(100)
    };
    let all = query().made_by(MadeByPredicate::All).run()?;
    assert_eq!(all.len(), 3);
    let stated = query().made_by(MadeByPredicate::Stated).limit(2).run()?;
    assert_eq!(stated.len(), 2);
    assert!(stated.iter().all(|s| ids[1..].contains(&s.id)));
    let concluded = query().made_by(MadeByPredicate::Concluded).limit(1).run()?;
    assert_eq!(concluded[0].id, ids[0]);
    for s in stated.iter().chain(&concluded) {
        assert_eq!(s.score, all.iter().find(|a| a.id == s.id).unwrap().score);
    }
    assert_eq!(
        vault.get_claim(&ids[0])?.unwrap().made_by_class(),
        Some(MadeByClass::Concluded)
    );
    Ok(())
}
