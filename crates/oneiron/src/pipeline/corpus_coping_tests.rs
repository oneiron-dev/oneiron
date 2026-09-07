use super::*;
use crate::affect::VadDelta;
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeValue, CopingStrategy, coping_outcome_value,
};

fn put_corpus_coping_outcome(
    vault: &Vault,
    id: EntityId,
    person: EntityId,
    scope: Option<CorpusId>,
    learned_at: u64,
) -> Result<()> {
    let value = CopingOutcomeValue::new(
        person,
        entity_id(0x70),
        CopingStrategy::SitSel,
        VadDelta::new(0.2, 0.0, 0.0)?,
        0.9,
        1,
    )?;
    let mut body = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(person),
        coping_outcome_value(&value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(crate::claim::ClaimSource::Inferred);
    body.valid_from = Some(learned_at);
    if let Some(scope) = scope {
        body.scope = Some(scope_with_corpus_id(None, scope)?);
    }
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: learned_at,
            end: u64::MAX,
        },
        learned_at,
    )
}

#[test]
fn corpus_coping_terminal_filters_before_truncation() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = entity_id(0x71);
    put_entity(&vault, person, crate::registry::ENTITY_TYPE_PERSON, 1, 1, 1)?;
    let core = entity_id(0x41);
    let selected = entity_id(0x44);
    let excluded = entity_id(0x43);
    put_corpus_coping_outcome(&vault, core, person, None, 10)?;
    put_corpus_coping_outcome(&vault, selected, person, Some(corpus(0x95)), 20)?;
    put_corpus_coping_outcome(&vault, excluded, person, Some(corpus(0x96)), 30)?;
    let ids = |builder: PipelineBuilder<'_>, limit| -> Result<Vec<EntityId>> {
        Ok(builder
            .prior_successful_coping_strategies(&person, limit)?
            .into_iter()
            .map(|row| row.claim_id)
            .collect())
    };
    let baseline = ids(vault.query(), 10)?;
    assert_eq!(baseline, vec![excluded, selected, core]);
    assert_eq!(ids(vault.query().corpus(CorpusScope::All), 10)?, baseline);
    for scope in [
        CorpusScope::Corpus(corpus(0x95)),
        CorpusScope::AnyOf(vec![corpus(0x95); 2]),
    ] {
        assert_eq!(
            ids(vault.query().corpus(scope.clone()), 10)?,
            vec![selected, core]
        );
        assert_eq!(ids(vault.query().corpus(scope), 1)?, vec![selected]);
    }
    assert_eq!(
        ids(vault.query().corpus(CorpusScope::Unscoped), 10)?,
        vec![core]
    );
    // This specialized terminal historically does not consume world/facet/rel
    // builder settings. Corpus selection must not silently change those rules.
    assert_eq!(
        ids(
            vault
                .query()
                .corpus(CorpusScope::Corpus(corpus(0x95)))
                .world(WorldScope::Base)
                .facet(&entity_id(0x72), FacetMode::Strict)
                .relationship(&entity_id(0x73), RelMode::Filter),
            10
        )?,
        vec![selected, core]
    );
    Ok(())
}

#[test]
fn corpus_coping_terminal_rejects_empty_any_of_even_at_zero_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for limit in [0, 1] {
        assert!(matches!(
            vault
                .query()
                .corpus(CorpusScope::AnyOf(vec![]))
                .prior_successful_coping_strategies(&entity_id(0x71), limit),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert!(
        vault
            .query()
            .corpus(CorpusScope::Corpus(corpus(0x95)))
            .prior_successful_coping_strategies(&entity_id(0x71), 0)?
            .is_empty()
    );
    Ok(())
}
