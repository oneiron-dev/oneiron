use super::*;
#[test]
fn rows_control_holds_strength_and_fan_in_order() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let mut config = vault.consolidation_selection()?;
    config.soak_ms = 10;
    config.evidence_minimum = 2;
    vault.set_consolidation_selection(&config)?;
    let config = vault.consolidation_selection()?;
    let base = SelectionCandidate {
        claim_id: EntityId::now(),
        first_seen_ms: 0,
        evidence_count: 2,
        fan_in: 2,
        new_refs: 1,
        signals: StrengthSignals {
            type_prior: 0.5,
            frequency: 0.0,
            recency: 0.0,
            diversity: 0.0,
        },
    };
    let mut fresh = base.clone();
    fresh.claim_id = EntityId::now();
    fresh.first_seen_ms = 95;
    let mut sparse = base.clone();
    sparse.claim_id = EntityId::now();
    sparse.evidence_count = 1;
    let mut connected = base.clone();
    connected.claim_id = EntityId::now();
    connected.fan_in = 10;
    connected.new_refs = 4;
    let mut strongest = base.clone();
    strongest.claim_id = EntityId::now();
    strongest.signals.type_prior = 1.0;
    let mut candidates = vec![
        base.clone(),
        fresh.clone(),
        sparse.clone(),
        connected.clone(),
        strongest.clone(),
    ];
    let plan = select_candidates(&candidates, 100, &config)?;
    assert_eq!(
        plan.ready,
        vec![strongest.claim_id, connected.claim_id, base.claim_id]
    );
    assert!(plan.held.contains(&(fresh.claim_id, SelectionHold::Soak)));
    assert!(
        plan.held
            .contains(&(sparse.claim_id, SelectionHold::EvidenceCount))
    );
    candidates[2].evidence_count = 2;
    assert!(
        select_candidates(&candidates, 110, &config)?
            .held
            .is_empty()
    );
    let mut changed = config;
    changed.soak_ms = 0;
    changed.evidence_minimum = 1;
    vault.set_consolidation_selection(&changed)?;
    assert!(
        select_candidates(&candidates, 100, &vault.consolidation_selection()?)?
            .held
            .is_empty()
    );
    Ok(())
}
#[test]
fn type_prior_dominates_other_signals_and_surprise_is_not_an_input() -> Result<()> {
    let config = SelectionConfig::default();
    let prior = StrengthSignals {
        type_prior: 1.0,
        frequency: 0.0,
        recency: 0.0,
        diversity: 0.0,
    };
    let other = StrengthSignals {
        type_prior: 0.0,
        frequency: 1.0,
        recency: 1.0,
        diversity: 1.0,
    };
    assert!(strength_score(prior, &config)? > strength_score(other, &config)?);
    let mut signals = BTreeMap::from([("type_prior".into(), 1.0)]);
    let score = strength_score(StrengthSignals::from_named(&signals), &config)?;
    signals.insert("surprise".into(), f64::NAN);
    signals.insert("perplexity".into(), f64::INFINITY);
    assert_eq!(
        strength_score(StrengthSignals::from_named(&signals), &config)?,
        score
    );
    let mut invalid = config;
    invalid.weights.type_prior = 0.1;
    assert!(strength_score(prior, &invalid).is_err());
    Ok(())
}
