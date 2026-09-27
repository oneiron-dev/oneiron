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

#[test]
fn retry_source_budget_is_a_narrowing_manifest_row() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let default_id = crate::gate::default_policy_manifest_id()?;
    let default = crate::gate::default_policy_manifest();
    let decode = |bytes: &[u8]| -> rmpv::Value {
        rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).expect("manifest map")
    };
    let encode = |value: &rmpv::Value| -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).expect("manifest codec");
        out
    };
    let limit = || -> Result<usize> {
        let txn = vault.store.env.read_txn()?;
        Ok(crate::gate::resolve_policy_manifest(&vault.store, &txn)?.dreamer_retry_source_limit())
    };
    assert_eq!(limit()?, 1_024);
    let rmpv::Value::Map(mut vault_fields) = decode(&default) else {
        panic!("default map")
    };
    let budget = vault_fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("dreamer_retry_source_limit"))
        .expect("shipped retry budget");
    budget.1 = 2_u64.into();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        default_id,
        &encode(&rmpv::Value::Map(vault_fields.clone())),
    )?;
    assert_eq!(limit()?, 2, "vault policy changes the source cap");
    // A second pack acts as a holder restriction: the resolved minimum may
    // narrow, but cannot widen the vault's two-source ceiling.
    let holder_id = crate::test_util::entity(0x4f);
    let pack = vault_fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("pack_id"))
        .expect("pack id");
    pack.1 = "holder-policy".into();
    let budget = vault_fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("dreamer_retry_source_limit"))
        .expect("retry cap");
    budget.1 = 100_u64.into();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        holder_id,
        &encode(&rmpv::Value::Map(vault_fields.clone())),
    )?;
    assert_eq!(limit()?, 2, "holder cannot widen vault cap");
    let budget = vault_fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("dreamer_retry_source_limit"))
        .expect("retry cap");
    budget.1 = 1_u64.into();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        holder_id,
        &encode(&rmpv::Value::Map(vault_fields)),
    )?;
    assert_eq!(limit()?, 1, "holder can narrow cap");
    Ok(())
}
