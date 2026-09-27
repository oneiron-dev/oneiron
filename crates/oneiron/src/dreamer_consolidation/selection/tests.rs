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
fn retry_source_policy_binds_real_holder_and_scope_with_vault_ceiling() -> Result<()> {
    use crate::gate::retry_source_policy::RetryPrecedence;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let holder = EntityId::now();
    let other = EntityId::now();
    let project = EntityId::now();
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert_eq!(policy.retry_budget_for(holder, None)?.max_sources(), 1_024);
    drop(txn);
    let id = crate::gate::default_policy_manifest_id()?;
    let raw = vault.get(&id)?.expect("seeded manifest");
    let rmpv::Value::Map(mut fields) =
        rmpv::decode::read_value(&mut raw.as_slice()).expect("manifest codec")
    else {
        panic!("policy map")
    };
    let row = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("retry_source_policy"))
        .expect("required policy row");
    row.1 = rmpv::Value::Array(vec![
        rmpv::Value::Map(vec![
            ("selector".into(), "vault".into()),
            ("max_sources".into(), 6_u64.into()),
            ("precedence".into(), "nested_narrowing".into()),
        ]),
        rmpv::Value::Map(vec![
            ("selector".into(), "project".into()),
            ("source_id".into(), project.to_hex().into()),
            ("max_sources".into(), 2_u64.into()),
        ]),
        rmpv::Value::Map(vec![
            ("selector".into(), "holder".into()),
            ("source_id".into(), holder.to_hex().into()),
            ("max_sources".into(), 5_u64.into()),
        ]),
    ]);
    let encode = |fields: &[(rmpv::Value, rmpv::Value)]| -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &rmpv::Value::Map(fields.to_vec())).unwrap();
        out
    };
    let write = |data: &[u8]| crate::test_util::put_policy_manifest_bytes(&vault, id, data);
    write(&encode(&fields))?;
    let scope = crate::llm::Scope {
        project: Some(project),
        ..Default::default()
    };
    let read = || -> Result<crate::gate::retry_source_policy::ResolvedRetryBudget> {
        let txn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?
            .retry_budget_for(holder, Some(&scope))
    };
    assert_eq!(
        read()?.max_sources(),
        2,
        "nested scope narrows matched holder"
    );
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert_eq!(
        policy.retry_budget_for(other, Some(&scope))?.max_sources(),
        2
    );
    assert_eq!(policy.retry_budget_for(holder, None)?.max_sources(), 5);
    drop(txn);
    // Vault configures holder precedence; it can bypass a work-budget scope
    // preference, never the vault's authority cap.
    let rmpv::Value::Array(rows) = &mut fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("retry_source_policy"))
        .unwrap()
        .1
    else {
        unreachable!()
    };
    let rmpv::Value::Map(vault_row) = &mut rows[0] else {
        unreachable!()
    };
    vault_row
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("precedence"))
        .unwrap()
        .1 = "holder_override".into();
    write(&encode(&fields))?;
    assert_eq!(read()?.precedence, RetryPrecedence::HolderOverride);
    assert_eq!(read()?.max_sources(), 5);
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert_eq!(
        policy.retry_budget_for(other, Some(&scope))?.max_sources(),
        2,
        "unrelated holder cannot select this actor's override"
    );
    drop(txn);
    let rmpv::Value::Array(rows) = &mut fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("retry_source_policy"))
        .unwrap()
        .1
    else {
        unreachable!()
    };
    let rmpv::Value::Map(holder_row) = &mut rows[2] else {
        unreachable!()
    };
    holder_row
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("max_sources"))
        .unwrap()
        .1 = 100_u64.into();
    write(&encode(&fields))?;
    assert_eq!(read()?.max_sources(), 6, "holder cannot exceed vault cap");
    let rmpv::Value::Array(rows) = &mut fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("retry_source_policy"))
        .unwrap()
        .1
    else {
        unreachable!()
    };
    rows.remove(0);
    write(&encode(&fields))?;
    let txn = vault.store.env.read_txn()?;
    let missing = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    assert!(
        missing.retry_budget_for(holder, Some(&scope)).is_err(),
        "holder/scoped rows cannot create an absent vault ceiling"
    );
    Ok(())
}
