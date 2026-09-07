use super::*;

#[test]
fn retrieval_depth_specificity_counts_only_visible_inbound_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (first, second) = (entity(0xB1), entity(0xB2));
    let sources = [entity(0xB3), entity(0xB4), entity(0xB5)];
    for source in sources {
        vault.put_edge(&source, EdgeKind::Mentions, &first, 0.5)?;
    }
    let rtxn = vault.store.env.read_txn()?;
    let visibility = DeniedNodes::new(&sources);
    let scoped =
        specificity_seed_weights(&vault.store, &rtxn, &[first, second], Some(&visibility))?;
    assert_eq!(scoped, vec![0.5, 0.5]);
    let unscoped = specificity_seed_weights(&vault.store, &rtxn, &[first, second], None)?;
    assert!(
        unscoped[0] < unscoped[1],
        "visible counts still affect specificity"
    );
    let visible = DeniedNodes::new(&[]);
    assert_eq!(
        specificity_seed_weights(&vault.store, &rtxn, &[first, second], Some(&visible))?,
        unscoped
    );
    Ok(())
}

#[test]
fn retrieval_depth_specificity_visibility_errors_fail_before_walk_rounds() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seed = entity(0xB6);
    let source = entity(0xA7);
    vault.put_edge(&source, EdgeKind::Mentions, &seed, 0.5)?;
    let rtxn = vault.store.env.read_txn()?;
    let error = ppr_query_scoped_in_txn(
        &vault.store,
        &rtxn,
        &[seed],
        0,
        0.15,
        vault.config.ppr_vad_alpha,
        SeedWeighting::Specificity,
        &DeniedNodes::failing(source),
    )
    .expect_err("seed specificity must consult source visibility even without traversal");
    assert!(matches!(error, Error::CorruptedIndex(PROBE_FAILURE)));
    Ok(())
}
