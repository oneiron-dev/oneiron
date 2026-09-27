use super::*;

#[test]
fn malformed_or_misbound_coverage_never_becomes_a_view_decision() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let run = EntityId::now();
    let summary = EntityId::now();
    let other = EntityId::now();
    let bogus = CodeRunCompactionCoverage {
        run_id: run,
        session_ref: other,
        summary_id: summary,
        epoch: 1,
        first: 1,
        last: 2,
    };
    let key = key(run, summary);
    let mut raw = encode(&bogus);
    for invalid in [vec![], vec![2_u8; BODY_LEN]] {
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, &key, &invalid)?;
            Ok(())
        })?;
        assert!(vault.code_run_compaction_coverage(run).is_err());
    }
    raw[1] ^= 1; // value's run contradicts its indexed key
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &raw)?;
        Ok(())
    })?;
    assert!(vault.code_run_compaction_coverage(run).is_err());
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &encode(&bogus))?;
        Ok(())
    })?;
    assert!(
        vault.code_run_compaction_coverage(run).is_err(),
        "no minted SUMMARY exists"
    );
    Ok(())
}
