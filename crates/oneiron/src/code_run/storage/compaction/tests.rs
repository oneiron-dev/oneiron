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

#[test]
fn coverage_row_must_match_the_exact_minted_summary_body() -> Result<()> {
    use crate::TimeRange;
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, encode_epoch_summary_body,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let run = EntityId::now();
    let session = EntityId::now();
    let actor = EntityId::now();
    let summary = EntityId::now();
    let body = encode_epoch_summary_body(&EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: session.to_hex(),
        epoch: 1,
        turn_start: 1,
        turn_end: 2,
        level: EPOCH_SUMMARY_LEVEL,
        text: "durable summary".into(),
        actor: actor.to_hex(),
    })?;
    vault.put_entity(
        &summary,
        ENTITY_TYPE_SUMMARY,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    let row = CodeRunCompactionCoverage {
        run_id: run,
        session_ref: session,
        summary_id: summary,
        epoch: 1,
        first: 1,
        last: 2,
    };
    let key = key(run, summary);
    let put = |row: &CodeRunCompactionCoverage| -> Result<()> {
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, &key, &encode(row))?;
            Ok(())
        })
    };
    put(&row)?;
    assert_eq!(vault.code_run_compaction_coverage(run)?.len(), 1);
    for mismatch in [
        CodeRunCompactionCoverage { epoch: 2, ..row },
        CodeRunCompactionCoverage { last: 3, ..row },
        CodeRunCompactionCoverage {
            session_ref: actor,
            ..row
        },
        CodeRunCompactionCoverage {
            summary_id: actor,
            ..row
        },
    ] {
        put(&mismatch)?;
        assert!(vault.code_run_compaction_coverage(run).is_err());
    }
    Ok(())
}
