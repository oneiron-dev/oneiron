use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::Store;

use super::archive_retained_side_rows::RETAINED_SIDE_ROWS;
use super::archive_retained_subjects::{RetainedSubjectRule, retained_subject_rule};

/// A record's erase over the retained rows: deletes each inert archive copy whose table's subject
/// rule ([`RetainedSubjectRule::records`]) names `id`, so no copy of a row about an erased record
/// outlives it or rides the next whole-vault export (FIX HARD-DELETE-RETAINED-ARCHIVE-ROW-OUTLIVES-RECORD).
/// A copy whose table states no rule, or whose bytes its rule cannot read, stays: the export
/// withholds it already. Registered once in the delete doors' ERASERS list, so the batch delete,
/// hard purge, soft erase and replayed tombstone all run it.
pub(crate) fn erase_retained_side_rows_of_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut erase: Vec<[u8; 32]> = Vec::new();
    for row in RETAINED_SIDE_ROWS.iter_raw_from(store, wtxn, &[])? {
        let (key, value) = row?;
        let (Some(typed), Ok(envelope)) = (
            <[u8; 32] as SideKey>::decode_key(&key),
            RETAINED_SIDE_ROWS.decode_value(&value),
        ) else {
            continue;
        };
        let Some(rule): Option<RetainedSubjectRule> = retained_subject_rule(&envelope.source_table)
        else {
            continue;
        };
        let Some(ids) = rule.records(&envelope.source_key, &envelope.source_value) else {
            continue;
        };
        if ids.contains(id) {
            erase.push(typed);
        }
    }
    for key in &erase {
        RETAINED_SIDE_ROWS.delete(store, wtxn, key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::archive_retained_side_rows::{
        ArchiveRetainedSideRow, RETAINED_SIDE_ROWS, collect_retained_side_rows_in_txn,
        retained_side_row_key,
    };
    use super::super::archive_retained_subjects::retained_subject_rule;
    use super::super::archive_side_dispositions::retained_decl;
    use crate::TimeRange;
    use crate::deletion::DeleteReason;
    use crate::entity_id::EntityId;
    use crate::error::Result;
    use crate::registry::ENTITY_TYPE_PERSON;

    const TABLE: &str = "WEAVE_DIGEST_SETTINGS";

    fn test_time(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    #[test]
    fn hard_delete_removes_the_inert_copies_about_the_record() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        let source_key = p.as_bytes().to_vec();
        let source_value = b"sentinel words".to_vec();
        assert_eq!(
            retained_subject_rule(TABLE)
                .unwrap()
                .records(&source_key, &source_value),
            Some(vec![p]),
            "the fixture names P"
        );
        assert!(
            retained_decl(TABLE).unwrap().actor.is_none(),
            "the fixture table has no actor scrub"
        );
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: source_key.clone(),
            source_value: source_value.clone(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        assert!(
            vault
                .delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?
                .existed,
            "P existed before its hard delete"
        );
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "hard delete removes the inert copy about P: still stored"
        );
        Ok(())
    }

    #[test]
    fn export_keeps_out_a_copy_about_a_hard_deleted_record() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        assert!(
            vault
                .delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?
                .existed,
            "P existed before its hard delete"
        );
        let source_key = p.as_bytes().to_vec();
        let source_value = b"sentinel words".to_vec();
        assert_eq!(
            retained_subject_rule(TABLE)
                .unwrap()
                .records(&source_key, &source_value),
            Some(vec![p]),
            "the fixture names P"
        );
        assert!(
            retained_decl(TABLE).unwrap().actor.is_none(),
            "the fixture table has no actor scrub"
        );
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: source_key.clone(),
            source_value: source_value.clone(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let carried = collect_retained_side_rows_in_txn(&vault, &rtxn)?;
        let mut found = false;
        for row in &carried {
            let carried_envelope = RETAINED_SIDE_ROWS.decode_value(&row.value)?;
            if carried_envelope.source_table == TABLE && carried_envelope.source_key == source_key {
                found = true;
                break;
            }
        }
        assert!(!found, "a copy about a hard-deleted record is not carried");
        Ok(())
    }

    #[test]
    fn an_unrelated_copy_stays_and_is_exported() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let q = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        vault.put_entity(&q, ENTITY_TYPE_PERSON, test_time(11), 11, b"person Q")?;
        let source_key = q.as_bytes().to_vec();
        let source_value = b"sentinel words".to_vec();
        assert_eq!(
            retained_subject_rule(TABLE)
                .unwrap()
                .records(&source_key, &source_value),
            Some(vec![q]),
            "the fixture names Q"
        );
        assert!(
            retained_decl(TABLE).unwrap().actor.is_none(),
            "the fixture table has no actor scrub"
        );
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: source_key.clone(),
            source_value: source_value.clone(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        assert!(
            vault
                .delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?
                .existed,
            "P existed before its hard delete"
        );
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_some(),
            "an unrelated copy stays stored"
        );
        let carried = collect_retained_side_rows_in_txn(&vault, &rtxn)?;
        let mut found = false;
        for row in &carried {
            let carried_envelope = RETAINED_SIDE_ROWS.decode_value(&row.value)?;
            if carried_envelope.source_table == TABLE && carried_envelope.source_key == source_key {
                found = true;
                break;
            }
        }
        assert!(found, "an unrelated copy is exported");
        Ok(())
    }
}
