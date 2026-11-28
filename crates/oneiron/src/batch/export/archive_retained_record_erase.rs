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
/// A copy whose table states no rule stays: the export withholds it already. A room-keyed copy
/// whose value cannot be read goes with its room. Registered once in the delete doors' ERASERS
/// list, so the batch delete, hard purge, soft erase and replayed tombstone all run it, and the
/// delete-scope probe counts copies so a record whose only local state is a copy is still deleted
/// (REVIEW-10618 P1-1).
fn retained_side_row_keys_of_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<[u8; 32]>> {
    let mut erase: Vec<[u8; 32]> = Vec::new();
    for row in RETAINED_SIDE_ROWS.iter_raw_from(store, txn, &[])? {
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
            if super::archive_retained_room_ledgers::retained_row_room(
                &envelope.source_table,
                &envelope.source_key,
            ) == Some(*id)
            {
                erase.push(typed);
            }
            continue;
        };
        if ids.contains(id) {
            erase.push(typed);
        }
    }
    Ok(erase)
}

/// Whether any inert archive copy is about `id`: an inert archive copy about a record is local
/// state its delete erases, so the delete-scope probe counts it (REVIEW-10618 P1-1).
pub(crate) fn retained_side_rows_of_record_exist_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(!retained_side_row_keys_of_record_in_txn(store, txn, id)?.is_empty())
}

pub(crate) fn erase_retained_side_rows_of_record_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let keys = retained_side_row_keys_of_record_in_txn(store, &*wtxn, id)?;
    for key in &keys {
        RETAINED_SIDE_ROWS.delete(store, wtxn, key)?;
    }
    Ok(!keys.is_empty())
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

    const MEMBERSHIP_TABLE: &str = "CONVERSATION_MEMBERSHIP_ROW";

    fn membership_source_key(room: &EntityId, ordinal: u64) -> Vec<u8> {
        let mut key = room.as_bytes().to_vec();
        key.extend_from_slice(&ordinal.to_be_bytes());
        key
    }

    fn membership_join(person: EntityId, actor: EntityId) -> crate::conversation::MembershipRow {
        crate::conversation::MembershipRow {
            v: 2,
            person,
            action: crate::conversation::MembershipAction::Join,
            at: 10,
            actor,
            visible_from: Some(0),
            handoff: None,
        }
    }

    fn encode_membership_row(row: &crate::conversation::MembershipRow) -> Result<Vec<u8>> {
        crate::side_table::SideTable::<
            (EntityId, u64),
            crate::conversation::MembershipRow,
            crate::side_table::Named,
        >::new(&crate::side_table::CONVERSATION_MEMBERSHIP_ROW)
        .encode_value(row)
    }

    fn hard_tombstone_value() -> Vec<u8> {
        crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserHardDelete,
            deleted_at: 1_771_027_200,
            request_id: [0xAB; 16],
        }
        .encode()
        .to_vec()
    }

    fn soft_tombstone_value() -> Vec<u8> {
        crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserDelete,
            deleted_at: 1_771_027_200,
            request_id: [0x5A; 16],
        }
        .encode()
        .to_vec()
    }

    #[test]
    fn hard_delete_of_a_record_known_only_by_an_inert_copy_removes_it() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: p.as_bytes().to_vec(),
            source_value: b"sentinel words".to_vec(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        vault.delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "a hard delete of P removes its only local state, an inert copy: still stored"
        );
        Ok(())
    }

    #[test]
    fn replayed_hard_tombstone_removes_an_inert_copy_of_a_record_never_held_here() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: p.as_bytes().to_vec(),
            source_value: b"sentinel words".to_vec(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        vault.apply_replayed_tombstone(&p, &hard_tombstone_value())?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "a replayed hard tombstone removes the inert copy: still stored"
        );
        Ok(())
    }

    #[test]
    fn soft_delete_of_a_record_known_only_by_an_inert_copy_removes_it() -> Result<()> {
        // A local soft headerless delete does not reach the soft-erase early return; a replayed
        // SOFT tombstone does, so this test replays one (see REPORT).
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: p.as_bytes().to_vec(),
            source_value: b"sentinel words".to_vec(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        vault.apply_replayed_tombstone(&p, &soft_tombstone_value())?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "a replayed soft tombstone removes the inert copy: still stored"
        );
        Ok(())
    }

    #[test]
    fn hard_delete_of_a_person_removes_the_inert_membership_copy_naming_them() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        let r = EntityId::now();
        let value = encode_membership_row(&membership_join(p, p))?;
        assert!(
            crate::conversation::membership_row_named_entities(&value)
                .is_some_and(|named| named.contains(&p)),
            "the fixture names P"
        );
        let envelope = ArchiveRetainedSideRow {
            source_table: MEMBERSHIP_TABLE.to_owned(),
            source_key: membership_source_key(&r, 0),
            source_value: value,
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        vault.delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "hard delete of P removes the inert membership copy naming them: still stored"
        );
        Ok(())
    }

    #[test]
    fn export_keeps_out_a_membership_copy_naming_a_hard_deleted_person() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let q = EntityId::now();
        let r = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        vault.put_entity(&q, ENTITY_TYPE_PERSON, test_time(11), 11, b"person Q")?;
        vault.put_entity(
            &r,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            test_time(12),
            12,
            b"\x80",
        )?;
        vault.delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?;
        let control = ArchiveRetainedSideRow {
            source_table: MEMBERSHIP_TABLE.to_owned(),
            source_key: membership_source_key(&r, 0),
            source_value: encode_membership_row(&membership_join(q, q))?,
            source_live: false,
        };
        let held = ArchiveRetainedSideRow {
            source_table: MEMBERSHIP_TABLE.to_owned(),
            source_key: membership_source_key(&r, 1),
            source_value: encode_membership_row(&membership_join(p, q))?,
            source_live: false,
        };
        let control_key = retained_side_row_key(&control);
        let held_key = retained_side_row_key(&held);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &control_key, &control)?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &held_key, &held)?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let carried = collect_retained_side_rows_in_txn(&vault, &rtxn)?;
        let mut control_found = false;
        let mut held_found = false;
        for row in &carried {
            let e = RETAINED_SIDE_ROWS.decode_value(&row.value)?;
            if e.source_table == MEMBERSHIP_TABLE && e.source_key == control.source_key {
                control_found = true;
            }
            if e.source_table == MEMBERSHIP_TABLE && e.source_key == held.source_key {
                held_found = true;
            }
        }
        assert!(
            control_found,
            "a copy naming live Q in R is exported (control)"
        );
        assert!(!held_found, "a copy naming hard-deleted P is not exported");
        Ok(())
    }

    #[test]
    fn an_unreadable_membership_copy_goes_with_its_room() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let r = EntityId::now();
        vault.put_entity(
            &r,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            test_time(10),
            10,
            b"\x80",
        )?;
        let source_value = b"not a row".to_vec();
        assert!(
            crate::conversation::membership_row_named_entities(&source_value).is_none(),
            "the fixture value does not decode"
        );
        let envelope = ArchiveRetainedSideRow {
            source_table: MEMBERSHIP_TABLE.to_owned(),
            source_key: membership_source_key(&r, 0),
            source_value,
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        vault.delete_entity_with_reason(&r, DeleteReason::UserHardDelete)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "hard delete of R removes its unreadable membership copy: still stored"
        );
        Ok(())
    }

    #[test]
    fn a_delete_of_a_record_known_only_by_an_inert_copy_answers_that_it_existed() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: p.as_bytes().to_vec(),
            source_value: b"sentinel words".to_vec(),
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
            "P existed as an inert copy even without an entity header"
        );
        Ok(())
    }

    #[test]
    fn a_soft_replay_of_a_record_known_only_by_an_inert_copy_reports_a_change() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let envelope = ArchiveRetainedSideRow {
            source_table: TABLE.to_owned(),
            source_key: p.as_bytes().to_vec(),
            source_value: b"sentinel words".to_vec(),
            source_live: false,
        };
        let key = retained_side_row_key(&envelope);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &key, &envelope)?;
        wtxn.commit()?;
        let outcome = vault.apply_replayed_tombstone(&p, &soft_tombstone_value())?;
        assert!(
            matches!(
                outcome,
                crate::deletion::ReplayedTombstoneOutcome::SoftErased { changed: true }
            ),
            "removing P's only local state, an inert copy, counts as a change"
        );
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            RETAINED_SIDE_ROWS.get(&vault, &rtxn, &key)?.is_none(),
            "the replay removed the inert copy"
        );
        Ok(())
    }

    #[test]
    fn a_former_members_hard_delete_keeps_a_live_room_ledger_exported() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let p = EntityId::now();
        let q = EntityId::now();
        let r = EntityId::now();
        vault.put_entity(&p, ENTITY_TYPE_PERSON, test_time(10), 10, b"person P")?;
        vault.put_entity(&q, ENTITY_TYPE_PERSON, test_time(11), 11, b"person Q")?;
        let actor = crate::WriteActor::new(q, crate::EdgeActorClass::Human);
        vault.create_conversation(
            r,
            &crate::conversation::ConversationBody::default(),
            actor,
            12,
        )?;
        vault.join_member(r, p, actor, 13, crate::conversation::HistoryChoice::Share)?;
        vault.join_member(r, q, actor, 14, crate::conversation::HistoryChoice::Share)?;
        vault.leave_member(r, p, actor, 15)?;
        vault.delete_entity_with_reason(&p, DeleteReason::UserHardDelete)?;

        let held = ArchiveRetainedSideRow {
            source_table: MEMBERSHIP_TABLE.to_owned(),
            source_key: membership_source_key(&r, 3),
            source_value: encode_membership_row(&membership_join(p, q))?,
            source_live: false,
        };
        let held_key = retained_side_row_key(&held);
        let mut wtxn = vault.store.env.write_txn()?;
        RETAINED_SIDE_ROWS.put(&vault, &mut wtxn, &held_key, &held)?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let carried = collect_retained_side_rows_in_txn(&vault, &rtxn)?;
        let mut live_ledger_rows = 0;
        let mut held_found = false;
        for row in &carried {
            let e = RETAINED_SIDE_ROWS.decode_value(&row.value)?;
            if e.source_table == MEMBERSHIP_TABLE
                && e.source_live
                && e.source_key.starts_with(r.as_bytes())
            {
                live_ledger_rows += 1;
            }
            if e == held {
                held_found = true;
            }
        }
        assert!(
            live_ledger_rows > 0,
            "R's live ledger is exported though a former member was hard-deleted"
        );
        assert!(
            !held_found,
            "an inert copy naming hard-deleted P is not exported"
        );
        Ok(())
    }
}
