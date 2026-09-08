use super::*;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::encode_claim_body;
use crate::off_record::{OffRecordBackendClass, OffRecordSession};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::session_overlay::{
    JournalEntry, JournalRole, JournalScope, OverlayKeyspace, SessionOverlay, SnapshotLookup,
};
use std::sync::Arc;

fn put_entry(scope: JournalScope, id: EntityId, kind: u8, data: Vec<u8>) -> JournalEntry {
    let occurred = TimeRange {
        start: 100,
        end: 100,
    };
    JournalEntry {
        scope,
        role: JournalRole::TurnOwnedArtifact,
        learned_at: 100,
        occurred,
        op: BatchOp::Put {
            id,
            entity_type: kind,
            occurred,
            learned_at: 100,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        },
    }
}

fn assert_session_rows(
    overlay: &Arc<SessionOverlay>,
    expected: &[JournalEntry],
    published: bool,
) -> Result<()> {
    let snapshot = overlay.snapshot()?;
    for keyspace in [
        OverlayKeyspace::Entities,
        OverlayKeyspace::TypeIndex,
        OverlayKeyspace::TemporalOccurredStart,
        OverlayKeyspace::TemporalLearned,
    ] {
        assert_eq!(snapshot.row_count(keyspace), expected.len(), "{keyspace:?}");
    }
    assert_eq!(snapshot.row_count(OverlayKeyspace::TemporalOccurredEnd), 0);
    assert_eq!(
        snapshot.row_count(OverlayKeyspace::TemporalLongIntervals),
        0
    );
    // Row mutations update the active segment's preview. Its journal remains
    // separate until TxnSegmentGuard::commit publishes both. Check the exact
    // successful journal prefix after commit, not through the row preview.
    let journal = snapshot.journal_entries();
    assert_eq!(journal.len(), if published { expected.len() } else { 0 });
    for (index, entry) in expected.iter().enumerate() {
        let BatchOp::Put {
            id,
            entity_type,
            data,
            ..
        } = &entry.op
        else {
            panic!("fixture must contain only puts");
        };
        let SnapshotLookup::Present(raw) =
            snapshot.lookup_single(OverlayKeyspace::Entities, id.as_bytes())
        else {
            panic!("expected staged entity {id:?}");
        };
        let header = EntityMetadataHeader::parse(&raw).expect("entity header");
        assert_eq!(header.entity_type, *entity_type);
        assert_eq!(header.occurred_start, entry.occurred.start);
        assert_eq!(header.occurred_end, entry.occurred.end);
        assert_eq!(header.learned_at, entry.learned_at);
        assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], data.as_slice());
        if published {
            let actual = &journal[index];
            assert_eq!(actual.scope, entry.scope);
            assert_eq!(actual.role, entry.role);
            assert_eq!(actual.occurred, entry.occurred);
            assert_eq!(actual.learned_at, entry.learned_at);
            let BatchOp::Put {
                id: actual_id,
                entity_type: actual_type,
                data: actual_data,
                ..
            } = &actual.op
            else {
                panic!("journal must preserve put operations");
            };
            assert_eq!(actual_id, id);
            assert_eq!(actual_type, entity_type);
            assert_eq!(actual_data, data);
        }
    }
    Ok(())
}

fn check_session_program(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    entries: Vec<JournalEntry>,
    staged_count: usize,
    accepted: bool,
) -> Result<()> {
    let route = session.write_route()?;
    let overlay = session.overlay();
    // First prove rollback. Then repeat the identical program and deliberately
    // commit its successful prefix, even on rejection, to prove that the
    // rejected claim was never journaled. Neither assertion relies on abort
    // hiding an incorrectly staged claim or on a committed-only journal read.
    for commit in [false, true] {
        let mut txn = vault.store.env.write_txn()?;
        let segment = overlay.install_txn_segment()?;
        let view = session.read_view()?;
        let BatchOp::Put { id: first_id, .. } = &entries[0].op else {
            panic!("fixture must contain only puts");
        };
        let before = view
            .entities
            .get(&txn, first_id.as_bytes())?
            .map(std::borrow::Cow::into_owned);
        let result = crate::batch::apply_ops_session(
            &view,
            &route,
            &vault.config,
            &vault.analyzer,
            &mut txn,
            entries.clone(),
        );
        // Admission refreshes its own entity accessor, never a logical read
        // view that a caller already holds.
        assert_eq!(
            view.entities.get(&txn, first_id.as_bytes())?.as_deref(),
            before.as_deref(),
        );
        drop(view);
        if accepted {
            result?;
        } else {
            assert!(matches!(result, Err(Error::InvalidClaimBody(_))));
        }
        assert_session_rows(&overlay, &entries[..staged_count], false)?;
        if commit {
            txn.commit()?;
            segment.commit()?;
        } else {
            drop(segment);
            drop(txn);
        }
        let expected = if commit {
            &entries[..staged_count]
        } else {
            &[]
        };
        assert_session_rows(&overlay, expected, true)?;
    }
    Ok(())
}

#[test]
fn anchor_session_admission_checks_both_base_and_overlay_dependencies() -> Result<()> {
    for (overlay_actor, overlay_subject) in
        [(false, false), (true, true), (false, true), (true, false)]
    {
        for (actor_kind, subject_kind, malformed, accepted) in [
            (None, Some(ENTITY_TYPE_PERSON), false, false),
            (Some(ENTITY_TYPE_PERSON), None, false, false),
            (
                Some(ENTITY_TYPE_ORG),
                Some(ENTITY_TYPE_PERSON),
                false,
                false,
            ),
            (
                Some(ENTITY_TYPE_PERSON),
                Some(ENTITY_TYPE_PLACE),
                false,
                false,
            ),
            (
                Some(ENTITY_TYPE_PERSON),
                Some(ENTITY_TYPE_PERSON),
                true,
                false,
            ),
            (
                Some(ENTITY_TYPE_PERSON),
                Some(ENTITY_TYPE_PERSON),
                false,
                true,
            ),
            (Some(ENTITY_TYPE_PERSON), Some(ENTITY_TYPE_ORG), false, true),
        ] {
            let (_dir, vault) = test_vault();
            let actor = entity(0xB1);
            let subject = entity(0xB2);
            let id = entity(0xB3);
            let dependencies = [
                (actor, actor_kind, overlay_actor),
                (subject, subject_kind, overlay_subject),
            ];
            for (id, kind, in_overlay) in dependencies {
                if let Some(kind) = kind.filter(|_| !in_overlay) {
                    seed(&vault, id, kind);
                }
            }
            let session = vault
                .off_record_session_vault()
                .enter("anchor-admission", OffRecordBackendClass::Local)?;
            let scope = JournalScope::new(entity(0xB4), id);
            let mut entries = Vec::new();
            for (id, kind, in_overlay) in dependencies {
                if let Some(kind) = kind.filter(|_| in_overlay) {
                    entries.push(put_entry(scope, id, kind, b"dependency".to_vec()));
                }
            }
            let dependency_count = entries.len();
            let value = if malformed {
                Value::Nil
            } else {
                Value::from(subject.to_hex())
            };
            let body = subject_fact(PREDICATE_ACTOR_SUBJECT_REF, actor, value, writer(), 100);
            entries.push(put_entry(
                scope,
                id,
                ENTITY_TYPE_CLAIM,
                encode_claim_body(&body)?,
            ));
            check_session_program(
                &vault,
                &session,
                entries,
                dependency_count + usize::from(accepted),
                accepted,
            )?;
            assert_eq!(
                session
                    .read_view()?
                    .entities
                    .get(&vault.store.env.read_txn()?, id.as_bytes())?
                    .is_some(),
                accepted,
            );
            assert!(vault.get(&id)?.is_none());
            for (dependency, _, in_overlay) in dependencies {
                if in_overlay {
                    assert!(vault.get(&dependency)?.is_none());
                }
            }
            session.close()?;
        }
    }
    Ok(())
}

#[test]
fn anchor_session_admission_observes_only_earlier_dependency_ops() -> Result<()> {
    for order in [
        [0, 1, 2],
        [1, 0, 2],
        [0, 2, 1],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let (_dir, vault) = test_vault();
        let actor = entity(0xB1);
        let subject = entity(0xB2);
        let id = entity(0xB3);
        let session = vault
            .off_record_session_vault()
            .enter("anchor-order", OffRecordBackendClass::Local)?;
        let scope = JournalScope::new(entity(0xB4), id);
        let body = subject_fact(
            PREDICATE_ACTOR_SUBJECT_REF,
            actor,
            Value::from(subject.to_hex()),
            writer(),
            100,
        );
        let ops = [
            put_entry(scope, actor, ENTITY_TYPE_PERSON, b"actor".to_vec()),
            put_entry(scope, subject, ENTITY_TYPE_PERSON, b"subject".to_vec()),
            put_entry(scope, id, ENTITY_TYPE_CLAIM, encode_claim_body(&body)?),
        ];
        let claim_position = order.iter().position(|op| *op == 2).expect("claim op");
        let accepted = claim_position == 2;
        let staged_count = if accepted { 3 } else { claim_position };
        let entries = order.into_iter().map(|op| ops[op].clone()).collect();
        check_session_program(&vault, &session, entries, staged_count, accepted)?;
        for entity in [actor, subject, id] {
            assert!(vault.get(&entity)?.is_none());
        }
        session.close()?;
    }
    Ok(())
}

#[test]
fn substrate_session_admission_observes_only_earlier_person_ops() -> Result<()> {
    for person_first in [false, true] {
        for kind in [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG] {
            let (_dir, vault) = test_vault();
            let person = entity(0xB1);
            let id = entity(0xB3);
            let session = vault
                .off_record_session_vault()
                .enter("substrate-order", OffRecordBackendClass::Local)?;
            let scope = JournalScope::new(entity(0xB4), id);
            let body = subject_fact(
                PREDICATE_PERSON_SUBSTRATE,
                person,
                Value::from("model"),
                writer(),
                100,
            );
            let dependency = put_entry(scope, person, kind, b"person".to_vec());
            let claim = put_entry(scope, id, ENTITY_TYPE_CLAIM, encode_claim_body(&body)?);
            let entries = if person_first {
                vec![dependency, claim]
            } else {
                vec![claim, dependency]
            };
            let accepted = person_first && kind == ENTITY_TYPE_PERSON;
            let staged_count = usize::from(person_first) + usize::from(accepted);
            check_session_program(&vault, &session, entries, staged_count, accepted)?;
            assert!(vault.get(&person)?.is_none());
            assert!(vault.get(&id)?.is_none());
            session.close()?;
        }
    }
    Ok(())
}

#[test]
fn anchor_session_admission_honors_overlay_masks_over_base_dependencies() -> Result<()> {
    for mask_actor in [false, true] {
        for tombstone in [false, true] {
            let (_dir, vault) = test_vault();
            let actor = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);
            let subject = seed(&vault, entity(0xB2), ENTITY_TYPE_PERSON);
            let id = entity(0xB3);
            let masked = if mask_actor { actor } else { subject };
            let base_row = vault.get(&masked)?;
            let session = vault
                .off_record_session_vault()
                .enter("anchor-mask", OffRecordBackendClass::Local)?;
            let scope = JournalScope::new(entity(0xB4), id);
            let body = subject_fact(
                PREDICATE_ACTOR_SUBJECT_REF,
                actor,
                Value::from(subject.to_hex()),
                writer(),
                100,
            );
            let claim = put_entry(scope, id, ENTITY_TYPE_CLAIM, encode_claim_body(&body)?);
            if tombstone {
                let route = session.write_route()?;
                let overlay = session.overlay();
                let view = session.read_view()?;
                let mut txn = vault.store.env.write_txn()?;
                let segment = overlay.install_txn_segment()?;
                overlay.delete(OverlayKeyspace::Entities, masked.as_bytes())?;
                assert!(view.entities.get(&txn, masked.as_bytes())?.is_some());
                let result = crate::batch::apply_ops_session(
                    &view,
                    &route,
                    &vault.config,
                    &vault.analyzer,
                    &mut txn,
                    vec![claim],
                );
                assert!(matches!(result, Err(Error::InvalidClaimBody(_))));
                assert_session_rows(&overlay, &[], false)?;
                drop(view);
                drop(segment);
                drop(txn);
                assert_session_rows(&overlay, &[], true)?;
            } else {
                // A known wrong overlay type must not borrow the valid base
                // header visible through the caller's older logical read view.
                let kind = if mask_actor {
                    ENTITY_TYPE_ORG
                } else {
                    ENTITY_TYPE_PLACE
                };
                let dependency = put_entry(scope, masked, kind, b"wrong type".to_vec());
                check_session_program(&vault, &session, vec![dependency, claim], 1, false)?;
            }
            assert_eq!(vault.get(&masked)?, base_row);
            assert!(vault.get(&id)?.is_none());
            session.close()?;
        }
    }
    Ok(())
}
