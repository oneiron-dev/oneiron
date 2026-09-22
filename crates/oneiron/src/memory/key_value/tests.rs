//! Behavior proofs through the real facade and production gate.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::tests::{append_actor_ceiling_rows, open_vault, put_person};
use serde_json::json;

fn address(namespace: &[&str], key: &str) -> KeyValueAddress {
    KeyValueAddress {
        namespace: namespace.iter().map(|s| (*s).to_owned()).collect(),
        key: key.to_owned(),
    }
}
fn input(namespace: &[&str], key: &str, request_id: &str, n: u64) -> KeyValuePut {
    let address = address(namespace, key);
    KeyValuePut {
        namespace: address.namespace,
        key: address.key,
        request_id: request_id.to_owned(),
        value: json!({"n": n}),
        source: "user_stated".to_owned(),
    }
}

#[test]
fn exact_actor_keys_replace_replay_delete_without_resurrection() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 91);
    let other = put_person(&vault, 92);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let outsider = vault.memory(other, EdgeActorClass::Human);
    let key = address(&["a", "b"], "k");
    assert_eq!(memory.key_value_get(&key).unwrap(), None);
    let first = memory
        .key_value_put(&input(&["a", "b"], "k", "one", 1))
        .unwrap();
    assert_eq!(
        memory
            .key_value_put(&input(&["a", "b"], "k", "one", 1))
            .unwrap()
            .item,
        first.item
    );
    assert!(
        memory
            .key_value_put(&input(&["a", "b"], "k", "one", 1))
            .unwrap()
            .replayed
    );
    assert_eq!(
        memory
            .key_value_put(&input(&["a", "b"], "k", "one", 2))
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(outsider.key_value_get(&key).unwrap(), None);
    assert!(!outsider.key_value_delete(&key).unwrap().existed);
    let other_value = outsider
        .key_value_put(&input(&["a", "b"], "k", "one", 9))
        .unwrap();
    assert_ne!(first.item.revision, other_value.item.revision);
    let second = memory
        .key_value_put(&input(&["a", "b"], "k", "two", 2))
        .unwrap();
    assert_ne!(first.item.revision, second.item.revision);
    assert_eq!(first.item.created_at, second.item.created_at);
    assert_eq!(
        memory.key_value_get(&key).unwrap().unwrap().value,
        json!({"n":2})
    );
    assert!(memory.key_value_delete(&key).unwrap().existed);
    assert!(!memory.key_value_delete(&key).unwrap().existed);
    assert_eq!(memory.key_value_get(&key).unwrap(), None);
    assert_eq!(
        memory
            .key_value_put(&input(&["a", "b"], "k", "two", 2))
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(
        outsider.key_value_get(&key).unwrap().unwrap().value,
        json!({"n":9})
    );
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&second.item.revision).unwrap())
            .unwrap()
            .unwrap()
            .lifecycle,
        ClaimLifecycleStatus::Retracted
    );
}

#[test]
fn exact_prefix_filter_and_namespace_pages_follow_live_keys() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 93);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    for (ns, key, n) in [
        (vec!["a", "b"], "a", 1),
        (vec!["a", "b"], "b", 2),
        (vec!["a", "bc"], "c", 2),
        (vec!["ab"], "d", 2),
    ] {
        memory.key_value_put(&input(&ns, key, key, n)).unwrap();
    }
    let page = memory
        .key_value_search(&KeyValueSearch {
            namespace_prefix: vec!["a".into()],
            filter: Some(json!({"n":2}).as_object().unwrap().clone()),
            limit: 1,
            offset: 1,
        })
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].key, "c");
    let exact = memory
        .key_value_search(&KeyValueSearch {
            namespace_prefix: vec!["a".into(), "b".into()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        exact
            .iter()
            .map(|item| item.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    let namespaces = memory
        .key_value_namespaces(&KeyValueNamespaces {
            prefix: vec!["a".into()],
            max_depth: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(namespaces, vec![vec!["a".to_owned()]]);
    memory.key_value_delete(&address(&["a", "b"], "a")).unwrap();
    memory.key_value_delete(&address(&["a", "b"], "b")).unwrap();
    assert_eq!(
        memory
            .key_value_namespaces(&KeyValueNamespaces {
                prefix: vec!["a".into()],
                ..Default::default()
            })
            .unwrap(),
        vec![vec!["a".to_owned(), "bc".to_owned()]]
    );
    assert!(
        memory
            .key_value_search(&KeyValueSearch {
                limit: 0,
                ..Default::default()
            })
            .is_err()
    );
    assert!(memory.key_value_get(&address(&["*"], "k")).is_err());
}

#[test]
fn gate_refusal_preserves_current_value_and_never_parks_a_replacement() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 94);
    append_actor_ceiling_rows(
        &vault,
        vec![("agent".into(), actor.to_hex(), "auto".into())],
    );
    let memory = vault.memory(actor, EdgeActorClass::Agent);
    let mut first = input(&["private"], "k", "allowed", 1);
    first.source = "observed".into();
    memory.key_value_put(&first).unwrap();
    let before = memory.pending_writes(100).unwrap();
    append_actor_ceiling_rows(
        &vault,
        vec![("agent".into(), actor.to_hex(), "proposed".into())],
    );
    let mut refused = first;
    refused.request_id = "requires-review".into();
    refused.value = json!({"n":2});
    assert!(memory.key_value_put(&refused).is_err());
    assert_eq!(
        memory
            .key_value_get(&address(&["private"], "k"))
            .unwrap()
            .unwrap()
            .value,
        json!({"n":1})
    );
    assert_eq!(memory.pending_writes(100).unwrap(), before);
    assert_eq!(
        vault
            .memory(actor, EdgeActorClass::Human)
            .key_value_get(&address(&["private"], "k"))
            .unwrap(),
        None
    );
}

#[test]
fn generic_claim_upsert_cannot_close_another_actors_key() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 95);
    let other = put_person(&vault, 96);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .key_value_put(&input(&["private"], "k", "one", 1))
        .unwrap();
    let body = vault
        .get_claim(&EntityId::from_hex(&receipt.item.revision).unwrap())
        .unwrap()
        .unwrap();
    let mut forged = crate::memory::tests::claim_input(
        PREDICATE,
        &owner,
        "user_stated",
        companion_value_to_json(&body.value),
    );
    forged.scope = body.scope.as_ref().map(companion_value_to_json);
    assert_eq!(
        vault
            .memory(other, EdgeActorClass::Human)
            .claim_upsert(&forged)
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
    forged.id = Some(receipt.item.revision.clone());
    forged.predicate = "test.disguised".into();
    assert!(
        vault
            .memory(other, EdgeActorClass::Human)
            .claim_upsert(&forged)
            .is_err()
    );
    assert_eq!(
        memory.key_value_get(&address(&["private"], "k")).unwrap(),
        Some(receipt.item)
    );
}

#[test]
fn canonical_demotion_does_not_turn_exact_keys_into_recall_results() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 97);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let receipt = memory
        .key_value_put(&input(&["long_term"], "k", "one", 1))
        .unwrap();
    let id = EntityId::from_hex(&receipt.item.revision).unwrap();
    vault
        .apply_claim_demotion(
            &id,
            crate::claim::ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.1,
            },
            crate::unix_seconds_now(),
        )
        .unwrap();
    assert_eq!(
        memory.key_value_get(&address(&["long_term"], "k")).unwrap(),
        Some(receipt.item)
    );
    assert!(
        memory
            .key_value_delete(&address(&["long_term"], "k"))
            .unwrap()
            .existed
    );
}

// Privileged fixture door only: replay an ABI-valid but potentially malformed
// keyed payload. App-tier generic writers must never be able to do this.
fn replay_keyed_body(vault: &crate::Vault, id: EntityId, body: &ClaimBody) {
    let bytes = crate::claim::encode_claim_body(body).unwrap();
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &bytes,
        )
        .commit()
        .unwrap();
}

#[test]
fn keyed_bodies_never_surface_through_generic_facade_scoped_or_pack_reads() {
    use crate::claim::ScopedReadActorKey;
    use crate::edge::EdgeKind;
    use crate::memory::{
        ClaimListFilter, Effort, MEMORY_CODE_NOT_FOUND, NeighborOpts, RecallScope,
    };

    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 101);
    let other = put_person(&vault, 102);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut request = input(&["private"], "canary", "old", 1);
    request.value = json!({"privatecanary": "do not disclose"});
    let old = memory.key_value_put(&request).unwrap();
    request.request_id = "current".into();
    let current = memory.key_value_put(&request).unwrap();
    let id = EntityId::from_hex(&current.item.revision).unwrap();
    let reference = memory.short_ref_or_hex(&id).unwrap();
    let (short, hash) = reference.split_once(':').unwrap();
    let hash = u8::from_str_radix(hash, 16).unwrap();
    // Make the exact-store row reachable by hostile/old indexes and graph
    // edges. A no-hit assertion on an unindexed row would miss the regression.
    vault
        .batch()
        .text(&id, &[("content", "privatecanary")])
        .text(&owner, &[("content", "publicanchor")])
        .edge(&owner, EdgeKind::Attached, &id, 1.0)
        .commit()
        .unwrap();
    assert!(
        vault
            .search_text("privatecanary", 10)
            .unwrap()
            .iter()
            .any(|hit| hit.id == id)
    );
    // Raw systems history is deliberately unchanged.
    assert!(vault.get_claim(&id).unwrap().is_some());
    assert!(
        vault
            .get_claim(&EntityId::from_hex(&old.item.revision).unwrap())
            .unwrap()
            .is_some()
    );

    for actor in [owner, other] {
        let facade = vault.memory(actor, EdgeActorClass::Human);
        for subject_ref in [None, Some(owner.to_hex())] {
            assert!(
                facade
                    .claim_list(&ClaimListFilter {
                        subject_ref,
                        predicate: Some(PREDICATE.into()),
                        limit: 100,
                        ..Default::default()
                    })
                    .unwrap()
                    .is_empty()
            );
        }
        for revision in [&old.item.revision, &current.item.revision] {
            assert!(facade.get_entity(revision).unwrap().is_none());
            assert_eq!(
                facade
                    .hydrate(std::slice::from_ref(revision))
                    .unwrap_err()
                    .code,
                MEMORY_CODE_NOT_FOUND
            );
            assert!(facade.claim_history(revision).unwrap().is_empty());
        }
        assert!(facade.get_entity(&owner.to_hex()).unwrap().is_some());
        assert!(facade.query_bm25("privatecanary", 10).unwrap().is_empty());
        assert!(
            facade
                .neighbors(
                    &owner.to_hex(),
                    &NeighborOpts {
                        edge_kind: Some("attached".into()),
                        limit: 10,
                        ..Default::default()
                    }
                )
                .unwrap()
                .is_empty()
        );
        for effort in [Effort::Light, Effort::Medium] {
            let pack = facade
                .recall(
                    "privatecanary",
                    effort,
                    &RecallScope::default(),
                    10,
                    None,
                    None,
                )
                .unwrap();
            assert!(
                pack.items
                    .iter()
                    .all(|item| item.predicate.as_deref() != Some(PREDICATE))
            );
        }
        let scoped = vault
            .scoped_read(ScopedReadActorKey::with_actor_class(actor.to_hex(), "human").unwrap());
        assert!(scoped.get(&id).unwrap().is_none());
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = scoped.get_entity_parts_with_receipt(&id, None).unwrap();
        assert!(value.is_none());
        assert!(scoped.hydrate_short_id(short, hash).unwrap().is_none());
        assert!(scoped.memory_timeline(&id).unwrap().records.is_empty());
        assert!(!scoped.is_entity_readable(&id).unwrap());
        assert!(
            scoped
                .search_text("privatecanary", 10, None)
                .unwrap()
                .is_empty()
        );
        assert!(
            scoped
                .edges_out(&owner)
                .unwrap()
                .value
                .unwrap_or_default()
                .iter()
                .all(|edge| edge.target != id)
        );
    }
    assert_eq!(
        memory
            .key_value_get(&address(&["private"], "canary"))
            .unwrap(),
        Some(current.item)
    );
    assert!(
        vault
            .memory(other, EdgeActorClass::Human)
            .key_value_get(&address(&["private"], "canary"))
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .query()
            .search_text("privatecanary", 10)
            .run()
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .query()
            .search_ppr(&[id], 1)
            .run()
            .unwrap()
            .iter()
            .all(|hit| hit.id != id)
    );
    let mut filter = crate::gate::ResolvedRetrievalFilter {
        entity_types: None,
        max_sensitivity_band: 3,
        include_stale: true,
        min_confidence: 0.0,
        min_salience: 0.0,
        deny_all: false,
    };
    for include_stale in [false, true] {
        filter.include_stale = include_stale;
        assert!(
            vault
                .query()
                .authority_filter(filter.clone())
                .search_text("privatecanary", 10)
                .run()
                .unwrap()
                .is_empty()
        );
    }
    let pack = vault
        .context_pack()
        .search_text("privatecanary", 10)
        .run()
        .unwrap();
    assert!(pack.results.is_empty());
    let pack = vault
        .context_pack()
        .search_text("publicanchor", 10)
        .edge_hop(1)
        .include_edges(true)
        .max_neighbors(20)
        .run()
        .unwrap();
    assert!(pack.results.iter().any(|entity| entity.id == owner));
    assert!(
        pack.results
            .iter()
            .chain(&pack.neighbors)
            .all(|entity| entity.id != id)
    );
}

#[test]
fn imported_claims_cannot_create_or_disguise_overwrites_of_keyed_revisions() {
    use crate::ingest::{
        ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
        admit_imported_evidence_claim_typed,
    };
    use crate::memory::AdmitImportedClaimInput;
    use crate::write_envelope::WriteActor;
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 103);
    let other = put_person(&vault, 104);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .key_value_put(&input(&["private"], "k", "one", 1))
        .unwrap();
    let id = EntityId::from_hex(&receipt.item.revision).unwrap();
    let before = vault.get_raw(&id).unwrap().unwrap();
    let before_receipts = memory.receipts(100).unwrap();
    for predicate in ["test.disguised", PREDICATE] {
        let err = vault
            .memory(other, EdgeActorClass::Human)
            .admit_imported_claim(&AdmitImportedClaimInput {
                source_id: "meeting-transcript".into(),
                source_record_id: "forged".into(),
                id: Some(id.to_hex()),
                subject_ref: owner.to_hex(),
                predicate: predicate.into(),
                value: json!({"malformed": true}),
                occurred_at: 100,
                learned_at: None,
            })
            .unwrap_err();
        assert_eq!(err.code, MEMORY_CODE_INVALID_STATE);
        let admission = ImportedEvidenceAdmission::proposed(
            "meeting-transcript",
            id,
            ImportedEvidenceEntityResolution::subject(owner),
            WriteActor::new(other, EdgeActorClass::Human),
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
        );
        let err = admit_imported_evidence_claim_typed(
            &vault,
            predicate,
            rmpv::Value::Nil,
            "forged",
            &admission,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Claim(crate::error::ClaimError::KeyValueWriteRequiresOwnedDoor)
        ));
        assert_eq!(vault.get_raw(&id).unwrap().unwrap(), before);
        assert_eq!(
            memory.key_value_get(&address(&["private"], "k")).unwrap(),
            Some(receipt.item.clone())
        );
    }
    let fresh = EntityId::now();
    let admission = ImportedEvidenceAdmission::proposed(
        "meeting-transcript",
        fresh,
        ImportedEvidenceEntityResolution::subject(owner),
        WriteActor::new(other, EdgeActorClass::Human),
        crate::temporal::TimeRange {
            start: 100,
            end: 100,
        },
        100,
    );
    assert!(matches!(
        admit_imported_evidence_claim_typed(
            &vault,
            PREDICATE,
            rmpv::Value::Nil,
            "forged",
            &admission
        ),
        Err(Error::Claim(
            crate::error::ClaimError::KeyValueWriteRequiresOwnedDoor
        ))
    ));
    assert!(vault.get_raw(&fresh).unwrap().is_none());
    assert_eq!(memory.receipts(100).unwrap(), before_receipts);
}

#[test]
fn duplicate_actor_or_class_evidence_never_selects_an_owner() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 105);
    let other = put_person(&vault, 106);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .key_value_put(&input(&["private"], "k", "one", 1))
        .unwrap();
    let id = EntityId::from_hex(&receipt.item.revision).unwrap();
    let original = vault.get_claim(&id).unwrap().unwrap();
    for (key, wrong) in [
        (
            WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
            rmpv::Value::Binary(other.as_bytes().to_vec()),
        ),
        (
            WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY,
            rmpv::Value::from(EdgeActorClass::Agent as u8),
        ),
    ] {
        for duplicate_matches in [false, true] {
            let mut body = original.clone();
            let Some(rmpv::Value::Map(entries)) = &mut body.evidence else {
                panic!("evidence map")
            };
            let duplicate = if duplicate_matches {
                entries
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .unwrap()
                    .1
                    .clone()
            } else {
                wrong.clone()
            };
            entries.push((rmpv::Value::from(key), duplicate));
            replay_keyed_body(&vault, id, &body);
            assert!(
                memory
                    .key_value_get(&address(&["private"], "k"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                memory
                    .key_value_search(&KeyValueSearch::default())
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn erased_shells_do_not_wedge_other_keys_or_replay_the_erased_request() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 107);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let request = input(&["private"], "erased", "one", 1);
    let erased = memory.key_value_put(&request).unwrap();
    let kept = memory
        .key_value_put(&input(&["private"], "kept", "one", 2))
        .unwrap();
    memory
        .safe_delete(
            &erased.item.revision,
            crate::memory::SafeDeleteReason::UserDelete,
        )
        .unwrap();
    let id = EntityId::from_hex(&erased.item.revision).unwrap();
    let shell = vault.get_raw(&id).unwrap().unwrap();
    assert!(
        memory
            .key_value_get(&address(&["private"], "erased"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        memory
            .key_value_get(&address(&["private"], "kept"))
            .unwrap(),
        Some(kept.item)
    );
    assert_eq!(
        memory
            .key_value_search(&KeyValueSearch::default())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        memory
            .key_value_namespaces(&KeyValueNamespaces::default())
            .unwrap(),
        vec![vec!["private".to_owned()]]
    );
    assert_eq!(
        memory.key_value_put(&request).unwrap_err().code,
        MEMORY_CODE_INVALID_STATE
    );
    memory
        .key_value_put(&input(&["private"], "kept", "two", 3))
        .unwrap();
    assert!(
        !memory
            .key_value_delete(&address(&["private"], "erased"))
            .unwrap()
            .existed
    );
    assert_eq!(vault.get_raw(&id).unwrap().unwrap(), shell);
}

#[test]
fn malformed_keyed_payloads_are_absent_without_fallback_to_superseded_values() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 108);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory
        .key_value_put(&input(&["private"], "broken", "old", 1))
        .unwrap();
    let request = input(&["private"], "broken", "current", 2);
    let current = memory.key_value_put(&request).unwrap();
    let id = EntityId::from_hex(&current.item.revision).unwrap();
    let original = vault.get_claim(&id).unwrap().unwrap();
    memory
        .key_value_put(&input(&["private"], "kept", "one", 10))
        .unwrap();
    let mut malformed = Vec::new();
    for value in [
        json!({"namespace": ["private"], "key": "broken", "value": [], "created_at": 1, "request_id": "current"}),
        json!({"namespace": [], "key": "broken", "value": {}, "created_at": 1, "request_id": "current"}),
        json!({"not_a_stored_value": true}),
    ] {
        let mut body = original.clone();
        body.value = json_to_rmpv(&value);
        malformed.push(body);
    }
    let mut bad_rung = original;
    let Some(rmpv::Value::Map(entries)) = &mut bad_rung.scope else {
        panic!("scope")
    };
    entries.push((
        rmpv::Value::from(crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        rmpv::Value::from("invalid"),
    ));
    malformed.push(bad_rung);
    for (n, body) in malformed.iter().enumerate() {
        replay_keyed_body(&vault, id, body);
        assert!(
            memory
                .key_value_get(&address(&["private"], "broken"))
                .unwrap()
                .is_none()
        );
        let page = memory.key_value_search(&KeyValueSearch::default()).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].key, "kept");
        assert!(
            memory
                .key_value_get(&address(&["private"], "kept"))
                .unwrap()
                .is_some()
        );
        memory
            .key_value_put(&input(&["private"], "kept", &format!("next-{n}"), 11))
            .unwrap();
        assert!(
            !memory
                .key_value_delete(&address(&["private"], "broken"))
                .unwrap()
                .existed
        );
        assert_eq!(
            memory.key_value_put(&request).unwrap_err().code,
            MEMORY_CODE_INVALID_STATE
        );
    }
    // An invalid CLAIM frame, not merely an invalid StoredValue, has the
    // same per-row exclusion. Storage errors still propagate normally.
    vault
        .with_write_txn(|txn| {
            let mut raw = vault.get_raw_in(txn, &id)?.unwrap();
            raw.truncate(crate::batch::ENTITY_METADATA_HEADER_LEN);
            raw.push(0xc0); // MessagePack nil, not a claim map.
            vault.store.entities.put(txn, id.as_bytes(), &raw)?;
            Ok(())
        })
        .unwrap();
    assert!(
        memory
            .key_value_get(&address(&["private"], "broken"))
            .unwrap()
            .is_none()
    );
    assert!(
        memory
            .key_value_get(&address(&["private"], "kept"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn competing_valid_heads_still_fail_loudly_without_picking_a_winner() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 109);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .key_value_put(&input(&["private"], "k", "one", 1))
        .unwrap();
    let body = vault
        .get_claim(&EntityId::from_hex(&receipt.item.revision).unwrap())
        .unwrap()
        .unwrap();
    let competing = EntityId::now();
    replay_keyed_body(&vault, competing, &body);
    vault
        .batch()
        .edge(&competing, crate::EdgeKind::ClaimOf, &owner, 1.0)
        .commit()
        .unwrap();
    let key = address(&["private"], "k");
    assert_eq!(
        memory.key_value_get(&key).unwrap_err().code,
        MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(
        memory
            .key_value_search(&KeyValueSearch::default())
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(
        memory.key_value_delete(&key).unwrap_err().code,
        MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(
        memory
            .key_value_put(&input(&["private"], "k", "two", 2))
            .unwrap_err()
            .code,
        MEMORY_CODE_INVALID_STATE
    );
}

#[test]
fn replacement_keeps_source_trust_and_refuses_generated_over_user_truth_atomically() {
    use crate::claim::ClaimSource;
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 110);
    // A real actor-bound generated auto permit lets the put reach the
    // supersession guard. It does not grant generated output user provenance.
    let mut manifest: rmpv::Value = rmpv::decode::read_value(&mut std::io::Cursor::new(
        crate::gate::default_policy_manifest(),
    ))
    .unwrap();
    let rmpv::Value::Map(entries) = &mut manifest else {
        panic!("manifest map")
    };
    let (_, rmpv::Value::Map(sources)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("source_trust"))
        .unwrap()
    else {
        panic!("source trust map")
    };
    let (_, generated) = sources
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("generated"))
        .unwrap();
    *generated = json_to_rmpv(
        &json!({"actor_ref": owner.to_hex(), "max_auto_sensitivity": 2, "auto": true, "receipted": true, "warned": true}),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let first = memory
        .key_value_put(&input(&["private"], "truth", "one", 1))
        .unwrap();
    let before = memory.receipts(100).unwrap();
    let pending_before = memory.pending_writes(100).unwrap();
    let mut generated = input(&["private"], "truth", "two", 2);
    generated.source = "generated".into();
    let error = memory.key_value_put(&generated).unwrap_err();
    assert_eq!(error.code, MEMORY_CODE_INVALID_STATE);
    assert!(!error.suggestions.is_empty());
    assert_eq!(
        memory
            .key_value_get(&address(&["private"], "truth"))
            .unwrap(),
        Some(first.item)
    );
    assert_eq!(memory.receipts(100).unwrap(), before);
    assert_eq!(memory.pending_writes(100).unwrap(), pending_before);
    let next = memory
        .key_value_put(&input(&["private"], "truth", "three", 3))
        .unwrap();
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&next.item.revision).unwrap())
            .unwrap()
            .unwrap()
            .source,
        Some(ClaimSource::UserStated)
    );
    generated.key = "draft".into();
    let draft = memory.key_value_put(&generated).unwrap();
    generated.request_id = "next".into();
    generated.value = json!({"n": 4});
    let replacement = memory.key_value_put(&generated).unwrap();
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&replacement.item.revision).unwrap())
            .unwrap()
            .unwrap()
            .source,
        Some(ClaimSource::Generated)
    );
    assert_eq!(
        vault
            .get_claim(&EntityId::from_hex(&draft.item.revision).unwrap())
            .unwrap()
            .unwrap()
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}

#[test]
fn exact_number_filters_preserve_representation_and_large_integer_precision() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 111);
    let memory = vault.memory(actor, EdgeActorClass::Human);
    for (key, number) in [
        ("integer", json!(2)),
        ("float", json!(2.0)),
        ("large", json!(9_007_199_254_740_993_u64)),
    ] {
        let mut request = input(&["numbers"], key, "one", 0);
        request.value = json!({"n": number});
        memory.key_value_put(&request).unwrap();
    }
    for (filter, expected) in [
        (json!(2), vec!["integer"]),
        (json!(2.0), vec!["float"]),
        (json!(9_007_199_254_740_993_u64), vec!["large"]),
        (json!(9_007_199_254_740_992_u64), vec![]),
    ] {
        let rows = memory
            .key_value_search(&KeyValueSearch {
                filter: Some(json!({"n": filter}).as_object().unwrap().clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            expected
        );
    }
}
