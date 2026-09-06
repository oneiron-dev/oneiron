//! Regressions for request policy freshness, wire identity, opaque bodies and
//! post-filter durable trace publication.

use super::*;

fn error_variants(method: VaultReadMethod) -> [VaultReadError; 6] {
    [
        VaultReadError::InvalidRequest {
            method,
            field: "query_vector".to_owned(),
            reason: "preserve the daemon reason".to_owned(),
        },
        VaultReadError::Transport {
            method,
            message: "preserve the transport detail".to_owned(),
        },
        VaultReadError::ProtocolMismatch {
            method,
            message: "preserve the protocol detail".to_owned(),
        },
        VaultReadError::RuntimeUnavailable { method },
        VaultReadError::Unimplemented {
            adapter: VaultReadAdapterKind::Cloud,
            method,
        },
        VaultReadError::Engine {
            method,
            engine_code: "CUSTOM_ENGINE_CODE".to_owned(),
            message: "preserve the engine detail".to_owned(),
        },
    ]
}

#[test]
fn wire_error_identity_is_checked_for_every_variant_and_method() {
    for requested in VaultReadMethod::ALL {
        for embedded in VaultReadMethod::ALL {
            for error in error_variants(embedded) {
                let bytes = serde_json::to_vec(&json!({ "err": error })).expect("error envelope");
                let actual = decode_wire_envelope(requested, requested.wire_op(), &bytes)
                    .expect_err("error envelope must not succeed");
                if requested == embedded {
                    assert_eq!(actual, error, "matching errors retain every payload field");
                } else {
                    assert!(
                        matches!(actual, VaultReadError::ProtocolMismatch { method, .. }
                            if method == requested),
                        "{requested:?} must reject {error:?}: {actual:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn persistent_adapter_observes_grant_revocation_and_narrowing() {
    // A world grant admits that world AND base reality. Narrow it to base,
    // or revoke it by naming another actor, between calls on the same adapter.
    for actor_ref in ["reader", "other"] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let (base_id, admitted_id) = seed_scoped_pack_vault(&vault);
        put_policy_manifest_bytes(
            &vault,
            entity(0x64),
            &scoped_grant_manifest("reader", &entity(0x61).to_hex()),
        )
        .expect("initial grant admits the target world");
        let reference = short_ref(&vault, &admitted_id);
        let adapter = InProcessVaultReadAdapter::new(
            &vault,
            ScopedReadActorKey::new("reader").expect("actor key"),
        );
        let query = CoreQueryRequest {
            query: None,
            query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
            limit: 10,
            view: None,
            count_mode: CountMode::Estimate,
        };
        let batch = CoreBatchShortIdHydrateRequest {
            refs: vec![reference.clone()],
            view: None,
        };
        let timeline = CoreMemoryTimelineRequest {
            id: admitted_id.to_hex(),
            view: None,
        };
        assert_eq!(
            adapter
                .hydrate(hydrate_request(&reference))
                .expect("first hydrate")
                .id,
            Some(admitted_id.to_hex())
        );
        assert!(
            adapter
                .query(query.clone())
                .expect("first query")
                .items
                .iter()
                .any(|item| item.id == admitted_id.to_hex())
        );
        assert!(
            adapter
                .context_pack(vector_pack_request())
                .expect("first pack")
                .0
                .results
                .iter()
                .any(|item| item.id == admitted_id.to_hex())
        );
        assert_eq!(
            adapter
                .hydrate_many(batch.clone())
                .expect("first batch")
                .results[0]
                .outcome,
            CoreShortIdHydrateOutcome::Live
        );
        assert!(
            !adapter
                .memory_timeline(timeline.clone())
                .expect("first timeline")
                .records
                .is_empty()
        );

        put_policy_manifest_bytes(
            &vault,
            entity(0x64),
            &scoped_grant_manifest(actor_ref, "base"),
        )
        .expect("replace the grant in the stored policy manifest");

        assert!(matches!(
            adapter.hydrate(hydrate_request(&reference)),
            Err(VaultReadError::Engine { method: VaultReadMethod::Hydrate, engine_code, .. })
                if engine_code == NOT_FOUND_ENGINE_CODE
        ));
        let second_query = adapter.query(query).expect("second query");
        assert!(
            second_query
                .items
                .iter()
                .all(|item| item.id != admitted_id.to_hex())
        );
        assert_eq!(
            second_query
                .items
                .iter()
                .any(|item| item.id == base_id.to_hex()),
            actor_ref == "reader",
            "narrowing retains base access; revocation does not"
        );
        assert!(
            adapter
                .context_pack(vector_pack_request())
                .expect("second pack")
                .0
                .results
                .iter()
                .all(|item| item.id != admitted_id.to_hex())
        );
        assert_eq!(
            adapter.hydrate_many(batch).expect("second batch").results[0].outcome,
            CoreShortIdHydrateOutcome::NotFound
        );
        assert!(matches!(
            adapter.memory_timeline(timeline),
            Err(VaultReadError::Engine { method: VaultReadMethod::MemoryTimeline, engine_code, .. })
                if engine_code == NOT_FOUND_ENGINE_CODE
        ));
        // The denial is a policy change, not deletion or a claim-status change.
        assert_eq!(
            vault.get_entity_type(&admitted_id).expect("stored claim"),
            Some(ENTITY_TYPE_CLAIM)
        );
    }
}

#[test]
fn opaque_bodies_survive_query_and_hydrate_views_losslessly() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let occurred = TimeRange { start: 1, end: 1 };
    let bodies = [vec![0xc1, 0xff, 0x00, 0x80], Vec::new(), vec![0xc0, 0xff]];
    let mut references = Vec::new();
    let mut ids = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        let id = entity(0x70 + u8::try_from(index).expect("fixture index"));
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, occurred, 1, body)
            .expect("arbitrary engine body");
        vault
            .batch()
            .vector(&id, &[1.0, 0.0, 0.0, 0.0])
            .commit()
            .expect("vector");
        references.push(short_ref(&vault, &id));
        ids.push(id);
    }
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("reader").expect("actor key"),
    );
    for view in [View::Summary, View::Full, View::Standard] {
        let query = adapter
            .query(CoreQueryRequest {
                query: None,
                query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
                limit: 10,
                view: Some(view),
                count_mode: CountMode::Estimate,
            })
            .expect("opaque bodies do not abort a query");
        assert_eq!(query.items.len(), bodies.len());
        let batch = adapter
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: references.clone(),
                view: Some(view),
            })
            .expect("opaque bodies do not abort a batch");
        assert_eq!(batch.results.len(), bodies.len());
        for (index, body) in bodies.iter().enumerate() {
            let expected = (view != View::Standard).then(|| json!({ "bodyBytes": body }));
            let queried = query
                .items
                .iter()
                .find(|item| item.id == ids[index].to_hex())
                .expect("opaque entity remains in query");
            assert_eq!(queried.body, expected);
            let hydrated = adapter
                .hydrate(CoreHydrateRequest {
                    view: Some(view),
                    ..hydrate_request(&references[index])
                })
                .expect("opaque body hydrates");
            assert_eq!(hydrated.status, CoreHydrateStatus::Live);
            assert_eq!(hydrated.item.expect("live item").body, expected);
            assert_eq!(
                batch.results[index].outcome,
                CoreShortIdHydrateOutcome::Live
            );
            assert_eq!(
                batch.results[index]
                    .result
                    .as_ref()
                    .expect("batch result")
                    .item
                    .as_ref()
                    .expect("batch item")
                    .body,
                expected
            );
        }
    }
}

#[test]
fn finish_post_filter_scrubs_all_durable_trace_stages_and_fork_index() {
    for remove_all in [false, true] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let (admitted_id, denied_id) = seed_scoped_pack_vault(&vault);
        let mut assembly = vault
            .context_pack()
            .limit(10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .capture_retrieval_trace(true)
            .run_unfinalized_with_telemetry()
            .expect("traced assembly");
        assert!(
            assembly
                .value
                .results
                .iter()
                .any(|item| item.id == denied_id)
        );
        assert!(
            assembly
                .value
                .results
                .iter()
                .any(|item| item.id == admitted_id)
        );
        let (_, provisional) = provisional_context_pack_run(&vault);
        let pre_trace = provisional
            .trace
            .expect("trace was captured before filtering");
        for candidates in trace_candidates(&pre_trace) {
            assert!(
                candidates
                    .iter()
                    .any(|entry| entry.result_id == *denied_id.as_bytes())
            );
        }
        assert!(
            vault
                .retrieval_trace_by_fork_hash(pre_trace.fork_hash)
                .expect("provisional fork lookup")
                .is_none()
        );
        let actor = if remove_all { "outsider" } else { "reader" };
        vault
            .scoped_read(ScopedReadActorKey::new(actor).expect("actor key"))
            .filter_context_pack(&mut assembly.value)
            .expect("scope filter");
        let finished = assembly
            .finish_post_filter()
            .expect("finalize filtered pack");
        let allowed: Vec<[u8; 16]> = finished
            .value
            .results
            .iter()
            .map(|item| *item.id.as_bytes())
            .collect();
        assert_eq!(
            allowed,
            if remove_all {
                Vec::new()
            } else {
                vec![*admitted_id.as_bytes()]
            }
        );
        let run = vault
            .retrieval_run(finished.run_id.expect("published run id"))
            .expect("durable read")
            .expect("published run");
        assert_eq!(run.result_ids, allowed);
        assert!(
            run.score_breakdown
                .iter()
                .all(|entry| allowed.contains(&entry.result_id))
        );
        let trace = run.trace.expect("trace capability retained");
        assert_ne!(trace.fork_hash, [0; 32]);
        assert!(
            !trace.per_channel.is_empty(),
            "trace channels remain available"
        );
        for candidates in trace_candidates(&trace) {
            assert!(
                candidates
                    .iter()
                    .all(|entry| allowed.contains(&entry.result_id))
            );
            assert_eq!(
                candidates.len(),
                allowed.len(),
                "surviving scoring detail is retained"
            );
        }
        let forked = vault
            .retrieval_trace_by_fork_hash(trace.fork_hash)
            .expect("fork index read")
            .expect("trace is still indexed");
        assert_eq!(
            forked, trace,
            "fork lookup exposes only the filtered durable trace"
        );
    }
}

fn trace_candidates(
    trace: &crate::store::RetrievalTrace,
) -> impl Iterator<Item = &Vec<crate::store::RetrievalScoreBreakdown>> {
    trace
        .per_channel
        .iter()
        .map(|channel| &channel.candidates)
        .chain([
            &trace.fused.candidates,
            &trace.blended.candidates,
            &trace.reranked.candidates,
            &trace.final_stage.candidates,
        ])
}

fn provisional_context_pack_run(vault: &Vault) -> (Vec<u8>, RetrievalRunRecord) {
    let rtxn = vault.store.env.read_txn().expect("read provisional row");
    let rows = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, b"retr_run:v0:")
        .expect("provisional row scan");
    let mut runs = Vec::new();
    for row in rows {
        let (key, value) = row.expect("provisional row");
        let record: RetrievalRunRecord = rmp_serde::from_slice(&value).expect("run record");
        if record.action == RetrievalAction::ContextPack {
            runs.push((key.to_vec(), record));
        }
    }
    assert_eq!(runs.len(), 1);
    runs.remove(0)
}

#[test]
fn finish_post_filter_propagates_finalize_failure_and_discards_trace() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    seed_scoped_pack_vault(&vault);
    let mut assembly = vault
        .context_pack()
        .limit(10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .capture_retrieval_trace(true)
        .run_unfinalized_with_telemetry()
        .expect("traced assembly");
    vault
        .scoped_read(ScopedReadActorKey::new("reader").expect("actor key"))
        .filter_context_pack(&mut assembly.value)
        .expect("scope filter");
    let (key, provisional) = provisional_context_pack_run(&vault);
    let fork_hash = provisional.trace.expect("captured trace").fork_hash;
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, &[0xc1])?;
            Ok(())
        })
        .expect("inject a genuinely corrupt provisional telemetry row");

    assert!(matches!(
        assembly.finish_post_filter(),
        Err(crate::Error::CorruptedIndex(_))
    ));
    let rtxn = vault.store.env.read_txn().expect("read discarded row");
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &key)
            .expect("row lookup")
            .is_none()
    );
    let mut provisional_key = b"retr_run_prov:v0:".to_vec();
    provisional_key.extend_from_slice(&provisional.run_id.as_bytes());
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &provisional_key)
            .expect("provisional marker lookup")
            .is_none()
    );
    drop(rtxn);
    assert!(
        vault
            .retrieval_runs(64)
            .expect("published runs")
            .iter()
            .all(|run| run.action != RetrievalAction::ContextPack)
    );
    assert!(
        vault
            .retrieval_trace_by_fork_hash(fork_hash)
            .expect("fork lookup")
            .is_none()
    );
}
