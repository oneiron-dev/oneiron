use std::sync::Arc;

use super::*;
use crate::hnsw::{self, DROPPED_REBUILDABLE_KEY, LinkDiscipline};
use crate::outbound_intent_ledger::{
    self as ledger, BudgetChargeMarker, BudgetClass, FrozenOutboundCall, IntentLedgerRecord,
    OutboundAuthorizationBinding, OutboundCallRequest, OutboundSendOutcome, OutboundSender,
    OutboundToolDescriptor,
};
use crate::overlay_db::OverlayDb;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{EdgeKind, EntityId, TimeRange};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn fixture() -> (tempfile::TempDir, Arc<Vault>) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    (dir, Arc::new(vault))
}

fn rows(vault: &Vault, db: &OverlayDb) -> Result<Rows> {
    let txn = vault.store.env.read_txn()?;
    db.iter(&txn)?
        .map(|row| row.map(|(k, v)| (k.to_vec(), v.to_vec())))
        .collect()
}

fn request(call_seq: u64, now_ms: u64) -> OutboundCallRequest {
    OutboundCallRequest::new(
        AttemptId::from_bytes(&[8; 16]).expect("attempt"),
        call_seq,
        "fixture-server",
        "fixture-tool",
        b"frozen payload".to_vec(),
        now_ms,
    )
    .with_authorization_binding(OutboundAuthorizationBinding::new([9; 32]))
}

fn pending(vault: &Vault, call_seq: u64) -> IntentLedgerRecord {
    let record = IntentLedgerRecord::pending(
        request(call_seq, 10),
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 10,
        },
    )
    .expect("valid pending fixture");
    vault
        .with_write_txn(|txn| {
            ledger::insert_pending_in_txn(vault, txn, &record).map_err(map_intent_ledger_error)
        })
        .expect("persist pending through landed encoder");
    record
}

fn shed(vault: &Vault) -> Result<ShedOutcome> {
    vault.shed_rebuildable_heap(ShedCause::LongOutboundWait, 1, 20)
}

fn entered(vault: &Vault) -> (SlimResidue, HeapDropReport) {
    match shed(vault).expect("shed") {
        ShedOutcome::Entered { residue, dropped } => (residue, dropped),
        other => panic!("expected entry, got {other:?}"),
    }
}

fn warm(vault: &Vault) -> Result<Vec<EntityId>> {
    // Ascending id/insert order, no deletes, and duplicate vectors pin ties.
    let ids: Vec<_> = (40..44).map(entity).collect();
    for (id, vector) in ids.iter().zip([
        [1.0, 0.0, 0.0, 0.0],
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
    ]) {
        vault.put_entity(id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
        vault.put_vector(id, &vector)?;
    }
    for pair in ids.windows(2) {
        vault.put_edge(&pair[0], EdgeKind::Mentions, &pair[1], 0.8)?;
    }
    let before = probes(vault)?;
    vault.maintain().rebuild_hnsw().run()?;
    assert_eq!(
        before,
        probes(vault)?,
        "pinned incremental/rebuild baseline"
    );
    assert_eq!(discipline(vault)?, LinkDiscipline::Symmetric);
    ppr(vault, ids[0])?;
    Ok(ids)
}

fn ppr(vault: &Vault, seed: EntityId) -> Result<Vec<(EntityId, u32)>> {
    Ok(vault
        .query()
        .search_ppr(&[seed], 2)
        .run()?
        .into_iter()
        .map(|score| (score.id, score.score.to_bits()))
        .collect())
}

fn probes(vault: &Vault) -> Result<Vec<Vec<(EntityId, u32)>>> {
    let txn = vault.store.env.read_txn()?;
    [
        [1.0, 0.0, 0.0, 0.0],
        [0.5, 0.5, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
    ]
    .iter()
    .map(|query| {
        Ok(
            hnsw::hnsw_search(&vault.store, &vault.config, &txn, query, 4, false)?
                .into_iter()
                .map(|score| (score.id, score.score.to_bits()))
                .collect(),
        )
    })
    .collect()
}

fn discipline(vault: &Vault) -> Result<LinkDiscipline> {
    let txn = vault.store.env.read_txn()?;
    hnsw::read_link_discipline(&vault.store, &txn)
}

fn dropped(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    hnsw::hnsw_is_dropped(&vault.store, &txn)
}

fn drop_graph(vault: &Vault) -> Result<HeapDropReport> {
    vault.with_write_txn(|txn| hnsw::drop_rebuildable_hnsw(&vault.store, txn))
}

fn assert_canonical_graph(vault: &Vault) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let ids = vault
        .store
        .vectors
        .iter(&txn)?
        .map(|row| {
            let (key, _) = row?;
            EntityId::from_bytes(key.as_ref().try_into().map_err(|_| Error::InvalidKey)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let graph = hnsw::build_hnsw_graph_from_snapshot(
        &vault.store,
        &vault.config,
        &txn,
        &ids,
        hnsw::read_link_discipline(&vault.store, &txn)?,
    )?;
    assert_eq!(vault.store.hnsw_neighbors.len(&txn)?, graph.count);
    assert_eq!(hnsw::hnsw_entity_count(&vault.store, &txn)?, ids.len());
    for (id, neighbors) in graph.neighbors {
        let expected: Vec<u8> = neighbors.iter().flat_map(|id| *id.as_bytes()).collect();
        assert_eq!(
            vault
                .store
                .hnsw_neighbors
                .get(&txn, id.as_bytes())?
                .as_deref(),
            Some(expected.as_slice())
        );
    }
    assert_eq!(
        vault.store.hnsw_meta.get(&txn, b"entry_point")?.as_deref(),
        graph
            .entry_point
            .as_ref()
            .map(|id| id.as_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn shed_requires_exactly_one_pending_intent() {
    let (_dir, vault) = fixture();
    assert_eq!(
        shed(&vault).unwrap(),
        ShedOutcome::Refused(ShedBlocker::NoPendingOutboundStep)
    );
    let first = pending(&vault, 1);
    let second = pending(&vault, 2);
    assert_eq!(
        shed(&vault).unwrap(),
        ShedOutcome::Refused(ShedBlocker::MultiplePendingOutboundSteps { count: 2 })
    );
    assert_eq!(vault.residency(), VaultResidency::Full);
    ledger::complete_record(&vault, second.id, 12).unwrap();
    let (residue, _) = entered(&vault);
    assert_eq!(
        residue.step,
        JournaledResumeStep {
            intent_id: first.id,
            attempt_id: first.attempt_id,
            call_seq: first.call_seq,
            updated_ms: first.updated_ms,
        }
    );
    assert_eq!(residue.entered_at_ms, 20);
}

#[test]
fn direct_call_zero_waited_secs_is_typed_error() {
    let (_dir, vault) = fixture();
    let revision = vault.store.env.info().last_txn_id;
    for cause in [ShedCause::LongOutboundWait, ShedCause::MemoryPressure] {
        assert!(matches!(
            vault.shed_rebuildable_heap(cause, 0, 20),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert_eq!(vault.store.env.info().last_txn_id, revision);
    assert_eq!(vault.residency(), VaultResidency::Full);
}

#[test]
fn ppr_cache_drop_recomputes_equal_results() -> Result<()> {
    let (_dir, vault) = fixture();
    let ids = warm(&vault)?;
    pending(&vault, 1);
    let expected = ppr(&vault, ids[0])?;
    assert!(!expected.is_empty());
    let entities = rows(&vault, &vault.store.entities)?;
    let edges = rows(&vault, &vault.store.edges_out)?;
    let incoming = rows(&vault, &vault.store.edges_in)?;
    let version = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .hnsw_meta
            .get(&txn, crate::store::GRAPH_VERSION_KEY)?
            .map(|v| v.to_vec())
    };
    let (_, report) = entered(&vault);
    assert!(report.ppr_cache_rows > 0 && report.ppr_dependency_rows > 0);
    assert!(rows(&vault, &vault.store.ppr_cache)?.is_empty());
    assert!(rows(&vault, &vault.store.ppr_cache_deps)?.is_empty());
    assert_eq!(expected, ppr(&vault, ids[0])?);
    assert!(!rows(&vault, &vault.store.ppr_cache)?.is_empty());
    assert!(!rows(&vault, &vault.store.ppr_cache_deps)?.is_empty());
    assert_eq!(entities, rows(&vault, &vault.store.entities)?);
    assert_eq!(edges, rows(&vault, &vault.store.edges_out)?);
    assert_eq!(incoming, rows(&vault, &vault.store.edges_in)?);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        version.as_deref(),
        vault
            .store
            .hnsw_meta
            .get(&txn, crate::store::GRAPH_VERSION_KEY)?
            .as_deref()
    );
    Ok(())
}

#[test]
fn hnsw_drop_rebuilds_equal_neighbors() -> Result<()> {
    let (_dir, vault) = fixture();
    warm(&vault)?;
    let expected = probes(&vault)?;
    let vectors = rows(&vault, &vault.store.vectors)?;
    let metadata = rows(&vault, &vault.store.hnsw_meta)?;
    let report = drop_graph(&vault)?;
    assert_eq!(report.hnsw_nodes, 4);
    assert!(dropped(&vault)?);
    assert!(rows(&vault, &vault.store.hnsw_neighbors)?.is_empty());
    let revision = vault.store.env.info().last_txn_id;
    for _ in 0..2 {
        assert_eq!(expected, probes(&vault)?);
        assert!(dropped(&vault)?);
    }
    assert_eq!(
        vault.store.env.info().last_txn_id,
        revision,
        "search is read-only"
    );
    assert_eq!(vectors, rows(&vault, &vault.store.vectors)?);
    let txn = vault.store.env.read_txn()?;
    for (key, value) in metadata {
        if key == hnsw::COUNT_KEY || key == b"entry_point" || key.starts_with(b"ow1:") {
            assert!(vault.store.hnsw_meta.get(&txn, &key)?.is_none());
        } else {
            assert_eq!(
                vault.store.hnsw_meta.get(&txn, &key)?.as_deref(),
                Some(value.as_slice())
            );
        }
    }
    drop(txn);
    vault.maintain().rebuild_hnsw().run()?;
    assert!(!dropped(&vault)?);
    assert_eq!(expected, probes(&vault)?);
    assert_canonical_graph(&vault)
}

#[test]
fn hnsw_lazy_rebuild_preserves_legacy_discipline() -> Result<()> {
    let (_dir, vault) = fixture();
    warm(&vault)?;
    // Rebuild a real Legacy baseline, not a Symmetric graph with a false label.
    vault.with_write_txn(|txn| {
        let ids: Vec<_> = (40..44).map(entity).collect();
        let graph = hnsw::build_hnsw_graph_from_snapshot(
            &vault.store,
            &vault.config,
            txn,
            &ids,
            LinkDiscipline::Legacy,
        )?;
        hnsw::write_rebuilt_hnsw(&vault.store, txn, &graph, LinkDiscipline::Legacy)
    })?;
    let expected = probes(&vault)?;
    drop_graph(&vault)?;
    let revision = vault.store.env.info().last_txn_id;
    assert_eq!(expected, probes(&vault)?);
    assert_eq!(vault.store.env.info().last_txn_id, revision);
    assert_eq!(discipline(&vault)?, LinkDiscipline::Legacy);
    assert!(dropped(&vault)?);
    vault.put_vector(&entity(40), &[0.0, 0.0, 0.0, 1.0])?;
    assert_eq!(discipline(&vault)?, LinkDiscipline::Legacy);
    assert!(!dropped(&vault)?);
    assert_canonical_graph(&vault)
}

#[test]
fn hnsw_write_routes_while_dropped() -> Result<()> {
    let (_dir, vault) = fixture();
    warm(&vault)?;
    drop_graph(&vault)?;
    let id = entity(44);
    vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"insert")?;
    vault.put_vector(&id, &[0.0, 0.0, 0.0, 1.0])?;
    assert!(!dropped(&vault)?);
    assert_canonical_graph(&vault)?;
    drop_graph(&vault)?;
    vault.put_vector(&entity(40), &[0.0, 0.0, 0.0, 1.0])?;
    assert!(!dropped(&vault)?);
    assert_canonical_graph(&vault)?;
    drop_graph(&vault)?;
    assert!(vault.delete_entity(&id)?);
    assert!(dropped(&vault)?);
    assert!(
        probes(&vault)?
            .iter()
            .flatten()
            .all(|(found, _)| *found != id)
    );
    assert!(dropped(&vault)?);
    vault.put_vector(&entity(40), &[0.0, 1.0, 0.0, 0.0])?;
    assert_canonical_graph(&vault)
}

#[test]
fn hnsw_dropped_marker_is_not_empty_corpus() -> Result<()> {
    let (_dir, vault) = fixture();
    drop_graph(&vault)?;
    assert!(probes(&vault)?.iter().all(Vec::is_empty));
    warm(&vault)?;
    drop_graph(&vault)?;
    assert!(probes(&vault)?.iter().all(|result| !result.is_empty()));
    vault.with_write_txn(|txn| {
        vault
            .store
            .hnsw_meta
            .put(txn, DROPPED_REBUILDABLE_KEY, &[2])?;
        Ok(())
    })?;
    assert!(matches!(dropped(&vault), Err(Error::CorruptedIndex(_))));
    assert!(matches!(probes(&vault), Err(Error::CorruptedIndex(_))));
    assert!(matches!(drop_graph(&vault), Err(Error::CorruptedIndex(_))));
    let txn = vault.store.env.read_txn()?;
    assert!(matches!(
        hnsw::hnsw_entity_count(&vault.store, &txn),
        Err(Error::CorruptedIndex(_))
    ));
    Ok(())
}

#[test]
fn dropped_marker_entity_count_equals_vector_count() -> Result<()> {
    let (_dir, vault) = fixture();
    warm(&vault)?;
    drop_graph(&vault)?;
    let txn = vault.store.env.read_txn()?;
    assert_eq!(vault.store.hnsw_neighbors.len(&txn)?, 0);
    assert_eq!(hnsw::hnsw_entity_count(&vault.store, &txn)?, 4);
    assert_eq!(vault.store.vectors.len(&txn)?, 4);
    Ok(())
}

#[test]
fn shed_is_idempotent_per_step() -> Result<()> {
    let (_dir, vault) = fixture();
    let ids = warm(&vault)?;
    let first = pending(&vault, 1);
    let (residue, _) = entered(&vault);
    ppr(&vault, ids[0])?;
    vault.maintain().rebuild_hnsw().run()?;
    match shed(&vault)? {
        ShedOutcome::AlreadySlim {
            residue: again,
            dropped,
        } => {
            assert_eq!(again, residue);
            assert_eq!(dropped.hnsw_nodes, 4);
            assert!(dropped.ppr_cache_rows > 0);
        }
        other => panic!("expected re-drop, got {other:?}"),
    }
    ledger::complete_record(&vault, first.id, 30).unwrap();
    assert_eq!(
        shed(&vault)?,
        ShedOutcome::AlreadySlim {
            residue: residue.clone(),
            dropped: HeapDropReport::default(),
        }
    );
    pending(&vault, 2);
    assert_eq!(
        shed(&vault)?,
        ShedOutcome::Refused(ShedBlocker::AlreadySlimForDifferentStep)
    );
    pending(&vault, 3);
    assert_eq!(
        shed(&vault)?,
        ShedOutcome::AlreadySlim {
            residue: residue.clone(),
            dropped: HeapDropReport::default(),
        }
    );
    assert_eq!(vault.residency(), VaultResidency::Slim);
    assert_eq!(
        vault.resume_from_slim_on_inbound()?,
        InboundResumeOutcome::Resumed { residue }
    );
    Ok(())
}

#[test]
fn same_step_with_touched_updated_ms_is_already_slim() {
    let (_dir, vault) = fixture();
    let record = pending(&vault, 1);
    let (residue, _) = entered(&vault);
    ledger::record_definite_non_delivery(&vault, record.id, 31).unwrap();
    let touched = ledger::begin_definite_non_delivery_retry(&vault, record.id, 32).unwrap();
    match shed(&vault).unwrap() {
        ShedOutcome::AlreadySlim { residue: again, .. } => {
            assert!(residue.step.same_step(&again.step));
            assert_ne!(residue.step, again.step);
            assert_eq!(again.entered_at_ms, residue.entered_at_ms);
            assert_eq!(again.step.updated_ms, touched.updated_ms);
        }
        other => panic!("timestamp is not identity: {other:?}"),
    }
}

#[test]
fn shed_failure_leaves_admission_residency() -> Result<()> {
    for already_slim in [false, true] {
        let (_dir, vault) = fixture();
        let ids = warm(&vault)?;
        let record = pending(&vault, 1);
        let prior = already_slim.then(|| entered(&vault).0);
        ppr(&vault, ids[0])?;
        vault.maintain().rebuild_hnsw().run()?;
        ledger::record_definite_non_delivery(&vault, record.id, 30).unwrap();
        let cache = rows(&vault, &vault.store.ppr_cache)?;
        let deps = rows(&vault, &vault.store.ppr_cache_deps)?;
        let graph = rows(&vault, &vault.store.hnsw_neighbors)?;
        vault.with_write_txn(|txn| {
            vault
                .store
                .hnsw_meta
                .put(txn, DROPPED_REBUILDABLE_KEY, &[99])?;
            Ok(())
        })?;
        assert!(matches!(shed(&vault), Err(Error::CorruptedIndex(_))));
        assert_eq!(
            cache,
            rows(&vault, &vault.store.ppr_cache)?,
            "PPR clear aborted"
        );
        assert_eq!(deps, rows(&vault, &vault.store.ppr_cache_deps)?);
        assert_eq!(graph, rows(&vault, &vault.store.hnsw_neighbors)?);
        let expected = prior.clone().map_or(SlimState::Full, SlimState::Slim);
        assert_eq!(*vault.slim.lock_state(), expected);
        vault.with_write_txn(|txn| {
            vault.store.hnsw_meta.delete(txn, DROPPED_REBUILDABLE_KEY)?;
            Ok(())
        })?;
        assert!(!ppr(&vault, ids[0])?.is_empty());
        assert!(!probes(&vault)?[0].is_empty());
        assert!(matches!(
            shed(&vault)?,
            ShedOutcome::Entered { .. } | ShedOutcome::AlreadySlim { .. }
        ));
    }
    Ok(())
}

#[test]
fn shed_refuses_unrebuildable_healed_graph_without_mutation() -> Result<()> {
    let malformed_rows = [
        (entity(43).as_bytes().to_vec(), b"bad".to_vec()),
        (entity(43).as_bytes().to_vec(), vec![0; 12]),
        (
            entity(43).as_bytes().to_vec(),
            [f32::NAN, 0.0, 0.0, 0.0]
                .into_iter()
                .flat_map(f32::to_le_bytes)
                .collect(),
        ),
        (b"bad-key".to_vec(), vec![0; 16]),
        (vec![0; 16], vec![0; 16]),
    ];
    for (key, value) in malformed_rows {
        for already_slim in [false, true] {
            let (_dir, vault) = fixture();
            let ids = warm(&vault)?;
            let record = pending(&vault, 1);
            let prior = already_slim.then(|| entered(&vault).0);
            vault.with_write_txn(|txn| {
                vault.store.vectors.put(txn, &key, &value)?;
                Ok(())
            })?;
            let vectors = rows(&vault, &vault.store.vectors)?;
            let strict_error = vault.maintain().rebuild_hnsw().run().unwrap_err();
            let report = vault.maintain().rebuild_hnsw_heal_invalid_vectors().run()?;
            assert_eq!(report.hnsw_invalid_vectors_skipped, 1);
            assert_eq!(vectors, rows(&vault, &vault.store.vectors)?);
            assert!(!dropped(&vault)?);
            let expected = probes(&vault)?;
            for result in &expected {
                assert!(!result.is_empty());
                assert!(result.iter().all(|(id, _)| {
                    ids.contains(id) && id.as_bytes().as_slice() != key.as_slice()
                }));
            }
            let expected_ppr = ppr(&vault, ids[0])?;
            // A failed re-shed must not even refresh the residue timestamp.
            ledger::record_definite_non_delivery(&vault, record.id, 30).unwrap();
            let databases = [
                &vault.store.vectors,
                &vault.store.vault_meta,
                &vault.store.hnsw_meta,
                &vault.store.hnsw_neighbors,
                &vault.store.ppr_cache,
                &vault.store.ppr_cache_deps,
            ];
            let before = databases
                .iter()
                .map(|db| rows(&vault, db))
                .collect::<Result<Vec<_>>>()?;
            assert!(!before[3].is_empty());
            assert!(!before[4].is_empty());
            let revision = vault.store.env.info().last_txn_id;
            let error = shed(&vault).unwrap_err();
            assert!(matches!(
                error,
                Error::InvalidKey
                    | Error::InvalidVector { .. }
                    | Error::DimensionMismatch { .. }
                    | Error::CorruptedIndex(_)
            ));
            assert_eq!(error.to_string(), strict_error.to_string());
            assert_eq!(vault.store.env.info().last_txn_id, revision);
            for (db, expected_rows) in databases.iter().zip(before) {
                assert_eq!(expected_rows, rows(&vault, db)?);
            }
            assert_eq!(
                *vault.slim.lock_state(),
                prior.map_or(SlimState::Full, SlimState::Slim)
            );
            assert!(!dropped(&vault)?);
            assert_eq!(expected, probes(&vault)?);
            assert_eq!(expected_ppr, ppr(&vault, ids[0])?);
        }
    }
    Ok(())
}

#[test]
fn lazy_read_still_refuses_new_malformed_source_rows() -> Result<()> {
    let (_dir, vault) = fixture();
    warm(&vault)?;
    drop_graph(&vault)?;
    vault.with_write_txn(|txn| {
        vault
            .store
            .vectors
            .put(txn, entity(43).as_bytes(), b"bad")?;
        Ok(())
    })?;
    let vectors = rows(&vault, &vault.store.vectors)?;
    let metadata = rows(&vault, &vault.store.hnsw_meta)?;
    let revision = vault.store.env.info().last_txn_id;
    assert!(matches!(probes(&vault), Err(Error::CorruptedIndex(_))));
    assert_eq!(vault.store.env.info().last_txn_id, revision);
    assert_eq!(vectors, rows(&vault, &vault.store.vectors)?);
    assert_eq!(metadata, rows(&vault, &vault.store.hnsw_meta)?);
    assert!(dropped(&vault)?);
    assert!(rows(&vault, &vault.store.hnsw_neighbors)?.is_empty());
    Ok(())
}

#[test]
fn malformed_ledger_selection_preserves_residency() -> Result<()> {
    for already_slim in [false, true] {
        let (_dir, vault) = fixture();
        pending(&vault, 1);
        let prior = already_slim.then(|| entered(&vault).0);
        let original = rows(&vault, &vault.store.vault_meta)?;
        let (key, value) = original
            .iter()
            .find(|(key, _)| key.starts_with(b"outbound:intent_ledger:v2:"))
            .expect("landed private ledger row");
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, key, b"malformed")?;
            Ok(())
        })?;
        let revision = vault.store.env.info().last_txn_id;
        assert!(matches!(shed(&vault), Err(Error::CorruptedIndex(_))));
        assert_eq!(vault.store.env.info().last_txn_id, revision);
        assert_eq!(
            *vault.slim.lock_state(),
            prior.map_or(SlimState::Full, SlimState::Slim)
        );
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, key, value)?;
            Ok(())
        })?;
        assert!(shed(&vault).is_ok());
    }
    Ok(())
}

#[test]
fn resume_is_lazy_and_writes_nothing() -> Result<()> {
    let (_dir, vault) = fixture();
    let ids = warm(&vault)?;
    pending(&vault, 1);
    let (residue, _) = entered(&vault);
    let ledger = rows(&vault, &vault.store.vault_meta)?;
    let revision = vault.store.env.info().last_txn_id;
    assert_eq!(
        vault.resume_from_slim_on_inbound()?,
        InboundResumeOutcome::Resumed { residue }
    );
    assert_eq!(
        vault.resume_from_slim_on_inbound()?,
        InboundResumeOutcome::AlreadyFull
    );
    assert_eq!(vault.residency(), VaultResidency::Full);
    assert_eq!(vault.store.env.info().last_txn_id, revision);
    assert_eq!(ledger, rows(&vault, &vault.store.vault_meta)?);
    assert!(dropped(&vault)?);
    assert!(rows(&vault, &vault.store.ppr_cache)?.is_empty());
    assert!(rows(&vault, &vault.store.hnsw_neighbors)?.is_empty());
    assert!(!ppr(&vault, ids[0])?.is_empty());
    assert!(!probes(&vault)?[0].is_empty());
    Ok(())
}

#[test]
fn journaled_step_survives_shed_rehydrate_no_duplicate_send() {
    struct InFlight<'a> {
        vault: &'a Vault,
        calls: usize,
    }
    impl OutboundSender for InFlight<'_> {
        fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
            self.calls += 1;
            let before = rows(self.vault, &self.vault.store.vault_meta).unwrap();
            let (residue, _) = entered(self.vault);
            assert_eq!(Some(&residue.step.intent_id), call.intent_id());
            self.vault.resume_from_slim_on_inbound().unwrap();
            assert_eq!(
                before,
                rows(self.vault, &self.vault.store.vault_meta).unwrap()
            );
            let listing = intent_ledger_records(self.vault).unwrap();
            assert_eq!(listing.records.len(), 1);
            assert_eq!(listing.records[0].state, IntentState::Pending);
            OutboundSendOutcome::Acked
        }
    }
    let (_dir, vault) = fixture();
    let descriptor = OutboundToolDescriptor {
        read_only_hint: Some(false),
        idempotency_supported_hint: Some(true),
    };
    let mut sender = InFlight {
        vault: &vault,
        calls: 0,
    };
    let first =
        ledger::execute_outbound_call(&vault, descriptor, request(1, 10), &mut sender).unwrap();
    let done = rows(&vault, &vault.store.vault_meta).unwrap();
    let replay =
        ledger::execute_outbound_call(&vault, descriptor, request(1, 30), &mut sender).unwrap();
    assert_eq!(sender.calls, 1);
    assert_eq!(first.intent_id, replay.intent_id);
    assert_eq!(first.state, Some(IntentState::Done));
    assert!(replay.replayed);
    assert_eq!(done, rows(&vault, &vault.store.vault_meta).unwrap());
    let listing = intent_ledger_records(&vault).unwrap();
    assert!(listing.corrupt.is_empty());
    assert_eq!(listing.records.len(), 1);
    assert_eq!(listing.records[0].state, IntentState::Done);
}

#[cfg(feature = "sync")]
fn manager(vault: &Arc<Vault>) -> Arc<crate::sync::WindowManager> {
    Arc::new(crate::sync::WindowManager::new(
        Arc::clone(vault),
        Arc::new(crate::sync::bridge::Materializer::new()),
        "slim-fixture",
    ))
}

#[cfg(feature = "sync")]
#[test]
fn sync_windows_drop_and_rebuild_equivalent() -> Result<()> {
    let (_dir, vault) = fixture();
    pending(&vault, 1);
    let manager = manager(&vault);
    let key = crate::sync::WindowKey::new("2026-03");
    let window = manager.open_window(&key)?;
    window
        .doc
        .get_map("slim_fixture")
        .insert("state", "retained")
        .unwrap();
    window.doc.commit();
    let expected = window.doc.get_deep_value();
    let weak = Arc::downgrade(&window);
    assert!(matches!(
        shed(&vault)?,
        ShedOutcome::Refused(ShedBlocker::SyncWindowBusy { .. })
    ));
    assert_eq!(manager.loaded_keys(), vec![key.clone()]);
    drop(window);
    let (_, report) = entered(&vault);
    assert_eq!(report.sync_windows, 1);
    assert!(report.estimated_reclaimed_bytes > 0);
    assert!(weak.upgrade().is_none());
    assert!(manager.loaded_keys().is_empty());
    let revision = vault.store.env.info().last_txn_id;
    vault.resume_from_slim_on_inbound()?;
    assert_eq!(vault.store.env.info().last_txn_id, revision);
    assert!(manager.loaded_keys().is_empty());
    assert_eq!(expected, manager.open_window(&key)?.doc.get_deep_value());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn full_drop_all_touch_everything_equivalence() -> Result<()> {
    let (_dir, vault) = fixture();
    let ids = warm(&vault)?;
    pending(&vault, 1);
    let manager = manager(&vault);
    let key = crate::sync::WindowKey::new("2026-03");
    let window = manager.open_window(&key)?;
    let doc = window.doc.get_deep_value();
    drop(window);
    let ppr_before = ppr(&vault, ids[0])?;
    let hnsw_before = probes(&vault)?;
    let (_, report) = entered(&vault);
    assert_eq!(report.sync_windows, 1);
    assert_eq!(report.hnsw_nodes, 4);
    assert!(report.ppr_cache_rows > 0 && report.ppr_dependency_rows > 0);
    assert!(report.estimated_reclaimed_bytes > 0);
    assert_eq!(doc, manager.open_window(&key)?.doc.get_deep_value());
    assert_eq!(ppr_before, ppr(&vault, ids[0])?);
    assert_eq!(hnsw_before, probes(&vault)?);
    assert_eq!(vault.residency(), VaultResidency::Slim);
    assert!(matches!(
        shed(&vault)?,
        ShedOutcome::AlreadySlim {
            dropped: HeapDropReport {
                sync_windows: 1,
                ..
            },
            ..
        }
    ));
    Ok(())
}

#[test]
fn slim_residue_rss_bound() -> Result<()> {
    fn rss_bytes() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
    }
    // Process-wide RSS includes other test threads and allocator/page-cache noise.
    const ALLOCATOR_AND_PAGE_CACHE_SLACK: u64 = 128 * 1024 * 1024;
    let (_dir, vault) = fixture();
    warm(&vault)?;
    pending(&vault, 1);
    let expected_cache = rows(&vault, &vault.store.ppr_cache)?.len() as u64;
    let expected_deps = rows(&vault, &vault.store.ppr_cache_deps)?.len() as u64;
    let before = rss_bytes();
    let (_, report) = entered(&vault);
    assert_eq!(report.hnsw_nodes, 4);
    assert_eq!(report.ppr_cache_rows, expected_cache);
    assert_eq!(report.ppr_dependency_rows, expected_deps);
    assert!(report.estimated_reclaimed_bytes > 0);
    if let (Some(before), Some(after)) = (before, rss_bytes()) {
        assert!(after <= before.saturating_add(ALLOCATOR_AND_PAGE_CACHE_SLACK));
    }
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn sync_drop_failure_preserves_admission_residue() -> Result<()> {
    for already_slim in [false, true] {
        let (_dir, vault) = fixture();
        warm(&vault)?;
        let record = pending(&vault, 1);
        let manager = manager(&vault);
        let key = crate::sync::WindowKey::new("2026-03");
        let prior = already_slim.then(|| entered(&vault).0);
        let window = manager.open_window(&key)?;
        ledger::record_definite_non_delivery(&vault, record.id, 30).unwrap();
        let admitted = prior.map_or(SlimState::Full, SlimState::Slim);
        let revision = vault.store.env.info().last_txn_id;
        assert!(matches!(
            shed(&vault)?,
            ShedOutcome::Refused(ShedBlocker::SyncWindowBusy { .. })
        ));
        assert_eq!(vault.store.env.info().last_txn_id, revision);
        assert_eq!(*vault.slim.lock_state(), admitted);
        drop(window);
        let bad_key = format!("u:w:{key}:ffffffff");
        vault.with_write_txn(|txn| {
            vault.store.sync_state.put(txn, &bad_key, b"bad update")?;
            Ok(())
        })?;
        let cache = rows(&vault, &vault.store.ppr_cache)?;
        assert!(shed(&vault).is_err());
        assert_eq!(*vault.slim.lock_state(), admitted);
        assert_eq!(manager.loaded_keys(), vec![key]);
        assert_eq!(cache, rows(&vault, &vault.store.ppr_cache)?);
        vault.with_write_txn(|txn| {
            vault.store.sync_state.delete(txn, &bad_key)?;
            Ok(())
        })?;
        assert!(matches!(
            shed(&vault)?,
            ShedOutcome::Entered { .. } | ShedOutcome::AlreadySlim { .. }
        ));
    }
    Ok(())
}

#[test]
fn stable_step_identity_and_report_merge_are_field_exact() {
    let step = JournaledResumeStep {
        intent_id: [1; 32],
        attempt_id: AttemptId::from_bytes(&[2; 16]).unwrap(),
        call_seq: 3,
        updated_ms: 4,
    };
    assert!(step.same_step(&JournaledResumeStep {
        updated_ms: 99,
        ..step
    }));
    for changed in [
        JournaledResumeStep {
            intent_id: [8; 32],
            ..step
        },
        JournaledResumeStep {
            attempt_id: AttemptId::from_bytes(&[8; 16]).unwrap(),
            ..step
        },
        JournaledResumeStep {
            call_seq: 8,
            ..step
        },
    ] {
        assert!(!step.same_step(&changed));
    }
    let report = HeapDropReport {
        sync_windows: 1,
        ppr_cache_rows: 2,
        ppr_dependency_rows: 3,
        hnsw_nodes: 4,
        estimated_reclaimed_bytes: 5,
    };
    assert_eq!(
        report.merged(report),
        HeapDropReport {
            sync_windows: 2,
            ppr_cache_rows: 4,
            ppr_dependency_rows: 6,
            hnsw_nodes: 8,
            estimated_reclaimed_bytes: 10,
        }
    );
}

#[test]
fn hnsw_lazy_search_matches_persisted_discipline_with_fast_dims() -> Result<()> {
    for discipline in [LinkDiscipline::Legacy, LinkDiscipline::Symmetric] {
        let mut config = embedding_test_config();
        config.fast_dims = Some(2);
        config.hnsw.m_max_0 = 1;
        config.hnsw.ef_construction = 8;
        config.hnsw.ef_search = 8;
        let (_dir, vault) = open_test_vault_with(config);
        let ids: Vec<_> = (50..56).map(entity).collect();
        for (index, id) in ids.iter().enumerate() {
            vault.put_entity(id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
            vault.put_vector(id, &[1.0, 1.0, index as f32, (5 - index) as f32])?;
        }
        vault.with_write_txn(|txn| {
            let graph = hnsw::build_hnsw_graph_from_snapshot(
                &vault.store,
                &vault.config,
                txn,
                &ids,
                discipline,
            )?;
            hnsw::write_rebuilt_hnsw(&vault.store, txn, &graph, discipline)
        })?;
        let search = || -> Result<Vec<Vec<(EntityId, u32)>>> {
            let txn = vault.store.env.read_txn()?;
            let mut results = Vec::new();
            for query in [&[1.0, 1.0][..], &[1.0, 1.0, 2.0, 3.0][..]] {
                for skip_rescore in [false, true] {
                    results.push(
                        hnsw::hnsw_search(
                            &vault.store,
                            &vault.config,
                            &txn,
                            query,
                            4,
                            skip_rescore,
                        )?
                        .into_iter()
                        .map(|row| (row.id, row.score.to_bits()))
                        .collect(),
                    );
                }
            }
            Ok(results)
        };
        let expected = search()?;
        drop_graph(&vault)?;
        let revision = vault.store.env.info().last_txn_id;
        assert_eq!(expected, search()?);
        assert_eq!(vault.store.env.info().last_txn_id, revision);
        assert!(dropped(&vault)?);
        let txn = vault.store.env.read_txn()?;
        assert_eq!(hnsw::read_link_discipline(&vault.store, &txn)?, discipline);
    }
    Ok(())
}
