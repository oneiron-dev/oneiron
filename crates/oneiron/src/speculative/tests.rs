use std::sync::Arc;

use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::temporal::TimeRange;

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 32 * 1024 * 1024;
    config.embedding_model = Some("test-model-v1".to_owned());
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, Arc::new(vault))
}

fn entity_id(byte: u8) -> EntityId {
    let mut bytes = [byte; 16];
    bytes[0] = 0x5e;
    EntityId::from_bytes(bytes).expect("valid entity id")
}

fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .commit()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn partial<'a>(text: &'a str, labels: &'a [String], terms: &'a [String]) -> SpeculativePartial<'a> {
    SpeculativePartial {
        text,
        query_vector: None,
        entity_labels: labels,
        salient_terms: terms,
    }
}

fn count_runs(vault: &Vault, action: RetrievalAction) -> Result<usize> {
    Ok(vault
        .retrieval_runs(200)?
        .into_iter()
        .filter(|run| run.action == action)
        .count())
}

#[test]
fn refires_only_on_signature_diff() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_text(&vault, entity_id(0x11), "kyoto trip planning")?;
    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());

    let labels = strings(&["Kyoto"]);
    let terms = strings(&["trip"]);
    let first = session.observe_partial(partial("kyoto", &labels, &terms))?;
    assert!(matches!(first, SpeculativeFireDecision::Fired { .. }));

    // Same meaning, growing text — and normalization: trim + lowercase.
    let labels_recased = strings(&["  kyoto "]);
    let terms_recased = strings(&["TRIP"]);
    for text in ["kyoto tri", "kyoto trip", "kyoto trip pla"] {
        let decision = session.observe_partial(partial(text, &labels_recased, &terms_recased))?;
        assert_eq!(decision, SpeculativeFireDecision::SkippedUnchanged);
    }

    assert_eq!(session.fires_used(), 1);
    assert_eq!(count_runs(&vault, RetrievalAction::Speculative)?, 1);
    Ok(())
}

#[test]
fn fire_cap_exhausts_after_max_fires() -> Result<()> {
    let (_dir, vault) = test_vault();
    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());

    for index in 0..6_usize {
        let labels = strings(&[&format!("entity-{index}")]);
        let decision = session.observe_partial(partial("stream", &labels, &[]))?;
        if index < 4 {
            assert!(
                matches!(decision, SpeculativeFireDecision::Fired { .. }),
                "fire {index} must fire"
            );
        } else {
            assert_eq!(decision, SpeculativeFireDecision::SkippedCapExhausted);
        }
    }
    assert_eq!(session.fires_used(), 4);
    assert_eq!(count_runs(&vault, RetrievalAction::Speculative)?, 4);
    Ok(())
}

#[test]
fn speculative_fires_are_telemetry_tagged_and_round_trip() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_text(&vault, entity_id(0x21), "tagged fixture")?;

    // Pre-existing row with another action must keep decoding alongside
    // the new variant.
    vault
        .query()
        .search_text("tagged fixture", 5)
        .run_with_telemetry()?;

    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());
    for index in 0..3_usize {
        let labels = strings(&[&format!("tag-{index}")]);
        let decision = session.observe_partial(partial("tagged fixture", &labels, &[]))?;
        assert!(matches!(decision, SpeculativeFireDecision::Fired { .. }));
    }

    let runs = vault.retrieval_runs(200)?;
    let speculative = runs
        .iter()
        .filter(|run| run.action == RetrievalAction::Speculative)
        .count();
    assert_eq!(speculative, 3, "exactly one tagged row per fire");
    assert!(
        runs.iter()
            .any(|run| run.action == RetrievalAction::Pipeline),
        "pre-existing rows must still decode"
    );

    let encoded = serde_json::to_string(&RetrievalAction::Speculative).expect("encode");
    assert_eq!(encoded, "\"speculative\"");
    let decoded: RetrievalAction = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, RetrievalAction::Speculative);
    Ok(())
}

#[test]
fn promote_path_returns_warm_pack_verbatim_with_no_new_rows() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_text(&vault, entity_id(0x31), "promote fixture alpha")?;
    put_text(&vault, entity_id(0x32), "promote fixture beta")?;

    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());
    let labels = strings(&["promote"]);
    let fired = session.observe_partial(partial("promote fixture", &labels, &[]))?;
    let SpeculativeFireDecision::Fired {
        run_id: fire_run_id,
    } = fired
    else {
        panic!("expected a fire");
    };
    let warm: Vec<ScoredEntity> = session.warm_candidates().to_vec();
    assert!(!warm.is_empty());

    let rows_before = vault.retrieval_runs(200)?.len();
    let outcome = session.finalize(partial("promote fixture done", &labels, &[]))?;
    let SpeculativeFinal::Promoted { scores, run_id } = outcome else {
        panic!("unchanged signature must promote");
    };
    assert_eq!(scores, warm, "promotion is verbatim");
    assert_eq!(run_id, fire_run_id, "run id is the promoted fire's");
    assert_eq!(
        vault.retrieval_runs(200)?.len(),
        rows_before,
        "promotion must add zero retrieval-run rows"
    );
    Ok(())
}

#[test]
fn finalize_runs_full_pass_and_warm_fills() -> Result<()> {
    let (_dir, vault) = test_vault();
    let warm_a = entity_id(0x41);
    let warm_b = entity_id(0x42);
    let fresh_c = entity_id(0x43);
    put_text(&vault, warm_a, "alfaseed apple")?;
    put_text(&vault, warm_b, "alfaseed apricot")?;
    put_text(&vault, fresh_c, "gammaseed grape")?;

    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());
    let fire_labels = strings(&["alpha"]);
    let fired = session.observe_partial(partial("alfaseed", &fire_labels, &[]))?;
    assert!(matches!(fired, SpeculativeFireDecision::Fired { .. }));
    let warm: Vec<ScoredEntity> = session.warm_candidates().to_vec();
    assert_eq!(warm.len(), 2);

    let pipeline_rows_before = count_runs(&vault, RetrievalAction::Pipeline)?;
    let final_labels = strings(&["alpha", "gamma"]);
    let outcome = session.finalize(partial("gammaseed", &final_labels, &[]))?;
    let SpeculativeFinal::Finalized {
        scores,
        run_id,
        warm_appended,
    } = outcome
    else {
        panic!("changed signature must finalize");
    };

    assert!(run_id.is_some());
    assert_eq!(
        count_runs(&vault, RetrievalAction::Pipeline)?,
        pipeline_rows_before + 1,
        "the finalize pass logs exactly one Pipeline row"
    );
    assert_eq!(warm_appended, 2);
    assert!(scores.len() <= SpeculativeSessionConfig::default().final_limit);
    // Fresh results first, then the warm-only candidates in warm order.
    assert_eq!(scores[0].id, fresh_c);
    assert_eq!(
        scores[1..]
            .iter()
            .map(|scored| scored.id)
            .collect::<Vec<_>>(),
        warm.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        "appended entries come after all fresh entries in warm order"
    );
    Ok(())
}

#[test]
fn empty_signature_never_fires() -> Result<()> {
    let (_dir, vault) = test_vault();
    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());

    let empty: Vec<String> = Vec::new();
    let whitespace = strings(&["   ", ""]);
    for _ in 0..3 {
        let decision = session.observe_partial(partial("uh so like", &empty, &whitespace))?;
        assert_eq!(decision, SpeculativeFireDecision::SkippedEmptySignature);
    }
    assert_eq!(session.fires_used(), 0);
    assert_eq!(count_runs(&vault, RetrievalAction::Speculative)?, 0);
    Ok(())
}

#[test]
fn fire_error_leaves_session_state_unchanged() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_text(&vault, entity_id(0x51), "retry fixture")?;
    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());

    let labels = strings(&["retry"]);
    let bad_vector = [f32::NAN, 0.0, 0.0, 0.0];
    let err = session
        .observe_partial(SpeculativePartial {
            text: "retry fixture",
            query_vector: Some(&bad_vector),
            entity_labels: &labels,
            salient_terms: &[],
        })
        .unwrap_err();
    assert!(
        !matches!(err, Error::InvalidConfig(_)),
        "vector component error expected: {err:?}"
    );
    assert_eq!(session.fires_used(), 0);
    assert!(session.warm_candidates().is_empty());

    // The signature was not recorded: the same partial retries and fires.
    let retried = session.observe_partial(partial("retry fixture", &labels, &[]))?;
    assert!(matches!(retried, SpeculativeFireDecision::Fired { .. }));
    assert_eq!(session.fires_used(), 1);
    Ok(())
}

#[test]
fn zero_limits_fail_closed_and_zero_cap_is_legal() -> Result<()> {
    let (_dir, vault) = test_vault();
    put_text(&vault, entity_id(0x61), "limits fixture")?;
    let labels = strings(&["limits"]);

    let mut session = SpeculativeSession::new(
        Arc::clone(&vault),
        SpeculativeSessionConfig {
            max_fires: 4,
            fire_limit: 0,
            final_limit: 20,
        },
    );
    let err = session
        .observe_partial(partial("limits fixture", &labels, &[]))
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "speculative limits must be greater than zero")
    );
    assert_eq!(session.fires_used(), 0);

    let session = SpeculativeSession::new(
        Arc::clone(&vault),
        SpeculativeSessionConfig {
            max_fires: 4,
            fire_limit: 8,
            final_limit: 0,
        },
    );
    let Err(err) = session.finalize(partial("limits fixture", &labels, &[])) else {
        panic!("final_limit == 0 must fail at the finalize fresh pass");
    };
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "speculative limits must be greater than zero")
    );

    // max_fires == 0 is a legal pure-promote session that never fires.
    let mut session = SpeculativeSession::new(
        Arc::clone(&vault),
        SpeculativeSessionConfig {
            max_fires: 0,
            fire_limit: 8,
            final_limit: 20,
        },
    );
    let decision = session.observe_partial(partial("limits fixture", &labels, &[]))?;
    assert_eq!(decision, SpeculativeFireDecision::SkippedCapExhausted);
    let outcome = session.finalize(partial("limits fixture", &labels, &[]))?;
    assert!(matches!(
        outcome,
        SpeculativeFinal::Finalized {
            warm_appended: 0,
            ..
        }
    ));
    Ok(())
}

// ===== EMB-2 hot-lane wiring (AC7) =====

fn funnel_vault() -> (tempfile::TempDir, Arc<Vault>, Vec<EntityId>, Vec<Vec<f32>>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.dimensions = 8;
    config.fast_dims = Some(4);
    config.map_size = 64 * 1024 * 1024;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.hnsw.ef_search = 128;
    let vault = Vault::open(dir.path(), config).expect("open vault");

    // v1/v2 share a prefix with opposite tails; v3 is prefix-farther but
    // full-dim-closer than v2: prefix top-2 = {v1, v2}, full top-2 = {v1, v3}.
    let vectors = vec![
        vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
        vec![1.0, 0.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0],
        vec![0.9, 0.1, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
    ];
    let mut ids = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let id = entity_id(0x70 + index as u8);
        vault
            .batch()
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")
            .vector(&id, vector)
            .commit()
            .expect("put vector");
        ids.push(id);
    }
    (dir, Arc::new(vault), ids, vectors)
}

#[test]
fn fires_ride_the_hot_lane_and_finalize_rescores() -> Result<()> {
    let (_dir, vault, ids, vectors) = funnel_vault();
    let query = vectors[0].clone();
    let mut session = SpeculativeSession::new(
        Arc::clone(&vault),
        SpeculativeSessionConfig {
            max_fires: 4,
            fire_limit: 2,
            final_limit: 2,
        },
    );

    // Text matches nothing; the vector channel drives the candidate set,
    // so the channel limit (== fire/final limit) exposes prefix vs
    // rescored ranking through set membership.
    let fire_labels = strings(&["hotlane"]);
    let fired = session.observe_partial(SpeculativePartial {
        text: "no indexed text",
        query_vector: Some(&query),
        entity_labels: &fire_labels,
        salient_terms: &[],
    })?;
    assert!(matches!(fired, SpeculativeFireDecision::Fired { .. }));
    let warm_ids: std::collections::HashSet<EntityId> = session
        .warm_candidates()
        .iter()
        .map(|scored| scored.id)
        .collect();
    assert_eq!(
        warm_ids,
        std::collections::HashSet::from([ids[0], ids[1]]),
        "fires skip the rescore: prefix top-2 admits the prefix-tied pair"
    );

    let final_labels = strings(&["hotlane", "checkout"]);
    let outcome = session.finalize(SpeculativePartial {
        text: "no indexed text",
        query_vector: Some(&query),
        entity_labels: &final_labels,
        salient_terms: &[],
    })?;
    let SpeculativeFinal::Finalized { scores, .. } = outcome else {
        panic!("changed signature must finalize");
    };
    let fresh_ids: std::collections::HashSet<EntityId> =
        scores.iter().map(|scored| scored.id).collect();
    assert_eq!(
        fresh_ids,
        std::collections::HashSet::from([ids[0], ids[2]]),
        "the finalize pass rescores: full-dim top-2 admits the tail-aligned pair"
    );
    Ok(())
}

// ===== EMB-1 hot bump through a fire (AC8) =====

#[cfg(feature = "sync")]
#[test]
fn fire_hot_bumps_pending_embedding_claims() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::registry::ENTITY_TYPE_CLAIM;
    use crate::sync::SyncQueue;

    let (_dir, vault) = test_vault();
    // The default policy manifest is itself a pending-embedding claim;
    // deindex it so the queue assertion below sees only the fixture claim
    // (same pattern as embed/tests.rs).
    let manifest_id = crate::gate::default_policy_manifest_id().expect("manifest id");
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &manifest_id)?;
        Ok(())
    })?;

    let claim_id = entity_id(0x81);
    let body = ClaimBody::new(
        "test.hotbump",
        ClaimSubject::Entity(entity_id(0x82)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let body_bytes = crate::claim::encode_claim_body(&body).expect("encode claim body");
    vault
        .batch()
        .put(
            &claim_id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &body_bytes,
        )
        .text(&claim_id, &[("body", "hotbump needle")])
        .commit()?;

    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());
    let labels = strings(&["hotbump"]);
    let fired = session.observe_partial(partial("hotbump needle", &labels, &[]))?;
    assert!(matches!(fired, SpeculativeFireDecision::Fired { .. }));

    let queue = SyncQueue::new(Arc::clone(&vault))?;
    let jobs = queue.drain_embed_jobs()?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].entity_id, claim_id);
    assert_eq!(
        jobs[0].priority,
        crate::embed::EMBED_PRIORITY_SURFACED_HOT,
        "a surfaced pending claim gets the priority-0 hot bump"
    );
    Ok(())
}

/// Grok #473-F7: warm-fill must dedupe against already-appended warm
/// entries, not only against the fresh id set — a warm-internal repeat
/// (latent today: pipeline output is unique, but the warm pack is session
/// state) must not double-append. The duplicate warm pack is injected
/// directly into the private session state to pin the guard itself.
#[test]
fn warm_fill_never_double_appends_a_warm_internal_duplicate() -> Result<()> {
    let (_dir, vault) = test_vault();
    let fresh_id = entity_id(0x91);
    let dup_id = entity_id(0x92);
    let other_id = entity_id(0x93);
    put_text(&vault, fresh_id, "dedupe fresh fixture")?;

    let mut session =
        SpeculativeSession::new(Arc::clone(&vault), SpeculativeSessionConfig::default());
    let warm_dup = ScoredEntity {
        id: dup_id,
        score: 0.5,
    };
    let warm_other = ScoredEntity {
        id: other_id,
        score: 0.4,
    };
    session.warm = Some(WarmPack {
        scores: vec![warm_dup, warm_dup, warm_other],
        run_id: None,
    });
    session.last_signature = partial_signature(&partial("x", &strings(&["warmed"]), &[]));

    let final_labels = strings(&["changed"]);
    let outcome = session.finalize(partial("dedupe fresh fixture", &final_labels, &[]))?;
    let SpeculativeFinal::Finalized {
        scores,
        warm_appended,
        ..
    } = outcome
    else {
        panic!("changed signature must finalize");
    };

    let appended_ids: Vec<EntityId> = scores.iter().skip(1).map(|scored| scored.id).collect();
    assert_eq!(scores[0].id, fresh_id);
    assert_eq!(
        appended_ids,
        vec![dup_id, other_id],
        "the warm-internal duplicate must append exactly once, in warm order"
    );
    assert_eq!(warm_appended, 2);
    Ok(())
}
