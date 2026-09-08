//! Provenanced and timestamped edge builders, replay and delete-edge guards.

use super::*;

struct EdgeFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    edge: EdgeRef,
    claim_id: EntityId,
}

type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
    let rtxn = vault.store.env.read_txn()?;
    let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
    let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
    let out = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .map(|value| value.to_vec());
    let inn = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .map(|value| value.to_vec());
    Ok((out, inn))
}

fn assert_edge_is_provenanced_reject(err: Error, expected_kind: EdgeKind, context: &str) {
    match err {
        Error::EdgeIsProvenanced { kind } => {
            assert_eq!(kind, expected_kind as u8, "{context}: kind byte");
        }
        other => panic!("{context}: expected EdgeIsProvenanced, got {other:?}"),
    }
}

fn assert_raw_edge_unchanged(
    vault: &Vault,
    edge: &EdgeRef,
    before: &[u8],
    context: &str,
) -> Result<()> {
    let (after_out, after_in) = raw_edge_values(vault, edge)?;
    assert_eq!(
        after_out.as_deref(),
        Some(before),
        "{context}: edges_out must stay byte-identical"
    );
    assert_eq!(
        after_in.as_deref(),
        Some(before),
        "{context}: edges_in must stay byte-identical"
    );
    Ok(())
}

fn provenanced_edge_fixture() -> Result<EdgeFixture> {
    let (dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let actor = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &edge,
        &EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    Ok(EdgeFixture {
        _dir: dir,
        vault,
        edge,
        claim_id,
    })
}

#[test]
fn public_timestamped_builder_rejects_over_provenanced_edge() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let vad = Vad {
        valence: 0.1,
        arousal: 0.2,
        dominance: 0.3,
    };

    let (before_out, before_in) = raw_edge_values(vault, &fixture.edge)?;
    let before_out = before_out.expect("provenanced edge");
    assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at(&src, kind, &tgt, 0.5, 2_000)
        .commit()
        .expect_err("batch edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at",
    )?;

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_001, vad)
        .commit()
        .expect_err("batch edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at_and_vad",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at(&src, kind, &tgt, 0.5, 2_002)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_003, vad)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at_and_vad",
    )?;

    let claim = vault
        .get_claim(&fixture.claim_id)?
        .expect("provenance claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn public_timestamped_builder_accepts_over_bare_edge() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let src = EntityId::now();
    let tgt = EntityId::now();
    let absent_tgt = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&absent_tgt, ENTITY_TYPE_PERSON, occurred, 1, b"absent")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let bare_edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    vault
        .batch()
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.5, 2_000)
        .commit()?;
    let (bare_out, bare_in) = raw_edge_values(&vault, &bare_edge)?;
    let bare_out = bare_out.expect("bare edge");
    assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(bare_in.as_deref(), Some(bare_out.as_slice()));

    let absent_edge = EdgeRef::new(src, EdgeKind::About, absent_tgt);
    vault
        .batch()
        .edge_with_created_at_and_vad(&src, EdgeKind::About, &absent_tgt, 0.5, 2_001, Vad::NEUTRAL)
        .commit()?;
    let (absent_out, absent_in) = raw_edge_values(&vault, &absent_edge)?;
    let absent_out = absent_out.expect("formerly absent edge");
    assert_eq!(absent_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(absent_in.as_deref(), Some(absent_out.as_slice()));
    Ok(())
}

#[test]
fn public_timestamped_builder_keeps_structural_edge_layout() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let child = EntityId::now();
    let parent = EntityId::now();
    let occurred = test_time_range(1, 1);
    // Milestone -> Task is the matrix-valid pair (ONE-1376); this test is
    // about the structural edge value layout, not about nesting.
    vault.put_entity(
        &parent,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(TaskRole::Milestone),
    )?;
    vault.put_entity(
        &child,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::habit::task_body_for_test(TaskRole::Task),
    )?;

    vault
        .batch()
        .edge_with_created_at(&child, EdgeKind::ChildOf, &parent, 0.5, 2_000)
        .commit()?;

    let edge = EdgeRef::new(child, EdgeKind::ChildOf, parent);
    let (out, inn) = raw_edge_values(&vault, &edge)?;
    let out = out.expect("structural edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(
            &child,
            EdgeKind::ChildOf,
            &parent,
            0.5,
            2_001,
            Vad {
                valence: 0.1,
                arousal: 0.2,
                dominance: 0.3,
            },
        )
        .commit()
        .expect_err("structural edge must reject VAD payload");
    assert!(
        matches!(
            err,
            Error::InvariantViolation("structural edges do not carry VAD")
        ),
        "expected structural VAD rejection, got {err:?}"
    );
    assert_raw_edge_unchanged(&vault, &edge, &out, "structural VAD rejection")?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replay_edge_with_created_at_accepts_bare_over_provenanced() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let (before_out, _) = raw_edge_values(vault, &fixture.edge)?;
    assert_eq!(
        before_out.expect("provenanced edge").len(),
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    );

    vault.with_write_txn(|wtxn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight: 0.91,
                created_at: 3_000,
                vad: Vad::NEUTRAL,
                provenance: None,
            }],
            true,
            false,
            false,
        )
    })?;

    let (after_out, after_in) = raw_edge_values(vault, &fixture.edge)?;
    let after_out = after_out.expect("replayed edge");
    assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(after_in.as_deref(), Some(after_out.as_slice()));
    Ok(())
}

/// ONE-1608 apply-side backstop: the generic edge-delete apply refuses
/// `EdgeKind::Blocks` outright.
///
/// `code_memory::remove_blocks_edge` is the ONE retirement door, and it
/// deletes its two rows itself — it never routes through this function — so
/// nothing legitimate reaches this arm with the kind. The refusal is
/// therefore FAIL-CLOSED rather than a silent skip: a `blocks` delete landing
/// here means some path staged an op it had no authority to stage, and
/// aborting the batch is the honest outcome. Pre-fix, a forged CRDT removal
/// drained into exactly this call and tore BOTH index rows out with no actor
/// gate; the sync arm now quarantines that op, and this is the second door
/// behind it.
#[test]
fn apply_delete_edge_refuses_blocks_and_leaves_both_index_rows_intact() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let blocker = EntityId::from_bytes([0xB1; 16])?;
    let blocked = EntityId::from_bytes([0xB2; 16])?;
    let actor_id = EntityId::from_bytes([0xB3; 16])?;
    let range = test_time_range(1, 1);
    for (id, entity_type) in [
        (&blocker, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&blocked, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&actor_id, ENTITY_TYPE_PERSON),
    ] {
        vault.put_entity(id, entity_type, range, 1, b"x")?;
    }

    // Seeded through the real door, so the rows under test are the exact
    // bytes a genuine `blocks` edge has.
    let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
    let ctx = crate::code_memory::BlocksWriteContext {
        actor: &actor,
        source: ClaimSource::UserStated,
    };
    vault.insert_blocks_edge(blocker, blocked, ctx)?;
    let edge = EdgeRef::new(blocker, EdgeKind::Blocks, blocked);
    let (before_out, before_in) = raw_edge_values(&vault, &edge)?;
    let before_out = before_out.expect("precondition: the door wrote the edges_out row");
    assert_eq!(
        before_in.as_deref(),
        Some(before_out.as_slice()),
        "precondition: the door mirrors identical bytes into edges_in"
    );

    let err = vault
        .with_write_txn(|wtxn| {
            apply_delete_edge(&vault.store, wtxn, blocker, EdgeKind::Blocks, blocked)
        })
        .expect_err("a blocks delete must never apply");
    // The EXISTING typed variant carries the refusal — no new error shape.
    assert_eq!(err.kind(), ErrorKind::ReservedEdgeKind);
    assert_matches!(err, Error::ReservedEdgeKind("blocks"));

    assert_raw_edge_unchanged(&vault, &edge, &before_out, "refused blocks delete")?;
    assert_eq!(
        vault.blocks_dependencies(blocker)?,
        vec![blocked],
        "the readiness edge stays readable through its own door"
    );
    Ok(())
}
