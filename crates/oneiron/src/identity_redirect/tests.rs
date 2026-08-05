//! ONE-1744 (MS-02) unit tests: redirect-row derivation, resolve semantics
//! (0/1/N + transitive chains), the CID-7 drop/rebuild doors, incremental
//! maintenance on both the local and sync-reconcile chokepoints, the
//! zero-head split lift, and the cycle guard.
//!
//! Fixture seeds live in `0xC5..=0xD3`, outside `PINNED_ID_BYTES`.

use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::identity_topology::{
    IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp, ReassignmentMap, SplitOp,
    SurvivorshipPlan,
};
use crate::temporal::TimeRange;
use crate::test_util::embedding_test_config;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(embedding_test_config())
}

fn id(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let person = id(byte);
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"redirect fixture",
        )
        .expect("put person");
    person
}

fn evidence() -> crate::identity_topology::IdentityOpEvidence {
    crate::identity_topology::IdentityOpEvidence {
        refs: Vec::new(),
        rationale: "redirect fixture".to_owned(),
    }
}

fn apply(vault: &Vault, op: &IdentityTopologyOp, now: u64) -> EntityId {
    let outcome = vault
        .apply_identity_topology_op(op, &IdentityOpWrite::auto(ClaimSource::Inferred), now)
        .expect("apply op");
    match outcome {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("expected Applied, got {other:?}"),
    }
}

fn merge(vault: &Vault, sources: Vec<EntityId>, survivor: EntityId, now: u64) -> EntityId {
    apply(
        vault,
        &IdentityTopologyOp::Merge(MergeOp {
            sources,
            survivor,
            evidence: evidence(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        now,
    )
}

fn split(vault: &Vault, entity: EntityId, heads: Vec<EntityId>, now: u64) -> EntityId {
    apply(
        vault,
        &IdentityTopologyOp::Split(SplitOp {
            entity,
            heads,
            reassignment: ReassignmentMap::default(),
            evidence: evidence(),
        }),
        now,
    )
}

fn resolved(vault: &Vault, id: &EntityId) -> Vec<EntityId> {
    vault.resolve_entity(id).expect("resolve")
}

/// Every id the projection currently holds a row for, with its heads —
/// the byte-level table snapshot the rebuild-identity assert compares.
fn table_snapshot(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, REDIRECT_TABLE_META_PREFIX)
        .expect("prefix iter")
        .map(|row| {
            let (key, value) = row.expect("row");
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

#[test]
fn live_entity_resolves_to_itself() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0xC5);
    assert_eq!(resolved(&vault, &person), vec![person]);
    // A live entity holds NO row: absence is the identity resolution, so a
    // dropped table degrades to identity rather than to a wrong head.
    assert!(table_snapshot(&vault).is_empty());
}

#[test]
fn merged_shell_resolves_to_the_single_survivor() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);
    merge(&vault, vec![loser], survivor, 200);

    assert_eq!(resolved(&vault, &loser), vec![survivor]);
    // The survivor stays live — a merge shells only its sources.
    assert_eq!(resolved(&vault, &survivor), vec![survivor]);
}

#[test]
fn split_shell_resolves_to_the_exact_head_set() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0xC5);
    let head_a = put_person(&vault, 0xC6);
    let head_b = put_person(&vault, 0xC7);
    let head_c = put_person(&vault, 0xC8);
    split(&vault, original, vec![head_a, head_b, head_c], 200);

    let mut expected = vec![head_a, head_b, head_c];
    expected.sort_unstable();
    assert_eq!(resolved(&vault, &original), expected);
}

#[test]
fn zero_head_split_applies_and_resolves_to_the_empty_set() {
    let (_dir, vault) = open_vault();
    let retired = put_person(&vault, 0xC5);

    // The MS-01 `EmptyHeads` rejection is LIFTED (ONE-1744): this applies.
    let (_, transitions) = match vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Split(SplitOp {
                entity: retired,
                heads: Vec::new(),
                reassignment: ReassignmentMap::default(),
                evidence: evidence(),
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            200,
        )
        .expect("zero-head split applies")
    {
        IdentityOpOutcome::Applied { event, transitions } => (event, transitions),
        other => panic!("expected Applied, got {other:?}"),
    };

    // The entity is shelled — a terminal state, not `Active`.
    assert_eq!(
        transitions,
        vec![(
            retired,
            crate::identity_topology::EntityLifecycleState::Split
        )]
    );
    assert_eq!(
        vault.entity_lifecycle_state(&retired).expect("state"),
        crate::identity_topology::EntityLifecycleState::Split
    );
    // Empty set is a legal resolution: the id is "gone", not redirected.
    assert_eq!(resolved(&vault, &retired), Vec::<EntityId>::new());
    // It leaves NO shell edge — the ledger is its only witness, which is
    // exactly why the rebuild input is edges PLUS the type-76 ledger.
    assert!(
        vault
            .edges_out(&retired)
            .expect("edges out")
            .iter()
            .all(|edge| !matches!(
                edge.kind,
                crate::edge::EdgeKind::MergedInto | crate::edge::EdgeKind::SplitInto
            ))
    );
}

#[test]
fn zero_head_shell_is_not_a_live_merge_target() {
    let (_dir, vault) = open_vault();
    let retired = put_person(&vault, 0xC5);
    let survivor = put_person(&vault, 0xC6);
    split(&vault, retired, Vec::new(), 200);

    // The regression the lift would otherwise open: the retired entity has
    // no shell EDGE, so an edge-only lifecycle read would call it `Active`,
    // admit this merge, and write an edge the fold then rejects `NotActive`
    // — ledger and edge truth diverging permanently.
    let err = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![retired],
                survivor,
                evidence: evidence(),
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            300,
        )
        .expect_err("merging a retired shell must reject");
    assert!(
        matches!(
            err,
            crate::error::Error::IdentityTopologyRejected(
                crate::identity_topology::IdentityTopologyRejection::NotActive {
                    entity,
                    state: crate::identity_topology::EntityLifecycleState::Split,
                }
            ) if entity == retired
        ),
        "expected NotActive on the retired shell, got {err:?}"
    );
    assert_eq!(resolved(&vault, &retired), Vec::<EntityId>::new());
}

#[test]
fn chains_resolve_transitively() {
    let (_dir, vault) = open_vault();
    let first = put_person(&vault, 0xC5);
    let middle = put_person(&vault, 0xC6);
    let final_head = put_person(&vault, 0xC7);

    // first -> middle, then middle -> final: resolving `first` must walk
    // through the intermediate shell to the live head.
    merge(&vault, vec![first], middle, 200);
    merge(&vault, vec![middle], final_head, 300);

    assert_eq!(resolved(&vault, &first), vec![final_head]);
    assert_eq!(resolved(&vault, &middle), vec![final_head]);
}

#[test]
fn split_then_merge_chain_resolves_through_both_hops() {
    let (_dir, vault) = open_vault();
    let original = put_person(&vault, 0xC5);
    let head_a = put_person(&vault, 0xC6);
    let head_b = put_person(&vault, 0xC7);
    let survivor = put_person(&vault, 0xC8);

    split(&vault, original, vec![head_a, head_b], 200);
    // One of the split's heads is later merged away.
    merge(&vault, vec![head_a], survivor, 300);

    // The original resolves to the SURVIVING frontier: head_a's redirect is
    // followed, head_b stands.
    let mut expected = vec![survivor, head_b];
    expected.sort_unstable();
    assert_eq!(resolved(&vault, &original), expected);
}

#[test]
fn undo_restores_identity_resolution() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);
    let event = merge(&vault, vec![loser], survivor, 200);
    assert_eq!(resolved(&vault, &loser), vec![survivor]);

    vault
        .undo_identity_topology_event(&event, &IdentityOpWrite::auto(ClaimSource::Inferred), 300)
        .expect("undo merge");

    // The redirect row is retracted with the edge: an undone merge leaves no
    // stale redirect behind.
    assert_eq!(resolved(&vault, &loser), vec![loser]);
    assert!(table_snapshot(&vault).is_empty());
}

#[test]
fn drop_degrades_to_identity_and_rebuild_restores_every_answer() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);
    let original = put_person(&vault, 0xC7);
    let head_a = put_person(&vault, 0xC8);
    let head_b = put_person(&vault, 0xC9);
    let retired = put_person(&vault, 0xCA);

    merge(&vault, vec![loser], survivor, 200);
    split(&vault, original, vec![head_a, head_b], 300);
    // The zero-head arm is IN the fixture: it is the row a from-edges-only
    // rebuild cannot reproduce, so it is the one that proves the rebuild
    // input is edges PLUS the type-76 ledger.
    split(&vault, retired, Vec::new(), 400);

    let before_table = table_snapshot(&vault);
    let before_answers: Vec<Vec<EntityId>> = [loser, original, retired, survivor]
        .iter()
        .map(|id| resolved(&vault, id))
        .collect();

    vault.drop_redirect_projection().expect("drop");
    assert!(table_snapshot(&vault).is_empty());
    // A dropped table degrades to identity — never to a wrong head.
    assert_eq!(resolved(&vault, &loser), vec![loser]);
    assert_eq!(resolved(&vault, &original), vec![original]);
    assert_eq!(resolved(&vault, &retired), vec![retired]);

    vault
        .rebuild_redirect_projection_from_edges()
        .expect("rebuild");

    // Byte-identical table AND identical resolve answers.
    assert_eq!(table_snapshot(&vault), before_table);
    let after_answers: Vec<Vec<EntityId>> = [loser, original, retired, survivor]
        .iter()
        .map(|id| resolved(&vault, id))
        .collect();
    assert_eq!(after_answers, before_answers);
    assert_eq!(resolved(&vault, &retired), Vec::<EntityId>::new());
}

#[test]
fn rebuild_is_idempotent_and_repairs_a_corrupted_table() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);
    merge(&vault, vec![loser], survivor, 200);
    let canonical = table_snapshot(&vault);

    // Plant a WRONG row: a projection is not truth, so a rebuild must
    // overwrite it from the edges rather than trust it.
    let stranger = put_person(&vault, 0xC7);
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(
                wtxn,
                &redirect_key(&loser),
                &encode_redirect_row(&[stranger]),
            )
        })
        .expect("plant bad row");
    assert_eq!(resolved(&vault, &loser), vec![stranger]);

    vault
        .rebuild_redirect_projection_from_edges()
        .expect("rebuild");
    assert_eq!(table_snapshot(&vault), canonical);
    assert_eq!(resolved(&vault, &loser), vec![survivor]);

    // Running it twice changes nothing.
    vault
        .rebuild_redirect_projection_from_edges()
        .expect("rebuild again");
    assert_eq!(table_snapshot(&vault), canonical);
}

#[test]
fn sync_reconcile_maintains_the_table_including_the_zero_head_arm() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);
    let retired = put_person(&vault, 0xC7);
    merge(&vault, vec![loser], survivor, 200);
    split(&vault, retired, Vec::new(), 300);
    let canonical = table_snapshot(&vault);

    // Drop the table WITHOUT rebuilding, then run the sync-ingest twin: the
    // reconcile chokepoint must restore every row on its own, because a
    // sync-ingested topology event reaches the table through this door and
    // never through the local apply door.
    vault.drop_redirect_projection().expect("drop");
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .expect("reconcile");

    assert_eq!(table_snapshot(&vault), canonical);
    assert_eq!(resolved(&vault, &loser), vec![survivor]);
    // The zero-head row is the one the reconciler stages NO edge op for, so
    // it is the row an early-return-on-empty-ops hook would have missed.
    assert_eq!(resolved(&vault, &retired), Vec::<EntityId>::new());
}

#[test]
fn resolution_never_rewrites_a_claim_subject() {
    let (_dir, vault) = open_vault();
    let survivor = put_person(&vault, 0xC5);
    let loser = put_person(&vault, 0xC6);

    let note = id(0xC7);
    vault
        .put_claim(
            &note,
            &ClaimBody::new(
                "core.conflict.open",
                ClaimSubject::Entity(loser),
                rmpv::Value::from("pre-merge note"),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put claim");

    merge(&vault, vec![loser], survivor, 200);
    // Resolving does not mutate anything either.
    assert_eq!(resolved(&vault, &loser), vec![survivor]);

    // r6: the stored subject is STILL the pre-merge id. An eager rewrite
    // (the Wikidata unmerge killer) would have moved it to the survivor and
    // destroyed the provenance an unmerge needs.
    let stored = vault
        .get_claim(&note)
        .expect("read claim")
        .expect("claim exists");
    assert_eq!(stored.subject, ClaimSubject::Entity(loser));
}

#[test]
fn cycle_and_depth_guards_error_instead_of_hanging() {
    let (_dir, vault) = open_vault();
    let first = put_person(&vault, 0xC5);
    let second = put_person(&vault, 0xC6);

    // No door can build a cycle (the apply path refuses to shell a shell),
    // so this is a synthetic on-disk-corruption fixture written straight
    // into the projection.
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(
                wtxn,
                &redirect_key(&first),
                &encode_redirect_row(&[second]),
            )?;
            vault
                .store
                .vault_meta
                .put(wtxn, &redirect_key(&second), &encode_redirect_row(&[first]))
        })
        .expect("plant cycle");

    let err = vault
        .resolve_entity(&first)
        .expect_err("a cycle must error, not hang");
    assert!(
        matches!(err, crate::error::Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}"
    );

    // A self-loop is the degenerate case and takes the same door.
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, &redirect_key(&first), &encode_redirect_row(&[first]))
        })
        .expect("plant self loop");
    assert!(matches!(
        vault.resolve_entity(&first),
        Err(crate::error::Error::CorruptedIndex(_))
    ));
}

#[test]
fn depth_guard_bounds_an_acyclic_chain_independently_of_the_cycle_guard() {
    let (_dir, vault) = open_vault();

    // An ACYCLIC chain longer than the bound: the cycle guard never fires
    // here (no id repeats), so this pins the depth guard on its own. The two
    // guards are independent — a `path.len()` bound would be no backstop for
    // a cycle, where the path set stops growing while the stack does not.
    let chain: Vec<EntityId> = (0..=u8::try_from(MAX_REDIRECT_CHAIN_DEPTH).expect("bound fits"))
        .map(|step| EntityId::from_bytes([0x30 + step % 0x40; 16]).unwrap_or_else(|_| id(0xC5)))
        .collect();
    let links: Vec<(EntityId, EntityId)> = chain
        .windows(2)
        .map(|pair| (pair[0], pair[1]))
        .filter(|(from, to)| from != to)
        .collect();
    vault
        .with_write_txn(|wtxn| {
            for (from, to) in &links {
                vault.store.vault_meta.put(
                    wtxn,
                    &redirect_key(from),
                    &encode_redirect_row(&[*to]),
                )?;
            }
            Ok(())
        })
        .expect("plant long chain");

    let err = vault
        .resolve_entity(&chain[0])
        .expect_err("an over-long chain must error, not recurse unbounded");
    assert!(
        matches!(err, crate::error::Error::CorruptedIndex(_)),
        "expected CorruptedIndex, got {err:?}"
    );
}

#[test]
fn redirect_row_codec_round_trips_and_refuses_malformed_bytes() {
    let a = id(0xC5);
    let b = id(0xC6);

    for heads in [Vec::new(), vec![a], vec![a, b]] {
        let encoded = encode_redirect_row(&heads);
        assert_eq!(decode_redirect_row(&encoded).expect("decode"), heads);
    }

    // Empty row (no version byte), wrong version, and a truncated id are all
    // shapes the encoder cannot produce.
    assert!(decode_redirect_row(&[]).is_err());
    assert!(decode_redirect_row(&[REDIRECT_ROW_VERSION + 1]).is_err());
    assert!(decode_redirect_row(&[REDIRECT_ROW_VERSION, 0x01, 0x02]).is_err());
}

#[test]
fn carrier_class_is_exported_and_stable() {
    // MS-07 (ONE-1749) registers this exact string in the ARCH-0038 carrier
    // list; it is a wire-visible name, so a rename is a breaking change.
    assert_eq!(REDIRECT_CARRIER_CLASS, "redirect_table");
    assert_eq!(crate::REDIRECT_CARRIER_CLASS, REDIRECT_CARRIER_CLASS);
}
