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
            crate::error::Error::Sync(crate::error::SyncError::IdentityTopologyRejected(
                crate::identity_topology::IdentityTopologyRejection::NotActive {
                    entity,
                    state: crate::identity_topology::EntityLifecycleState::Split,
                }
            )) if entity == retired
        ),
        "expected NotActive on the retired shell, got {err:?}"
    );
    assert_eq!(resolved(&vault, &retired), Vec::<EntityId>::new());
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
            )
            .unwrap(),
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
