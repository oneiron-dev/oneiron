//! Done-means for the batched dependent walk (rule 5: no erase refuses for
//! its count of dependents): every door completes past the batch row, a read
//! mid-walk already sees the withdrawal, a restart resumes the walk, and the
//! threshold asks its question once.

use super::{DependentWalkDoor, DependentWalkPolicy};
use crate::config::VaultConfig;
use crate::deletion::{DeleteEntityOptions, TombstoneReason, TombstoneValueV2};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::TombstoneStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::settings::CarriedWorlds;
use crate::test_util::entity;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

const NEEDLE: &str = "walkneedle";
/// Two dependents a transaction, and a question past three.
const SMALL: DependentWalkPolicy = DependentWalkPolicy {
    batch: 2,
    check_threshold: 3,
};

fn at(second: u64) -> TimeRange {
    TimeRange {
        start: second,
        end: second,
    }
}

fn body(value: &serde_json::Value) -> Vec<u8> {
    rmp_serde::to_vec_named(value).expect("body")
}

fn epoch_body(epoch: u64, text: &str) -> Result<Vec<u8>> {
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochSummaryBody,
        encode_epoch_summary_body,
    };
    encode_epoch_summary_body(&EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: entity(0x71).to_hex(),
        epoch,
        turn_start: epoch * 3,
        turn_end: epoch * 3 + 2,
        level: EPOCH_SUMMARY_LEVEL,
        text: text.into(),
        actor: entity(0x72).to_hex(),
    })
}

fn open() -> (tempfile::TempDir, Vault) {
    let (tmp, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    vault.set_dependent_walk_policy(SMALL).expect("policy");
    (tmp, vault)
}

/// The source each door walks: what it erases, purges or changes.
fn put_source(vault: &Vault, door: DependentWalkDoor, source: &EntityId) -> Result<()> {
    match door {
        DependentWalkDoor::ChangedDocsSource => vault.put_entity(
            source,
            ENTITY_TYPE_ASSET_TEXT,
            at(1),
            1,
            &body(&serde_json::json!({ "source": "imported", "text": "first page" })),
        ),
        DependentWalkDoor::UnmadeEpoch => vault.put_entity(
            source,
            ENTITY_TYPE_SUMMARY,
            at(1),
            1,
            &epoch_body(1, "steps 3-5")?,
        ),
        _ => vault.put_entity(
            source,
            ENTITY_TYPE_TURN,
            at(1),
            1,
            &body(&serde_json::json!({ "txt": "the source" })),
        ),
    }
}

/// Five dependents of `source`, each carrying the needle.
fn derive_five(vault: &Vault, source: &EntityId) -> Result<Vec<EntityId>> {
    let dependents: Vec<_> = (0x60..0x65).map(entity).collect();
    let mut batch = vault.batch();
    for dependent in &dependents {
        batch = batch
            .put(
                dependent,
                ENTITY_TYPE_TURN,
                at(2),
                2,
                &body(&serde_json::json!({ "txt": NEEDLE })),
            )
            .text(dependent, &[("body", NEEDLE)])
            .edge(dependent, EdgeKind::DerivedFrom, source, 1.0);
    }
    batch.commit()?;
    Ok(dependents)
}

/// The real door that walks `source`'s dependents for `door`.
fn walk_through(vault: &Vault, door: DependentWalkDoor, source: &EntityId) -> Result<()> {
    match door {
        DependentWalkDoor::SoftErase => vault.delete_entity(source).map(drop),
        DependentWalkDoor::Purge => vault
            .delete_entity_with_options(source, DeleteEntityOptions { purge: true })
            .map(drop),
        DependentWalkDoor::Tombstone => vault.with_write_txn(|txn| {
            crate::ports::TombstoneStore::port_tombstone_create(
                vault,
                txn,
                source,
                TombstoneValueV2 {
                    reason: TombstoneReason::UserDelete,
                    deleted_at: 3,
                    request_id: [9; 16],
                },
            )
        }),
        DependentWalkDoor::ChangedDocsSource => vault.put_entity(
            source,
            ENTITY_TYPE_ASSET_TEXT,
            at(1),
            3,
            &body(&serde_json::json!({ "source": "imported", "text": "second page" })),
        ),
        DependentWalkDoor::UnmadeEpoch => vault.put_entity(
            source,
            ENTITY_TYPE_SUMMARY,
            at(1),
            3,
            &body(&serde_json::json!({ "text": "no epoch any more" })),
        ),
    }
}

fn withdrawn(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault.store.port_deletion_state(&txn, id)?.stale)
}

fn withdrawn_worlds(vault: &Vault, id: &EntityId) -> Result<Option<CarriedWorlds>> {
    let txn = vault.store.env.read_txn()?;
    crate::ports::withdrawn_worlds_in(&vault.store, &txn, id)
}

fn found(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    Ok(vault
        .search_text(NEEDLE, 20)?
        .into_iter()
        .map(|hit| hit.id)
        .collect())
}

/// The code's own list of dependent-walk doors, each driven for real past
/// the batch row: none refuses, each leaves its walk named for itself, every
/// dependent reads withdrawn before the walk reaches it, and the walk
/// finishes with one question.
#[test]
fn no_dependent_walk_door_refuses_for_a_count() -> Result<()> {
    for door in DependentWalkDoor::ALL {
        let (_tmp, vault) = open();
        let source = entity(0x5B);
        put_source(&vault, door, &source)?;
        let dependents = derive_five(&vault, &source)?;
        assert_eq!(
            found(&vault)?,
            dependents.iter().copied().collect(),
            "{door:?}: the dependents read live before the walk"
        );

        // The device stops right after the transaction that marked the walk.
        vault.store.test_hooks.stop_dependent_walks_after(0);
        walk_through(&vault, door, &source)?;
        let pending = vault.pending_dependent_walks()?;
        assert_eq!(
            pending.len(),
            1,
            "{door:?}: the walk goes on past one batch"
        );
        assert_eq!(pending[0].document, source);
        assert_eq!(pending[0].door, door.code());
        for dependent in &dependents {
            assert!(
                withdrawn(&vault, dependent)?,
                "{door:?}: a dependent the walk has not reached reads withdrawn"
            );
        }
        assert!(found(&vault)?.is_empty(), "{door:?}: search finds none");

        vault
            .store
            .test_hooks
            .stop_dependent_walks_after(usize::MAX);
        vault.finish_dependent_walks()?;
        assert!(vault.pending_dependent_walks()?.is_empty());
        for dependent in &dependents {
            assert!(
                withdrawn(&vault, dependent)?,
                "{door:?}: every dependent is withdrawn"
            );
        }
        assert!(found(&vault)?.is_empty());
        let checks = vault.dependent_walk_checks()?;
        assert_eq!(checks.len(), 1, "{door:?}: the threshold asks once");
        assert_eq!(checks[0].document, source.to_hex());
        assert_eq!(checks[0].door, door.code());
        assert_eq!(checks[0].threshold, SMALL.check_threshold);
        assert!(checks[0].walked > SMALL.check_threshold);
    }
    Ok(())
}

/// An epoch summary written from a dependent carries the erased words too:
/// mid-walk it reads withdrawn, for the same worlds, before its batch comes.
#[test]
fn a_read_mid_walk_sees_epoch_summaries_withdrawn_as_after_it() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::SoftErase, &source)?;
    let mut dependents = derive_five(&vault, &source)?;
    // Last in key order, so the first batch leaves both summaries pending.
    let (summary, nested) = (entity(0xEE), entity(0xEF));
    vault
        .batch()
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            at(4),
            4,
            &epoch_body(2, "steps 6-8")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &source, 1.0)
        .put(
            &nested,
            ENTITY_TYPE_SUMMARY,
            at(5),
            5,
            &epoch_body(3, "steps 9-11")?,
        )
        .edge(&nested, EdgeKind::DerivedFrom, &summary, 1.0)
        .commit()?;
    dependents.extend([summary, nested]);
    for id in &dependents {
        assert!(!withdrawn(&vault, id)?);
    }

    vault.store.test_hooks.stop_dependent_walks_after(0);
    assert!(vault.delete_entity(&source)?);
    let mid_walk = dependents
        .iter()
        .map(|id| Ok((withdrawn(&vault, id)?, withdrawn_worlds(&vault, id)?)))
        .collect::<Result<Vec<_>>>()?;
    assert!(mid_walk.iter().all(|(stale, _)| *stale));

    vault
        .store
        .test_hooks
        .stop_dependent_walks_after(usize::MAX);
    vault.finish_dependent_walks()?;
    let after = dependents
        .iter()
        .map(|id| Ok((withdrawn(&vault, id)?, withdrawn_worlds(&vault, id)?)))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        mid_walk, after,
        "a read mid-walk answers as the finished walk does"
    );
    Ok(())
}

/// A device that stops mid-walk finishes the walk when it opens again.
#[test]
fn a_restart_mid_walk_resumes_and_finishes() -> Result<()> {
    let (tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::SoftErase, &source)?;
    let dependents = derive_five(&vault, &source)?;
    vault.store.test_hooks.stop_dependent_walks_after(1);
    assert!(vault.delete_entity(&source)?);
    let pending = vault.pending_dependent_walks()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].walked, 4, "the marking batch and one more ran");
    drop(vault);

    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    assert!(
        vault.pending_dependent_walks()?.is_empty(),
        "the open finished it"
    );
    for dependent in &dependents {
        assert!(withdrawn(&vault, dependent)?);
    }
    assert!(found(&vault)?.is_empty());
    assert_eq!(vault.dependent_walk_checks()?.len(), 1);
    Ok(())
}
