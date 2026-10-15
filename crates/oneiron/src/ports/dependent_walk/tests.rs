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
    open_with(VaultConfig::default())
}

fn open_with(config: VaultConfig) -> (tempfile::TempDir, Vault) {
    let (tmp, vault) = crate::test_util::open_test_vault_with(config);
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

/// A docs source rewritten at the same stamp: the walk it marks stays
/// pending past the first batch.
fn change_docs_source(vault: &Vault, source: &EntityId, text: &str) -> Result<()> {
    vault.put_entity(
        source,
        ENTITY_TYPE_ASSET_TEXT,
        at(1),
        1,
        &body(&serde_json::json!({ "source": "imported", "text": text })),
    )
}

fn span_of(vault: &Vault, id: &EntityId) -> Result<crate::ports::SourceSpan> {
    Ok(crate::ports::SourceSpan {
        document: *id,
        frontier: vault.read_entity_header(id)?.expect("header").learned_at,
    })
}

fn complete(
    vault: &Vault,
    id: &EntityId,
    regenerated_at: u64,
    sources: &[crate::ports::SourceSpan],
) -> Result<bool> {
    use crate::ports::DependencyIndex;
    vault.with_write_txn(|txn| {
        vault
            .store
            .port_dependency_complete_regeneration(txn, id, regenerated_at, sources)
    })
}

/// A claim derived from `source`, last in key order so the first batch
/// leaves it pending, with a lexical query hint for `hint`.
fn derive_claim(vault: &Vault, source: &EntityId, hint: &str) -> Result<EntityId> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
    let (actor, subject, claim) = (entity(0x73), entity(0x74), entity(0x75));
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"actor",
    )?;
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"subject",
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, crate::EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("fixture"))?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(&claim, candidate, &envelope, at(10), 11, &[hint])
        .edge(&claim, EdgeKind::DerivedFrom, source, 1.0)
        .commit()?;
    Ok(claim)
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

/// A docs source rewritten at the same stamp: the dependency a new
/// derivation records mid-walk is the new text's, and stays live (Sol and
/// Astra R1 on #1471).
#[test]
fn a_dependency_admitted_mid_walk_stays_live() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    let dependents = derive_five(&vault, &source)?;
    vault.put_entity(
        &source,
        ENTITY_TYPE_ASSET_TEXT,
        at(1),
        1,
        &body(&serde_json::json!({ "source": "imported", "text": "second page" })),
    )?;
    assert_eq!(vault.pending_dependent_walks()?.len(), 1);
    // Between the walk's last row done and the next it covers.
    let mut bytes = [0; 16];
    bytes[0] = 0x63;
    bytes[15] = 1;
    let fresh = EntityId::from_bytes(bytes)?;
    vault
        .batch()
        .put(
            &fresh,
            ENTITY_TYPE_TURN,
            at(4),
            4,
            &body(&serde_json::json!({ "txt": "fresh" })),
        )
        .edge(&fresh, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    assert!(
        !withdrawn(&vault, &fresh)?,
        "the new derivation reads live mid-walk"
    );
    vault.finish_dependent_walks()?;
    assert!(!withdrawn(&vault, &fresh)?, "the walk passed it by");
    for dependent in &dependents {
        assert!(withdrawn(&vault, dependent)?);
    }
    Ok(())
}

/// A dependent rewritten before the walk reaches it regenerates as it would
/// after a single-transaction walk: its completion meets the revision the
/// mark covered, not the rewrite's (Sol R1 on #1471).
#[test]
fn a_dependent_rewritten_mid_walk_regenerates() -> Result<()> {
    use crate::ports::{DependencyIndex, SourceSpan};
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    let dependents = derive_five(&vault, &source)?;
    walk_through(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    let late = dependents[4];
    assert!(withdrawn(&vault, &late)?, "past the first batch, pending");
    vault.put_entity(
        &late,
        ENTITY_TYPE_TURN,
        at(2),
        20,
        &body(&serde_json::json!({ "txt": "regenerated" })),
    )?;
    vault.finish_dependent_walks()?;
    let span = SourceSpan {
        document: source,
        frontier: vault
            .read_entity_header(&source)?
            .expect("source header")
            .learned_at,
    };
    assert!(
        vault.with_write_txn(|txn| {
            vault
                .store
                .port_dependency_complete_regeneration(txn, &late, 20, &[span])
        })?,
        "the regeneration completes"
    );
    assert!(!withdrawn(&vault, &late)?);
    Ok(())
}

/// Search mid-walk fills its limit with live records: a pending dependent
/// leaves the ranking at once, as its postings will (Astra R1 on #1471).
#[test]
fn search_mid_walk_fills_its_limit_with_live_records() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    derive_five(&vault, &source)?;
    let live = entity(0x6A);
    let words = format!("{NEEDLE} and a good many other words that dilute it");
    vault
        .batch()
        .put(
            &live,
            ENTITY_TYPE_TURN,
            at(2),
            2,
            &body(&serde_json::json!({ "txt": words })),
        )
        .text(&live, &[("body", words.as_str())])
        .commit()?;
    walk_through(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    assert_eq!(vault.pending_dependent_walks()?.len(), 1);
    let hits: Vec<_> = vault
        .search_text(NEEDLE, 1)?
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(hits, vec![live]);
    Ok(())
}

/// A body regenerated before a second change of its source, completed while
/// the walk of that change has not reached it: the walk's mark fences it, as
/// a single-transaction walk's would (Sol and Astra R2 on #1471).
#[test]
fn a_body_written_before_the_mark_never_completes_mid_walk() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    let dependents = derive_five(&vault, &source)?;
    change_docs_source(&vault, &source, "second page")?;
    vault.finish_dependent_walks()?;
    let late = dependents[4];
    vault.put_entity(
        &late,
        ENTITY_TYPE_TURN,
        at(2),
        20,
        &body(&serde_json::json!({ "txt": "regenerated from the second page" })),
    )?;
    change_docs_source(&vault, &source, "third page")?;
    assert_eq!(vault.pending_dependent_walks()?.len(), 1);
    assert!(
        !complete(&vault, &late, 20, &[span_of(&vault, &source)?])?,
        "the body predates the third page"
    );
    assert!(withdrawn(&vault, &late)?);
    vault.finish_dependent_walks()?;
    assert!(withdrawn(&vault, &late)?, "the walk withdrew it");
    Ok(())
}

/// An epoch summary withdrawn only through a dependent the walk has not
/// reached, regenerated from a live source and put twice: its completion
/// holds (Sol R2 on #1471).
#[test]
fn an_epoch_summary_put_twice_mid_walk_completes() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::SoftErase, &source)?;
    let dependents = derive_five(&vault, &source)?;
    let (summary, live) = (entity(0xEE), entity(0x6B));
    vault
        .batch()
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            at(4),
            5,
            &epoch_body(2, "steps 6-8")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &dependents[4], 1.0)
        .put(
            &live,
            ENTITY_TYPE_TURN,
            at(3),
            3,
            &body(&serde_json::json!({ "txt": "a live source" })),
        )
        .commit()?;
    vault.store.test_hooks.stop_dependent_walks_after(0);
    assert!(vault.delete_entity(&source)?);
    assert!(withdrawn(&vault, &summary)?, "pending through its source");

    vault
        .batch()
        .delete_edge(&summary, EdgeKind::DerivedFrom, &dependents[4])
        .edge(&summary, EdgeKind::DerivedFrom, &live, 1.0)
        .commit()?;
    for _ in 0..2 {
        vault.put_entity(
            &summary,
            ENTITY_TYPE_SUMMARY,
            at(4),
            20,
            &epoch_body(2, "steps 6-8, regenerated")?,
        )?;
    }
    assert!(
        complete(&vault, &summary, 20, &[span_of(&vault, &live)?])?,
        "the regeneration completes"
    );
    assert!(!withdrawn(&vault, &summary)?);
    vault
        .store
        .test_hooks
        .stop_dependent_walks_after(usize::MAX);
    vault.finish_dependent_walks()?;
    assert!(!withdrawn(&vault, &summary)?, "the walk leaves it live");
    Ok(())
}

/// A claim the walk has not reached keeps no lexical query hint in the
/// ranking: search mid-walk fills its limit with live records (Sol and
/// Astra R2 on #1471).
#[test]
fn a_hinted_claim_mid_walk_leaves_the_limit_to_live_records() -> Result<()> {
    let (_tmp, vault) = open_with(crate::test_util::embedding_test_config());
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::SoftErase, &source)?;
    derive_five(&vault, &source)?;
    let claim = derive_claim(&vault, &source, "matcha order history")?;
    let live = entity(0x6A);
    let words = "matcha order and a good many other words that dilute it";
    vault
        .batch()
        .put(
            &live,
            ENTITY_TYPE_TURN,
            at(2),
            2,
            &body(&serde_json::json!({ "txt": words })),
        )
        .text(&live, &[("body", words)])
        .commit()?;
    let first = |vault: &Vault| -> Result<Vec<EntityId>> {
        Ok(vault
            .search_text("matcha order", 1)?
            .into_iter()
            .map(|hit| hit.id)
            .collect())
    };
    assert_eq!(first(&vault)?, vec![claim], "its hint ranks it first");

    vault.store.test_hooks.stop_dependent_walks_after(0);
    assert!(vault.delete_entity(&source)?);
    assert!(withdrawn(&vault, &claim)?);
    assert_eq!(first(&vault)?, vec![live]);
    Ok(())
}

/// A leased fill for a claim the walk has not reached, after a put of the
/// same body marked it again with the same token, writes no vector (Astra R2
/// on #1471).
#[test]
fn a_fill_leased_before_a_same_body_put_mid_walk_writes_nothing() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    let (_tmp, vault) = open_with(crate::test_util::embedding_test_config());
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::SoftErase, &source)?;
    derive_five(&vault, &source)?;
    let claim = entity(0x75);
    let claim_body = crate::claim::encode_claim_body(&ClaimBody::new(
        "test.walk_fill",
        ClaimSubject::Entity(entity(0x74)),
        rmpv::Value::from("filled mid-walk"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?)?;
    let claim_row = (crate::registry::ENTITY_TYPE_CLAIM, at(10), 11);
    vault
        .batch()
        .put(&claim, claim_row.0, claim_row.1, claim_row.2, &claim_body)
        .edge(&claim, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    let token = {
        let txn = vault.store.env.read_txn()?;
        vault.store.pending_embedding_token(&txn, &claim)?
    }
    .expect("a claim is marked for embedding");

    vault.store.test_hooks.stop_dependent_walks_after(0);
    assert!(vault.delete_entity(&source)?);
    assert!(withdrawn(&vault, &claim)?);
    vault
        .batch()
        .put(&claim, claim_row.0, claim_row.1, claim_row.2, &claim_body)
        .commit()?;
    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    assert_eq!(
        vault.get_vector(&claim)?,
        None,
        "a withdrawn claim takes no fill"
    );
    Ok(())
}

/// A second change of the source while its walk is pending covers what the
/// first walk passed by: a derivation of the first change's text goes too.
#[test]
fn a_second_change_mid_walk_withdraws_what_the_first_passed_by() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    derive_five(&vault, &source)?;
    change_docs_source(&vault, &source, "second page")?;
    // Inside the rows the first walk still covers: it settles there.
    let mut bytes = [0; 16];
    bytes[0] = 0x63;
    bytes[15] = 2;
    let fresh = EntityId::from_bytes(bytes)?;
    vault
        .batch()
        .put(
            &fresh,
            ENTITY_TYPE_TURN,
            at(4),
            4,
            &body(&serde_json::json!({ "txt": "from the second page" })),
        )
        .edge(&fresh, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    assert!(!withdrawn(&vault, &fresh)?);
    change_docs_source(&vault, &source, "third page")?;
    assert!(withdrawn(&vault, &fresh)?, "the second mark covers it");
    vault.finish_dependent_walks()?;
    assert!(withdrawn(&vault, &fresh)?);
    assert!(vault.pending_dependent_walks()?.is_empty());
    Ok(())
}

/// A source erased, recreated in no world, and erased again while its first
/// walk is pending: what only the second mark covers is withdrawn for the
/// worlds that mark read, none of the first's (Astra R3 on #1471).
#[test]
fn a_second_mark_lends_its_rows_none_of_the_first_marks_worlds() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    let claim_in = |world: Option<EntityId>| -> Result<Vec<u8>> {
        let mut claim = ClaimBody::new(
            "test.walk_world",
            ClaimSubject::Entity(entity(0x74)),
            rmpv::Value::from("worded"),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        claim.world = world;
        crate::claim::encode_claim_body(&claim)
    };
    let (_tmp, vault) = open();
    let (source, world) = (entity(0x5B), entity(0x5E));
    let claim_type = crate::registry::ENTITY_TYPE_CLAIM;
    vault.put_entity(
        &world,
        crate::registry::ENTITY_TYPE_WORLD,
        at(1),
        1,
        b"world",
    )?;
    vault.put_entity(&source, claim_type, at(1), 1, &claim_in(Some(world))?)?;
    derive_five(&vault, &source)?;
    vault.store.test_hooks.stop_dependent_walks_after(0);
    assert!(vault.delete_entity(&source)?);

    vault.put_entity(&source, claim_type, at(1), 10, &claim_in(None)?)?;
    let summary = entity(0xEE);
    vault
        .batch()
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            at(11),
            11,
            &epoch_body(2, "steps 6-8")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    assert!(vault.delete_entity(&source)?);
    assert!(withdrawn(&vault, &summary)?);
    assert_eq!(withdrawn_worlds(&vault, &summary)?, None, "mid-walk");
    vault
        .store
        .test_hooks
        .stop_dependent_walks_after(usize::MAX);
    vault.finish_dependent_walks()?;
    assert!(withdrawn(&vault, &summary)?);
    assert_eq!(withdrawn_worlds(&vault, &summary)?, None, "after the walk");
    Ok(())
}

/// A source changed again and again before its walk finishes keeps a walk
/// row of bounded size: a later mark that answers for an earlier one takes
/// its place (Astra R4 on #1471).
#[test]
fn a_source_changed_again_and_again_mid_walk_keeps_a_bounded_walk() -> Result<()> {
    let (_tmp, vault) = open();
    let source = entity(0x5B);
    put_source(&vault, DependentWalkDoor::ChangedDocsSource, &source)?;
    let dependents = derive_five(&vault, &source)?;
    for page in 0..40 {
        change_docs_source(&vault, &source, &format!("page {page}"))?;
    }
    let walk = {
        let txn = vault.store.env.read_txn()?;
        super::WALK.get(&vault.store, &txn, &source)?
    }
    .expect("the walk is pending");
    assert!(
        walk.earlier.is_empty(),
        "the latest mark answers for every earlier one"
    );
    vault.finish_dependent_walks()?;
    for dependent in &dependents {
        assert!(withdrawn(&vault, dependent)?);
    }
    Ok(())
}
